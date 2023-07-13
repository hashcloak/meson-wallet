#![allow(non_snake_case)]
use crate::cli;
use crate::create_sender_util::{create2addr, create_init_code};
use crate::erc4337_common::{ERC4337Error, GasQueryResult};
use crate::tornado_util::Deposit;
use crate::user_opertaion::UserOperation;
use ethers::abi::AbiEncode;
use ethers::prelude::k256::ecdsa::SigningKey;
use ethers::prelude::{Address, Bytes, Provider, Signature, Wallet, U256};
use ethers::signers::Signer;
use ethers::utils::keccak256;
use ethers::utils::{__serde_json::json, hex};
use futures::executor::block_on;
use rand::random;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::ops::Add;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Deserialize)]
pub struct Erc4337Wallet {
    key_store_path: PathBuf,
    meson_setting_path: PathBuf,
    Chain: HashMap<String, ChainInfo>,
}

#[derive(Deserialize)]
struct ChainInfo {
    Ticker: String,
    Endpoint: String,
}
#[derive(Deserialize, Serialize)]
pub struct SimpleAccount {
    address: Address,
    owner: Address,
    entry_point: Address,
    salt: U256,
    deployed: bool,
}

const EXECUTE_SIGNATURE: &str = "b61d27f6";

impl Erc4337Wallet {
    pub fn new<P: AsRef<Path>>(wallet_config_path: P) -> Self {
        let toml_str = fs::read_to_string(wallet_config_path).unwrap();
        let smart_wallet: Erc4337Wallet = toml::from_str(&toml_str).unwrap();

        smart_wallet
    }

    pub fn create_account(&self, owner: Address, entry_point: Option<Address>) -> SimpleAccount {
        let salt: u128 = random();
        let salt = U256::from(salt);
        let address: Address = create2addr(owner, salt);
        let entry_point = match entry_point {
            Some(addr) => addr,
            None => Address::from_str("0x0576a174D229E3cFA37253523E645A78A0C91B57").unwrap(),
        };
        let account = SimpleAccount {
            address,
            owner,
            entry_point,
            salt,
            deployed: false,
        };
        let dir = self.key_store_path.join("smart_accounts");
        fs::create_dir_all(&dir).unwrap();
        let addr_str = "0x".to_owned() + &hex::encode(account.address);
        let mut file = fs::File::create(&dir.join(&addr_str)).unwrap();
        let contents = serde_json::to_string(&account).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        account
    }

    //test only, should sendthrough meson
    //send_tx without paymaster
    pub async fn fill_user_op(
        &self,
        account: &SimpleAccount,
        to: Address,
        amount: U256,
        chain_id: U256,
        data: Option<Vec<u8>>,
    ) -> (UserOperation, String) {
        let mut userOp = UserOperation::new();
        //only include initcode if not deployed yet
        userOp = if !account.deployed {
            let initcode = create_init_code(account.owner, account.salt);
            userOp.init_code(initcode)
        } else {
            userOp
        };
        userOp = userOp.sender(account.address);

        //query nonce only if deployed
        userOp = userOp.nonce(0);
        if account.deployed {
            let addr_str = "0x".to_owned() + &hex::encode(account.address);
            let nonce = self.query_nonce(addr_str).await;
            userOp = userOp.nonce(nonce);
        }

        //create calldata
        let mut func_signature = Bytes::from_str(EXECUTE_SIGNATURE).unwrap().to_vec();
        let mut param;
        match data {
            Some(n) => param = AbiEncode::encode((to, amount, Bytes::from(n))),
            None => param = AbiEncode::encode((to, amount, Bytes::default())),
        }
        let call_data = [func_signature, param].concat();
        userOp = userOp.call_data(call_data);
        userOp = userOp.verification_gas_limit(0xffffff);
        userOp = userOp.pre_verification_gas(0xffffff);
        userOp = userOp.max_fee_per_gas(0xffffff);

        //set signature to random data for querying gas
        userOp = userOp.signature(Bytes::from_str("0x43b8da28f2e270442c1618c6594a8b9c3cc44fd321d6135339be632af153e1fa5a00d1b1336d40091ae887b0b8d2a8a6f20b8d9818435196082f38cc46e0bad11b").unwrap());
        //let gas_info = self.query_gas_info(account, &userOp).await;
        //println!("{gas_info:?}");

        //shoud set the gas price from gas_info (current stackup version doesn't work)
        userOp = userOp
            .call_gas_imit(100000000)
            .verification_gas_limit(500000)
            .pre_verification_gas(1000000)
            .max_fee_per_gas(7000000000u64)
            .max_priority_fee_per_gas(600000000);

        //set signature to empty bytes for signing
        userOp = userOp.signature(Bytes::default());
        let op_clone = userOp.clone();

        let owner_addr_str = "0x".to_owned() + &hex::encode(account.owner);
        let mut keypath = self
            .key_store_path
            .join("keystore")
            .join(owner_addr_str.clone());
        if !keypath.exists() {
            keypath = self
                .key_store_path
                .join("imported_keystore")
                .join(owner_addr_str);
        }
        let password = cli::prompt_password_confirm().unwrap();

        let owner_wallet = Wallet::decrypt_keystore(keypath, password).unwrap();
        // let owner_wallet: Wallet<SigningKey> =
        //     "d5d81bccdb261aa45fc232b15689d29b60dca53c5329d52081a911731fb5112b"
        //         .parse()
        //         .unwrap();
        let (signature, op_hash) = self.light_sign(op_clone, owner_wallet, account, chain_id);
        userOp = userOp.signature(signature.to_vec());
        let hash_str = hex::encode(op_hash);
        println!("{userOp:?}");
        (userOp, hash_str)
    }

    pub async fn fill_tornado_deposit_user_op(
        &self,
        eth_amount: &str,
        net_id: u64,
        account: &SimpleAccount,
        tornado_addr: Address,
    ) -> (UserOperation, String) {
        let tor_deposit = Deposit::new();
        let tx = tor_deposit.gen_deposit_tx(None, eth_amount, net_id);
        let (user_op, hash_str) = self
            .fill_user_op(
                account,
                tornado_addr,
                ethers::utils::parse_ether(eth_amount).unwrap(),
                net_id.into(),
                Some(tx),
            )
            .await;

        (user_op, hash_str)
    }

    pub async fn fill_tornado_withdraw_user_op(
        &self,
        tor_note: &str,
        recipient: Address,
        net_id: u64,
        account: &SimpleAccount,
        tornado_addr: Address,
    ) -> (UserOperation, String) {
        let tx = Deposit::parse_and_withdraw(tor_note, recipient, None, None, None).await;
        let (user_op, hash_str) = self
            .fill_user_op(account, tornado_addr, 0.into(), net_id.into(), Some(tx))
            .await;

        (user_op, hash_str)
    }

    pub fn light_sign(
        &self,
        userOp: UserOperation,
        owner_wallet: Wallet<SigningKey>,
        account: &SimpleAccount,
        chain_id: U256,
    ) -> (Signature, [u8; 32]) {
        let op_hash = keccak256(AbiEncode::encode((
            userOp.hash(),
            account.entry_point,
            chain_id,
        )));
        let signature: Signature = block_on(owner_wallet.sign_message(op_hash)).unwrap();
        (signature, op_hash)
    }

    //test only, should query through meson
    pub async fn query_gas_info(
        &self,
        account: &SimpleAccount,
        userOp: &UserOperation,
    ) -> GasQueryResult {
        let rpc_url = "http://localhost:4337";
        //let rpc_url = "https://node.stackup.sh/v1/rpc/9c21ff1cba3a5407d43324bfc6718044de9203b2b6fb09aac8b52a7d7496bdf5";
        let provider = Provider::try_from(rpc_url).unwrap();
        let testjson = json!([userOp, account.entry_point]);
        let query_result: GasQueryResult = provider
            .request(
                "eth_estimateUserOperationGas",
                json!([userOp, account.entry_point]),
            )
            .await
            .unwrap();
        query_result
    }

    //test only, should query through meson
    pub async fn query_nonce(&self, smart_account_addr: String) -> U256 {
        let rpc_url = "http://localhost:8545";
        let provider = Provider::try_from(rpc_url).unwrap();
        let nonce: U256 = provider
            .request(
                "eth_call",
                json!([{
                    "to": smart_account_addr,
                    "data": "0xd087d288",
                },"latest"]),
            )
            .await
            .unwrap();

        nonce
    }

    pub async fn send_op(&self, userOp: UserOperation, account: &mut SimpleAccount) -> String {
        let rpc_url = "http://localhost:4337";
        let provider = Provider::try_from(rpc_url).unwrap();
        let result: String = provider
            .request(
                "eth_sendUserOperation",
                json!([userOp, account.entry_point]),
            )
            .await
            .unwrap();

        if !account.deployed {
            account.deployed = true;
            let dir = self.key_store_path.join("smart_accounts");
            let addr_str = "0x".to_owned() + &hex::encode(account.address);
            let mut file = fs::File::create(&dir.join(&addr_str)).unwrap();
            let contents = serde_json::to_string(&account).unwrap();
            file.write_all(contents.as_bytes()).unwrap();
        }
        result
    }

    pub fn load_account(&self, smart_account_addr: String) -> SimpleAccount {
        let dir = self
            .key_store_path
            .join("smart_accounts")
            .join(smart_account_addr);
        let toml_str = fs::read_to_string(dir).unwrap();
        let account: SimpleAccount = serde_json::from_str(&toml_str).unwrap();
        account
    }
}

#[cfg(test)]
mod tests {
    use crate::tornado_util;

    use super::*;
    use ethers::prelude::*;
    use ethers::utils::__serde_json::json;
    use futures::executor::block_on;
    use futures::FutureExt;
    use std::sync::Arc;
    const RPC_URL: &str = "https://eth.llamarpc.com";
    #[test]
    pub fn test_create_account() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path);
        let owner = Address::from_str("1f0bdb0533b9ab79c891e65ac3ad3df4cd164b50").unwrap();
        wallet.create_account(
            owner,
            Some(
                "0x3cD5A8Ddd0EFb5804978a4Da74D3Fb6d074829F3"
                    .parse()
                    .unwrap(),
            ),
        );
    }

    #[tokio::test]
    pub async fn test_rpc() {
        //let rpc_url = "https://eth.llamarpc.com";
        //let rpc_url = "https://node.stackup.sh/v1/rpc/9c21ff1cba3a5407d43324bfc6718044de9203b2b6fb09aac8b52a7d7496bdf5";
        let rpc_url = "http://localhost:4337";
        let provider = Provider::try_from(rpc_url).unwrap();
        let op = UserOperation::new();
        let block_number: Result<GasQueryResult, ProviderError> = provider
            .request(
                "eth_sendUserOperation",
                json!([{"callData":"0xb61d27f60000000000000000000000007a531c4f680ff73ca991557f5ee274744a696517000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000",
                "callGasLimit":44980,
                "initCode":"0x3b65465fa21686034605f7cf4c9edc6c4ca133725fbfb9cf0000000000000000000000001f0bdb0533b9ab79c891e65ac3ad3df4cd164b50000000000000000000000000000000003932ea3bfa1f9fb389748e004491266c",
                "maxFeePerGas":44980,
                "maxPriorityFeePerGas":44980,
                "nonce":"0x0","paymasterAndData":"0x",
                "preVerificationGas": 45028,
                "sender":"0x1795a0cd3df0fca0b3b0a3c4f7f8721839f2e2de",
                "signature":"0x43b8da28f2e270442c1618c6594a8b9c3cc44fd321d6135339be632af153e1fa5a00d1b1336d40091ae887b0b8d2a8a6f20b8d9818435196082f38cc46e0bad11b",
                "verificationGasLimit":1500000},
                "0x8944bd0fed9732f99c5a5a4b5d730a1b7f45783c"]),
            )
            .await;

        let r: GasQueryResult;

        match block_number {
            Ok(gas_result) => println!("{:?}", gas_result),
            Err(E) => match E {
                ProviderError::JsonRpcClientError(mes) => {
                    let res: String = mes.to_string();
                    println!("{:?}", res);
                }
                _ => panic!("{}", E),
            },
        };
    }

    #[tokio::test]
    pub async fn test_query_gas() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path);
        let owner = Address::from_str("1F0BDb0533b9aB79c891E65aC3ad3df4cd164B50").unwrap();
        let account = wallet.create_account(
            owner,
            Option::Some(
                "0xe78A0F7E598Cc8b0Bb87894B0F60dD2a88d6a8Ab"
                    .parse()
                    .unwrap(),
            ),
        );
        wallet
            .fill_user_op(
                &account,
                "0x0000000000000000000000000000000000000001"
                    .parse()
                    .unwrap(),
                U256::from_dec_str("10").unwrap(),
                5777.into(),
                None,
            )
            .await;
    }

    #[tokio::test]
    pub async fn test_send() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path);
        let mut account = wallet.load_account("0x0009b114f7f9b054b30f1cdc18080e115e14fd51".into());
        let (userOp, ophash) = wallet
            .fill_user_op(
                &account,
                "0x0000000000000000000000000000000000000010"
                    .parse()
                    .unwrap(),
                U256::from_dec_str("10").unwrap(),
                12345.into(),
                None,
            )
            .await;

        let result = wallet.send_op(userOp, &mut account).await;
        println!("{}", result);
        println!("{}", ophash);
    }

    #[tokio::test]

    pub async fn test_tornado_deposit() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path);
        let mut account = wallet.load_account("0xca45fe0684c78401e48c853fc911a93ef77a1b31".into());
        let (user_op, op_hash) = wallet
            .fill_tornado_deposit_user_op(
                "0.1",
                12345,
                &account,
                tornado_util::TORNADO_ADDRESS.parse().unwrap(),
            )
            .await;
        let result = wallet.send_op(user_op, &mut account).await;
        println!("{}", result);
    }

    #[tokio::test]
    pub async fn test_tornado_withdraw() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path);
        let mut account = wallet.load_account("0xca45fe0684c78401e48c853fc911a93ef77a1b31".into());
        let (user_op, op_hash) = wallet
        .fill_tornado_withdraw_user_op(
            "tornado-eth-0.1-12345-0x10fe361cf9e3c8fc040dee1dfb71c41fb06a500e5a8fc2f1dc5b140607c9b656069573d13ab0d66ca39a003e5901aa63efbdf5939d242a01b60534ef89b8",
             "0x0000000000000000000000000000000000000007".parse().unwrap(),
              12345,
               &account,
                tornado_util::TORNADO_ADDRESS.parse().unwrap(),
            )
            .await;
        let result = wallet.send_op(user_op, &mut account).await;
        println!("{}", result);
    }

    #[tokio::test]
    pub async fn test_nonce() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path);
        let nonce = wallet
            .query_nonce("0xca45fe0684c78401e48c853fc911a93ef77a1b31".into())
            .await;
        println!("{}", nonce);
    }
}
