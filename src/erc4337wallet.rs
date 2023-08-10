use crate::cli;
use crate::create_sender_util::{bls_create2addr, create2addr, create_init_code};
use crate::erc4337_common::{Account, ERC4337Error, GasQueryResult, SkCipher};
use crate::tornado_util::Deposit;
use crate::user_opertaion::UserOperation;
use aes::cipher::{KeyIvInit, StreamCipher};
use base64ct::{Base64, Encoding};
use ethers::abi::AbiEncode;
use ethers::prelude::k256::ecdsa::SigningKey;
use ethers::prelude::{Address, Bytes, Provider, Signature, Wallet, U256};
use ethers::signers::Signer;
use ethers::utils::keccak256;
use ethers::utils::{__serde_json::json, hex};
use futures::executor::block_on;
use rand::random;
use rand::{CryptoRng, Rng};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const DEFAULT_KEY_SIZE: usize = 32usize;
const DEFAULT_IV_SIZE: usize = 16usize;
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 13u8;
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

//Different from crate::bls::PublicKey to derive serde
//todo: condider using compressed g2 form
type BLSPublicKey = [U256; 4];

type Aes128Ctr = ctr::Ctr64LE<aes::Aes128>;

#[derive(Deserialize)]
pub struct Erc4337Wallet {
    pub key_store_path: PathBuf,
    pub meson_setting_path: PathBuf,
    pub Chain: HashMap<String, ChainInfo>,
}

#[derive(Deserialize)]
pub struct ChainInfo {
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
const NODE_RPC_URL: &str = "http://localhost:8545"; //test only, should handle by meson
const BUNDLER_RPC_URL: &str = "http://localhost:4337"; //test only, should handle by meson

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
        //todo: move entry point to wallet setting
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
        let mut user_op = UserOperation::new();
        //only include initcode if not deployed yet
        user_op = if !account.deployed {
            let initcode = create_init_code(account.owner, account.salt);
            user_op.init_code(initcode)
        } else {
            user_op
        };
        user_op = user_op.sender(account.address);

        //query nonce only if deployed
        user_op = user_op.nonce(0);
        if account.deployed {
            let addr_str = "0x".to_owned() + &hex::encode(account.address);
            let nonce = self.query_nonce(addr_str).await;
            user_op = user_op.nonce(nonce);
        }

        //create calldata
        let mut func_signature = Bytes::from_str(EXECUTE_SIGNATURE).unwrap().to_vec();
        let mut param;
        match data {
            Some(n) => param = AbiEncode::encode((to, amount, Bytes::from(n))),
            None => param = AbiEncode::encode((to, amount, Bytes::default())),
        }
        let call_data = [func_signature, param].concat();
        user_op = user_op.call_data(call_data);
        user_op = user_op.verification_gas_limit(0xffffff);
        user_op = user_op.pre_verification_gas(0xffffff);
        user_op = user_op.max_fee_per_gas(0xffffff);

        //set signature to random data for querying gas
        user_op = user_op.signature(Bytes::from_str("0x43b8da28f2e270442c1618c6594a8b9c3cc44fd321d6135339be632af153e1fa5a00d1b1336d40091ae887b0b8d2a8a6f20b8d9818435196082f38cc46e0bad11b").unwrap());
        let gas_info = self.query_gas_info(account, &user_op).await;
        println!("{gas_info:?}");

        //shoud set the gas price from gas_info (current stackup version doesn't work)
        user_op = user_op
            .call_gas_imit(gas_info.callGasLimit)
            .verification_gas_limit(500000)
            .pre_verification_gas(1000000)
            .max_fee_per_gas(7000000000u64)
            .max_priority_fee_per_gas(600000000);

        //set signature to empty bytes for signing
        user_op = user_op.signature(Bytes::default());
        let op_clone = user_op.clone();

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
        user_op = user_op.signature(signature.to_vec());
        let hash_str = hex::encode(op_hash);
        println!("{user_op:?}");
        (user_op, hash_str)
    }

    pub async fn g_fill_op<P: Account>(
        &self,
        account: &P,
        to: Address,
        amount: U256,
        password: &str,
        data: Option<Vec<u8>>,
    ) -> (UserOperation, String) {
        let mut user_op = UserOperation::new();
        //only include initcode if not yet deployed
        user_op = if !account.deployed() {
            let initcode = account.create_init_code();
            user_op.init_code(initcode)
        } else {
            user_op
        };
        user_op = user_op.sender(account.address());

        //query nonce only if deployed
        user_op = user_op.nonce(0);
        if account.deployed() {
            let addr_str = "0x".to_owned() + &hex::encode(account.address());
            let nonce = self.query_nonce(addr_str).await;
            user_op = user_op.nonce(nonce);
        }

        //create calldata
        let func_signature = Bytes::from_str(EXECUTE_SIGNATURE).unwrap().to_vec();
        let param;
        match data {
            Some(n) => param = AbiEncode::encode((to, amount, Bytes::from(n))),
            None => param = AbiEncode::encode((to, amount, Bytes::default())),
        }
        let call_data = [func_signature, param].concat();
        user_op = user_op.call_data(call_data);
        user_op = user_op.verification_gas_limit(0xffffff);
        user_op = user_op.pre_verification_gas(0xffffff);
        user_op = user_op.max_fee_per_gas(0xffffff);

        //set signature to random data for querying gas
        user_op = user_op.signature(Bytes::from_str("0x43b8da28f2e270442c1618c6594a8b9c3cc44fd321d6135339be632af153e1fa5a00d1b1336d40091ae887b0b8d2a8a6f20b8d9818435196082f38cc46e0bad11b").unwrap());
        let gas_info = self.g_query_gas_info(account, &user_op).await;
        println!("{gas_info:?}");

        //shoud set the gas price from gas_info (current stackup version doesn't work)
        user_op = user_op
            .call_gas_imit(gas_info.callGasLimit)
            .verification_gas_limit(500000)
            .pre_verification_gas(1000000)
            .max_fee_per_gas(7000000000u64)
            .max_priority_fee_per_gas(600000000);

        user_op = user_op
            .call_gas_imit(500000)
            .verification_gas_limit(500000)
            .pre_verification_gas(1000000)
            .max_fee_per_gas(7000000000u64)
            .max_priority_fee_per_gas(600000000);

        //set signature to empty bytes for signing
        user_op = user_op.signature(Bytes::default());
        //let op_clone = user_op.clone();

        let sig = account.sign(&user_op, password);
        let user_op = user_op.signature(sig);
        let user_op_hash = hex::encode(keccak256(AbiEncode::encode((
            user_op.hash(),
            account.entry_point(),
            account.chain_id(),
        ))));
        (user_op, user_op_hash)
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
        user_op: UserOperation,
        owner_wallet: Wallet<SigningKey>,
        account: &SimpleAccount,
        chain_id: U256,
    ) -> (Signature, [u8; 32]) {
        let op_hash = keccak256(AbiEncode::encode((
            user_op.hash(),
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
        user_op: &UserOperation,
    ) -> GasQueryResult {
        let rpc_url = "http://localhost:4337";
        //let rpc_url = "https://node.stackup.sh/v1/rpc/9c21ff1cba3a5407d43324bfc6718044de9203b2b6fb09aac8b52a7d7496bdf5";
        let provider = Provider::try_from(rpc_url).unwrap();
        let query_result: GasQueryResult = provider
            .request(
                "eth_estimateUserOperationGas",
                json!([user_op, account.entry_point]),
            )
            .await
            .unwrap();
        query_result
    }

    pub async fn g_query_gas_info<P: Account>(
        &self,
        account: &P,
        user_op: &UserOperation,
    ) -> GasQueryResult {
        let provider = Provider::try_from(BUNDLER_RPC_URL).unwrap();
        let query_result: GasQueryResult = provider
            .request(
                "eth_estimateUserOperationGas",
                json!([user_op, account.entry_point()]),
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

    pub async fn send_op(&self, user_op: UserOperation, account: &mut SimpleAccount) -> String {
        let rpc_url = "http://localhost:4337";
        let provider = Provider::try_from(rpc_url).unwrap();
        let result: String = provider
            .request(
                "eth_sendUserOperation",
                json!([user_op, account.entry_point]),
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

    // pub fn load_account_t(&self, )

    pub fn encrypt_key<P, R, S, T>(dir: P, rng: &mut R, mut sk: S, password: T) -> Result<(), ()>
    where
        P: AsRef<Path>,
        R: Rng + CryptoRng,
        S: AsMut<[u8]>,
        T: AsRef<[u8]>,
    {
        // Generate a random salt.
        let mut salt = vec![0u8; DEFAULT_KEY_SIZE];
        rng.fill_bytes(salt.as_mut_slice());

        // Key Derivation with scrypt.
        let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
        let scrypt_params = ScryptParams::new(
            DEFAULT_KDF_PARAMS_LOG_N,
            DEFAULT_KDF_PARAMS_R,
            DEFAULT_KDF_PARAMS_P,
        )
        .unwrap();
        scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice()).unwrap();

        // Encrypt the private key using AES-128-CTR.
        let mut iv = vec![0u8; DEFAULT_IV_SIZE];
        rng.fill_bytes(iv.as_mut_slice());
        let ciphertext: &mut [u8] = sk.as_mut();
        let mut encrypter = Aes128Ctr::new((&key[..16]).into(), (&iv[..16]).into());
        encrypter.apply_keystream(ciphertext);

        // Calculate the MAC.
        let mac = Keccak256::new()
            .chain_update(&key[16..32])
            .chain_update(&ciphertext)
            .finalize();
        let mac = Base64::encode_string(&mac);
        let salt = Base64::encode_string(&salt);
        let iv = Base64::encode_string(&iv);

        //store the encrypted mnemonic
        let enc_mac = SkCipher {
            cipher: Base64::encode_string(&ciphertext),
            mac: mac,
            salt: salt,
            iv: iv,
        };
        let str_json = serde_json::to_string(&enc_mac).unwrap();
        fs::write::<PathBuf, String>(dir.as_ref().to_path_buf(), str_json)
            .expect("Unable to write file");
        Ok(())
    }

    pub fn decrypt_key<P, S>(dir: P, password: S) -> Result<Vec<u8>, ()>
    where
        P: AsRef<Path>,
        S: AsRef<[u8]>,
    {
        let str_json = fs::read_to_string(dir.as_ref()).unwrap();
        let json_cipher: SkCipher = serde_json::from_str(&str_json).unwrap();
        let mut cipher = Base64::decode_vec(&json_cipher.cipher).unwrap();
        let mac_from_json = json_cipher.mac;
        let salt = Base64::decode_vec(&json_cipher.salt).unwrap();
        let iv = Base64::decode_vec(&json_cipher.iv).unwrap();

        //Derive the key
        let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
        let scrypt_params = ScryptParams::new(
            DEFAULT_KDF_PARAMS_LOG_N,
            DEFAULT_KDF_PARAMS_R,
            DEFAULT_KDF_PARAMS_P,
        )
        .unwrap();
        scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice()).unwrap();

        //Derive and compare the mac
        let mac = Keccak256::new()
            .chain_update(&key[16..32])
            .chain_update(&cipher)
            .finalize();
        let mac = Base64::encode_string(&mac);

        //Decrypt the mnemonic
        let mut decryptor = Aes128Ctr::new((&key[..16]).into(), (&iv[..16]).into());
        decryptor.apply_keystream(&mut cipher);
        // let sk = PrivateKey::from_bytes(&cipher);

        if mac != mac_from_json {
            return Err(());
        };
        Ok(cipher)
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

    //test create basic smart contract account
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

    //test sending user_op (needs to set bundler url in send_op())
    #[tokio::test]
    pub async fn test_send_userop() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path);
        let mut account = wallet.load_account("0x0009b114f7f9b054b30f1cdc18080e115e14fd51".into());
        let (user_op, ophash) = wallet
            .fill_user_op(
                &account,
                "0x0000000000000000000000000000000000000012"
                    .parse()
                    .unwrap(),
                U256::from_dec_str("10").unwrap(),
                12345.into(),
                None,
            )
            .await;

        let result = wallet.send_op(user_op, &mut account).await;
        println!("{}", result);
        println!("{}", ophash);
    }

    #[tokio::test]
    //test sending tornado cash deposit user_op
    //for some version of bundler, needs to disable gas query to endable tornado cash
    pub async fn test_tornado_deposit() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path);
        let mut account = wallet.load_account("0x0009b114f7f9b054b30f1cdc18080e115e14fd51".into());
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
    //test sending tornado cash withdraw user_op
    //for some version of bundler, needs to disable gas query to endable tornado cash
    pub async fn test_tornado_withdraw() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path);
        let mut account = wallet.load_account("0x0009b114f7f9b054b30f1cdc18080e115e14fd51".into());
        let (user_op, op_hash) = wallet
        .fill_tornado_withdraw_user_op(
            "tornado-eth-0.1-12345-0xb232192e07b6122f607f016871658e8fc602696738064ca18acc275968f6006d98a270ffbccba51af4c9d668eda576592eb7cfe42d47913b8175c6f27b39",
             "0x0000000000000000000000000000000000000087".parse().unwrap(),
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
