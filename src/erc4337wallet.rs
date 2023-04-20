use crate::create_sender_util::{create2addr, create_init_code};
use crate::erc4337_common::GasQueryResult;
use crate::user_opertaion::UserOperation;
use ethers::abi::AbiEncode;
use ethers::prelude::{Address, Bytes, Provider, U256};
use ethers::utils::{__serde_json::json, hex};
use futures::executor::block_on;
use rand::random;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
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

    //send_tx without paymaster
    pub async fn send_tx(&self, account: &SimpleAccount, to: Address, amount: U256) {
        //todo: need to be able to query nonce on-chain
        let nonce = 0;
        let mut userOp = UserOperation::new();
        //only include initcode if not deployed yet
        userOp = if !account.deployed {
            let initcode = create_init_code(account.owner, account.salt);
            userOp.init_code(initcode)
        } else {
            userOp
        };
        userOp = userOp.sender(account.address);
        userOp = userOp.nonce(nonce);

        //create calldata
        let mut signature = Bytes::from_str(EXECUTE_SIGNATURE).unwrap().to_vec();
        let mut param = AbiEncode::encode((to, amount, Bytes::default()));
        let call_data = [signature, param].concat();
        userOp = userOp.call_data(call_data);
        userOp = userOp.verification_gas_limit(0xffffff);
        userOp = userOp.pre_verification_gas(0xffffff);
        userOp = userOp.signature(Bytes::from_str("0x43b8da28f2e270442c1618c6594a8b9c3cc44fd321d6135339be632af153e1fa5a00d1b1336d40091ae887b0b8d2a8a6f20b8d9818435196082f38cc46e0bad11b").unwrap());
        let gas_info = self.query_gas_info_test(account, &userOp).await;
        userOp = userOp
            .call_gas_imit(gas_info.verificationGas)
            .verification_gas_limit(gas_info.verificationGas)
            .pre_verification_gas(gas_info.preVerificationGas);

        println!("{userOp:?}")
    }

    pub async fn query_gas_info_test(
        &self,
        account: &SimpleAccount,
        userOp: &UserOperation,
    ) -> GasQueryResult {
        //test only, should query through meson
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

    //shoud use send_tx to directly deploy account normally
    pub fn deploy_account(&self, account: SimpleAccount) {}
}

#[cfg(test)]
mod tests {
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
        let owner = Address::from_str("5B38Da6a701c568545dCfcB03FcB875f56beddC4").unwrap();
        wallet.create_account(owner, Option::None);
    }

    abigen!(
        IUniswapV2Pair,
        r#"[function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)]"#
    );

    #[tokio::test]
    pub async fn test_rpc() {
        //let rpc_url = "https://eth.llamarpc.com";
        //let rpc_url = "https://node.stackup.sh/v1/rpc/9c21ff1cba3a5407d43324bfc6718044de9203b2b6fb09aac8b52a7d7496bdf5";
        let rpc_url = "http://localhost:4337";
        let provider = Provider::try_from(rpc_url).unwrap();
        let op = UserOperation::new();
        let block_number: U64 = provider
            .request(
                "eth_estimateUserOperationGas",
                json!([{"callData":"0xb61d27f60000000000000000000000007a531c4f680ff73ca991557f5ee274744a696517000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000",
                "callGasLimit":"0x0",
                "initCode":"0x3b65465fa21686034605f7cf4c9edc6c4ca133725fbfb9cf0000000000000000000000001f0bdb0533b9ab79c891e65ac3ad3df4cd164b50000000000000000000000000000000003932ea3bfa1f9fb389748e004491266c",
                "maxFeePerGas":"0x0",
                "maxPriorityFeePerGas":"0x0",
                "nonce":"0x0","paymasterAndData":"0x",
                "preVerificationGas": 44980,
                "sender":"0x1795a0cd3df0fca0b3b0a3c4f7f8721839f2e2de",
                "signature":"0x43b8da28f2e270442c1618c6594a8b9c3cc44fd321d6135339be632af153e1fa5a00d1b1336d40091ae887b0b8d2a8a6f20b8d9818435196082f38cc46e0bad11b",
                "verificationGasLimit":"0xffffff"},
                "0x8944bd0fed9732f99c5a5a4b5d730a1b7f45783c"]),
            )
            .await
            .unwrap();
        //let a = json!([op, "0x0576a174D229E3cFA37253523E645A78A0C91B57"]);

        println!("{}", block_number);
        //let provider = Arc::new(Provider::try_from(rpc_url).unwrap());
        // let pair_address: Address = "0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11"
        //     .parse()
        //     .unwrap();
        // let uniswap = IUniswapV2Pair::new(pair_address, provider);

        // let (reserve_0, reserve_1, blocktimestamp) = uniswap.get_reserves().call().await.unwrap();
        // println!("{},{},{}", reserve_0, reserve_1, blocktimestamp);
        // .request(
        //     "eth_sendUserOperation",
        //     json!([{"callData":"0xb61d27f60000000000000000000000007a531c4f680ff73ca991557f5ee274744a696517000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000",
        //     "callGasLimit":"0x9960199",
        //     "initCode":"0xd25e3ec8f95ccc0428484493468715bcd7244eaa5fbfb9cf0000000000000000000000007a531c4f680ff73ca991557f5ee274744a69651700000000000000000000000000000000d2bc493ccba2b50e2f174221b608be81",
        //     "maxFeePerGas":"0x97b9262d649",
        //     "maxPriorityFeePerGas":"0x99682f009",
        //     "nonce":"0x0","paymasterAndData":"0x",
        //     "preVerificationGas":"0x99682f09",
        //     "sender":"0x7c236bcc65196c8eef8144eb0b53919513106547",
        //     "signature":"0x",
        //     "verificationGasLimit":"1500000"},
        //     "0x0576a174d229e3cfa37253523e645a78a0c91b57"]),
        // )
    }

    #[tokio::test]
    pub async fn test_query_gas() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path);
        let owner = Address::from_str("1F0BDb0533b9aB79c891E65aC3ad3df4cd164B50").unwrap();
        let account = wallet.create_account(
            owner,
            Option::Some(
                "0x8944bd0FeD9732f99c5a5A4B5d730a1B7f45783c"
                    .parse()
                    .unwrap(),
            ),
        );
        wallet
            .send_tx(
                &account,
                "7A531C4F680fF73Ca991557F5Ee274744A696517".parse().unwrap(),
                U256::from_dec_str("10").unwrap(),
            )
            .await;
    }
}
