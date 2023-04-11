use crate::create_sender_util::{create2addr, create_init_code};
use crate::user_opertaion::UserOperation;
use ethers::abi::AbiEncode;
use ethers::prelude::{Address, Bytes, U256};
use ethers::utils::hex;
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
    salt: U256,
    deployed: bool,
}

const EXECUTE_SIGNATURE: &str = "b61d27f6";

impl Erc4337Wallet {
    pub fn new<P: AsRef<Path>>(wallet_config_path: P) -> Self {
        let toml_str = fs::read_to_string(wallet_config_path).unwrap();
        let samet_wallet: Erc4337Wallet = toml::from_str(&toml_str).unwrap();

        samet_wallet
    }

    pub fn create_account(&self, owner: Address) {
        let salt: u128 = random();
        let salt = U256::from(salt);
        let address: Address = create2addr(owner, salt);
        let account = SimpleAccount {
            address,
            owner,
            salt,
            deployed: false,
        };
        let dir = self.key_store_path.join("smart_accounts");
        fs::create_dir_all(&dir).unwrap();
        let addr_str = "0x".to_owned() + &hex::encode(account.address);
        let mut file = fs::File::create(&dir.join(&addr_str)).unwrap();
        let contents = serde_json::to_string(&account).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
    }

    //send_tx without paymaster
    pub fn send_tx(&self, account: SimpleAccount, to: Address, amount: U256) {
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
    }

    //shoud use send_tx to directly deploy account normally
    pub fn deploy_account(&self, account: SimpleAccount) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::prelude::*;
    use futures::executor::block_on;
    use futures::FutureExt;
    const RPC_URL: &str = "https://eth.llamarpc.com";
    #[test]
    pub fn test_create_account() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path);
        let owner = Address::from_str("5B38Da6a701c568545dCfcB03FcB875f56beddC4").unwrap();
        wallet.create_account(owner);
    }
}
