use crate::user_opertaion::UserOperation;
use ethers::prelude::{Address, U256};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

// currently unused, can be used with DirectPost
// #[derive(Serialize)]
// pub struct UserOperationRequest {
//     pub jsonrpc: i8,
//     pub id: i8,
//     pub command: String,
//     pub params: (user_opertaion::UserOperation, Address),
// }

// impl UserOperationRequest {
//     pub fn to_json(&self) -> Vec<u8> {
//         let json_vec = serde_json::to_vec(self).expect("eth json error");
//         json_vec
//     }
// }

// gas query result return from Meson
#[derive(Debug, Serialize, Deserialize)]
pub struct GasQueryResult {
    pub pre_verification_gas: u128,
    pub verification_gas: u128,
    pub call_gas_limit: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ERC4337Error {
    pub code: i64,
    pub message: String,
    pub data: String,
}

impl std::error::Error for ERC4337Error {}
impl fmt::Display for ERC4337Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "code: {}, message: {}", self.code, self.message)
    }
}

// struct to store private key
#[derive(Debug, Serialize, Deserialize)]
pub struct SkCipher {
    pub cipher: String,
    pub mac: String,
    pub salt: String,
    pub iv: String,
}

// trait for an erc4337 account, used by erc4337 wallet
pub trait Account {
    // create the init code for first time deployment
    fn create_init_code<P: AsRef<Path>>(&self, supported_accounts_path: P) -> Vec<u8>;

    // sign a given user_op
    fn sign<P: AsRef<Path>>(
        &self,
        user_op: &UserOperation,
        password: &str,
        key_store_path: P,
    ) -> Vec<u8>;

    // return the address of the smart contract account
    fn address(&self) -> Address;

    // return the entry point used by the smart contract account
    fn entry_point(&self) -> Address;

    // return chain id
    fn chain_id(&self) -> U256; //todo: does account need to hold chain_id?

    // return the salt used in Create2 to deploy the account
    fn salt(&self) -> U256;

    // return wether the account has deployed
    fn deployed(&self) -> bool; //todo: does account need to hold deployment status? (Consider checking deployment status every time)

    // set the deployment status
    fn set_deployed<P: AsRef<Path>>(&mut self, status: bool, key_store_path: P); //update and save deployed status
}
