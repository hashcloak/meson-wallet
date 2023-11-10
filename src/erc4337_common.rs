use crate::error::MesonWalletError;
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
    #[serde(rename = "preVerificationGas")]
    pub pre_verification_gas: u128,
    #[serde(rename = "verificationGas")]
    pub verification_gas: u128,
    #[serde(rename = "callGasLimit")]
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
    fn create_init_code<P: AsRef<Path>>(
        &self,
        supported_accounts_path: P,
        chain_id: U256,
    ) -> Result<Vec<u8>, MesonWalletError>;

    // sign a given user_op
    fn sign<P: AsRef<Path>>(
        &self,
        user_op: &UserOperation,
        chain_id: U256,
        password: &str,
        key_store_path: P,
    ) -> Result<Vec<u8>, MesonWalletError>;

    // return the address of the smart contract account
    fn address(&self) -> Address;

    // return the entry point used by the smart contract account
    fn entry_point(&self) -> Address;

    // return the salt used in Create2 to deploy the account
    fn salt(&self) -> U256;

    // delete an account
    fn delete_account<P: AsRef<Path>>(
        &self,
        key_store_path: P,
        _account: Address, //account to initiate the deletion, only used in multisig
        password: &str,
    ) -> Result<(), MesonWalletError>;
}
