use crate::user_opertaion::{self, UserOperation};
use ethers::prelude::{Address, U256};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};
use std::fmt;
#[derive(Serialize)]
pub struct UserOperationRequest {
    pub jsonrpc: i8,
    pub id: i8,
    pub command: String,
    pub params: (user_opertaion::UserOperation, Address),
}

impl UserOperationRequest {
    pub fn to_json(&self) -> Vec<u8> {
        let mut json_vec = serde_json::to_vec(self).expect("eth json error");
        json_vec
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GasQueryResult {
    pub preVerificationGas: u128,
    pub verificationGas: u128,
    pub callGasLimit: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ERC4337Error {
    pub code: i64,
    pub message: String,
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SkCipher {
    pub cipher: String,
    pub mac: String,
    pub salt: String,
    pub iv: String,
}

impl std::error::Error for ERC4337Error {}
impl fmt::Display for ERC4337Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "code: {}, message: {}", self.code, self.message)
    }
}

pub trait Account {
    fn create_init_code(&self) -> Vec<u8>;

    fn sign(&self, user_op: &UserOperation, password: &str) -> Vec<u8>;

    fn address(&self) -> Address;

    fn entry_point(&self) -> Address;

    fn chain_id(&self) -> U256; //todo: does account need to hold chain_id?

    fn salt(&self) -> U256;

    fn deployed(&self) -> bool; //todo: does account need to hold deployed status?

    fn set_deployed(&mut self, status: bool); //update and save deployed status
}
