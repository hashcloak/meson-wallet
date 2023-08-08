use crate::user_opertaion;
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

impl std::error::Error for ERC4337Error {}
impl fmt::Display for ERC4337Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "code: {}, message: {}", self.code, self.message)
    }
}

pub trait Account {
    fn create_init_code(&self) -> Vec<u8>;

    fn get_create2_address(&self) -> Address;

    fn sign(&self, msg: &[u8]) -> Vec<u8>;
}
