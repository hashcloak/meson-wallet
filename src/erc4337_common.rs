use crate::user_opertaion;
use ethers::prelude::{Address, U256};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize};

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
