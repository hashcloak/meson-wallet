#![allow(non_snake_case)]
use ethers::abi::AbiEncode;
use ethers::abi::Address;
use ethers::contract::{EthAbiCodec, EthAbiType};
use ethers::core::utils::keccak256;
use ethers::prelude::{Bytes, H256, U256};
use std::ops::Deref;
use std::str::FromStr;
//use ethers_core::types::*;
use serde::{Deserialize, Serialize};

/// Parameters for user_operation
#[derive(Clone, Default, PartialEq, Eq, Debug, EthAbiCodec, EthAbiType, Serialize)]
pub struct UserOperation {
    /// The account making the operation
    pub sender: Address,

    /// Anti-replay parameter; also used as the salt for first-time account creation
    pub nonce: U256,

    /// The initCode of the account (needed if and only if the account is not yet on-chain and needs to be created)
    pub initCode: Bytes,

    /// The data to pass to the sender during the main execution call
    pub callData: Bytes,

    /// The amount of gas to allocate the main execution call
    pub callGasLimit: U256,

    /// The amount of gas to allocate for the verification step
    pub verificationGasLimit: U256,

    /// The amount of gas to pay for to compensate the bundler for pre-verification execution and calldata
    pub preVerificationGas: U256,

    /// Maximum fee per gas (similar to EIP-1559 max_fee_per_gas)
    pub maxFeePerGas: U256,

    /// Maximum priority fee per gas (similar to EIP-1559 max_priority_fee_per_gas)
    pub maxPriorityFeePerGas: U256,

    /// Address of paymaster sponsoring the transaction, followed by extra data to send to the paymaster (empty for self-sponsored transaction)
    pub paymasterAndData: Bytes,

    /// Data passed into the account along with the nonce during the verification step
    pub signature: Bytes, /////////////////  Celo-specific transaction fields /////////////////
}

impl UserOperation {
    /// Creates an emtpy userOperation with all fields left empty
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `sender` field in the transaction to the provided value
    #[must_use]
    pub fn sender<T: Into<Address>>(mut self, sender: T) -> Self {
        self.sender = sender.into();
        self
    }

    /// Sets the `nonce` field in the transaction to the provided value
    #[must_use]
    pub fn nonce<T: Into<U256>>(mut self, nonce: T) -> Self {
        self.nonce = nonce.into();
        self
    }

    /// Sets the `init_code` field in the transaction to the provided value
    #[must_use]
    pub fn init_code<T: Into<Bytes>>(mut self, init_code: T) -> Self {
        self.initCode = init_code.into();
        self
    }

    /// Sets the `call_data` field in the transaction to the provided value
    #[must_use]
    pub fn call_data<T: Into<Bytes>>(mut self, call_data: T) -> Self {
        self.callData = call_data.into();
        self
    }

    /// Sets the `call_gas_imit` field in the transaction to the provided value
    #[must_use]
    pub fn call_gas_imit<T: Into<U256>>(mut self, call_gas_imit: T) -> Self {
        self.callGasLimit = call_gas_imit.into();
        self
    }

    /// Sets the `verification_gas_limit` field in the transaction to the provided value
    #[must_use]
    pub fn verification_gas_limit<T: Into<U256>>(mut self, verification_gas_limit: T) -> Self {
        self.verificationGasLimit = verification_gas_limit.into();
        self
    }

    /// Sets the `pre_verification_gas` field in the transaction to the provided value
    #[must_use]
    pub fn pre_verification_gas<T: Into<U256>>(mut self, pre_verification_gas: T) -> Self {
        self.preVerificationGas = pre_verification_gas.into();
        self
    }

    /// Sets the `max_fee_per_gas` field in the transaction to the provided value
    #[must_use]
    pub fn max_fee_per_gas<T: Into<U256>>(mut self, max_fee_per_gas: T) -> Self {
        self.maxFeePerGas = max_fee_per_gas.into();
        self
    }

    /// Sets the `max_priority_fee_per_gas` field in the transaction to the provided value
    #[must_use]
    pub fn max_priority_fee_per_gas<T: Into<U256>>(mut self, max_priority_fee_per_gas: T) -> Self {
        self.maxPriorityFeePerGas = max_priority_fee_per_gas.into();
        self
    }

    /// Sets the `paymaster_and_data` field in the transaction to the provided value
    #[must_use]
    pub fn paymaster_and_data<T: Into<Bytes>>(mut self, paymaster_and_data: T) -> Self {
        self.paymasterAndData = paymaster_and_data.into();
        self
    }

    /// Sets the `signature` field in the transaction to the provided value
    #[must_use]
    pub fn signature<T: Into<Bytes>>(mut self, signature: T) -> Self {
        self.signature = signature.into();
        self
    }

    ///For lighter signature scheme
    pub fn pack(&self) -> Vec<u8> {
        let user_operation_packed = UserOperationUnsigned::from(self.clone());
        user_operation_packed.encode()
    }

    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.pack();
        let hash = keccak256(bytes);
        hash
    }
}

#[derive(EthAbiCodec, EthAbiType)]
pub struct UserOperationUnsigned {
    pub sender: Address,
    pub nonce: U256,
    pub initCode: H256,
    pub callData: H256,
    pub callGasLimit: U256,
    pub verificationGasLimit: U256,
    pub preVerificationGas: U256,
    pub maxFeePerGas: U256,
    pub maxPriorityFeePerGas: U256,
    pub paymasterAndData: H256,
}

impl From<UserOperation> for UserOperationUnsigned {
    fn from(value: UserOperation) -> Self {
        Self {
            sender: value.sender,
            nonce: value.nonce,
            initCode: keccak256(value.initCode.deref()).into(),
            callData: keccak256(value.callData.deref()).into(),
            callGasLimit: value.callGasLimit,
            verificationGasLimit: value.verificationGasLimit,
            preVerificationGas: value.preVerificationGas,
            maxFeePerGas: value.maxFeePerGas,
            maxPriorityFeePerGas: value.maxPriorityFeePerGas,
            paymasterAndData: keccak256(value.paymasterAndData.deref()).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_user_op() {
        let mut user_op = UserOperation::new();
        user_op = user_op
            .sender(Address::from_str("0x85ef6db74c13b3bfa12a784702418e5aafad73eb").unwrap())
            .nonce(0i32)
            .call_data(Bytes::from_str("0x23").unwrap())
            .call_gas_imit(999i32)
            .verification_gas_limit(999i32)
            .pre_verification_gas(999i32)
            .max_fee_per_gas(999i32)
            .max_priority_fee_per_gas(999i32)
            .paymaster_and_data(Bytes::from_str("0x12345678").unwrap())
            .signature(Bytes::from_str("0x0000").unwrap());

        user_op = user_op.signature(Bytes::default());
        //let encode_byte = user_op.encode();
        let abiencode_op = user_op.pack();
        let b = Bytes::try_from(abiencode_op).unwrap().to_string();
        print!("{:?}", b);
    }
}
