use ethers::abi::AbiEncode;
use ethers::abi::Address;
use ethers::contract::{EthAbiCodec, EthAbiType};
use ethers::core::utils::keccak256;
use ethers::prelude::{Bytes, H256, U256};
use ethers::utils::hex;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

// Parameters for user_operation
#[derive(Clone, Default, PartialEq, Eq, Debug, EthAbiCodec, EthAbiType, Serialize, Deserialize)]
pub struct UserOperation {
    // The account making the operation
    pub sender: Address,

    // Anti-replay parameter;
    pub nonce: U256,

    // The initCode of the account (needed if and only if the account is not yet on-chain and needs to be created)
    #[serde(rename = "initCode")]
    pub init_code: Bytes,

    // The data to pass to the sender during the main execution call
    #[serde(rename = "callData")]
    pub call_data: Bytes,

    // The amount of gas to allocate the main execution call
    #[serde(rename = "callGasLimit")]
    pub call_gas_limit: U256,

    // The amount of gas to allocate for the verification step
    #[serde(rename = "verificationGasLimit")]
    pub verification_gas_limit: U256,

    // The amount of gas to pay for to compensate the bundler for pre-verification execution and calldata
    #[serde(rename = "preVerificationGas")]
    pub pre_verification_gas: U256,

    // Maximum fee per gas (similar to EIP-1559 max_fee_per_gas)
    #[serde(rename = "maxFeePerGas")]
    pub max_fee_per_gas: U256,

    // Maximum priority fee per gas (similar to EIP-1559 max_priority_fee_per_gas)
    #[serde(rename = "maxPriorityFeePerGas")]
    pub max_priority_fee_per_gas: U256,

    // Address of paymaster sponsoring the transaction, followed by extra data to send to the paymaster (empty for self-sponsored transaction)
    #[serde(rename = "paymasterAndData")]
    pub paymaster_and_data: Bytes,

    // Data passed into the account along with the nonce during the verification step
    pub signature: Bytes,
}

impl UserOperation {
    // Creates an emtpy userOperation with all fields left empty
    pub fn new() -> Self {
        Self::default()
    }

    // Sets the `sender` field in the transaction to the provided value
    #[must_use]
    pub fn sender<T: Into<Address>>(mut self, sender: T) -> Self {
        self.sender = sender.into();
        self
    }

    // Sets the `nonce` field in the transaction to the provided value
    #[must_use]
    pub fn nonce<T: Into<U256>>(mut self, nonce: T) -> Self {
        self.nonce = nonce.into();
        self
    }

    // Sets the `init_code` field in the transaction to the provided value
    #[must_use]
    pub fn init_code<T: Into<Bytes>>(mut self, init_code: T) -> Self {
        self.init_code = init_code.into();
        self
    }

    // Sets the `call_data` field in the transaction to the provided value
    #[must_use]
    pub fn call_data<T: Into<Bytes>>(mut self, call_data: T) -> Self {
        self.call_data = call_data.into();
        self
    }

    // Sets the `call_gas_limit` field in the transaction to the provided value
    #[must_use]
    pub fn call_gas_limit<T: Into<U256>>(mut self, call_gas_limit: T) -> Self {
        self.call_gas_limit = call_gas_limit.into();
        self
    }

    // Sets the `verification_gas_limit` field in the transaction to the provided value
    #[must_use]
    pub fn verification_gas_limit<T: Into<U256>>(mut self, verification_gas_limit: T) -> Self {
        self.verification_gas_limit = verification_gas_limit.into();
        self
    }

    // Sets the `pre_verification_gas` field in the transaction to the provided value
    #[must_use]
    pub fn pre_verification_gas<T: Into<U256>>(mut self, pre_verification_gas: T) -> Self {
        self.pre_verification_gas = pre_verification_gas.into();
        self
    }

    // Sets the `max_fee_per_gas` field in the transaction to the provided value
    #[must_use]
    pub fn max_fee_per_gas<T: Into<U256>>(mut self, max_fee_per_gas: T) -> Self {
        self.max_fee_per_gas = max_fee_per_gas.into();
        self
    }

    // Sets the `max_priority_fee_per_gas` field in the transaction to the provided value
    #[must_use]
    pub fn max_priority_fee_per_gas<T: Into<U256>>(mut self, max_priority_fee_per_gas: T) -> Self {
        self.max_priority_fee_per_gas = max_priority_fee_per_gas.into();
        self
    }

    // Sets the `paymaster_and_data` field in the transaction to the provided value
    // the wallet doesn't support paymaster yet
    #[allow(dead_code)]
    #[must_use]
    pub fn paymaster_and_data<T: Into<Bytes>>(mut self, paymaster_and_data: T) -> Self {
        self.paymaster_and_data = paymaster_and_data.into();
        self
    }

    // Sets the `signature` field in the transaction to the provided value
    #[must_use]
    pub fn signature<T: Into<Bytes>>(mut self, signature: T) -> Self {
        self.signature = signature.into();
        self
    }

    // pack the userOp for signature
    pub fn pack(&self) -> Vec<u8> {
        let user_operation_packed = UserOperationUnsigned::from(self.clone());
        user_operation_packed.encode()
    }

    // hash the packed userOp for signature
    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.pack();
        let hash = keccak256(bytes);
        hash
    }

    // return the function signature called in wallet contract
    pub fn get_function_signature(&self) -> String {
        "0x".to_string() + &hex::encode(&self.call_data[..4])
    }

    // return the receipient of a userOp
    pub fn get_receipient(&self) -> String {
        "0x".to_string() + &hex::encode(&self.call_data[16..36])
    }

    // return the amount of a userOp
    pub fn get_amount(&self) -> U256 {
        U256::from_big_endian(&self.call_data[36..68])
    }

    // return the data of a userOp
    pub fn get_data(&self) -> String {
        hex::encode(&self.call_data[68..])
    }
}

// user operation without signature for signing
#[derive(EthAbiCodec, EthAbiType)]
pub struct UserOperationUnsigned {
    pub sender: Address,
    pub nonce: U256,
    pub init_code: H256,
    pub call_data: H256,
    pub call_gas_limit: U256,
    pub verification_gas_limit: U256,
    pub pre_verification_gas: U256,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
    pub paymaster_and_data: H256,
}

impl From<UserOperation> for UserOperationUnsigned {
    fn from(value: UserOperation) -> Self {
        Self {
            sender: value.sender,
            nonce: value.nonce,
            init_code: keccak256(value.init_code.deref()).into(),
            call_data: keccak256(value.call_data.deref()).into(),
            call_gas_limit: value.call_gas_limit,
            verification_gas_limit: value.verification_gas_limit,
            pre_verification_gas: value.pre_verification_gas,
            max_fee_per_gas: value.max_fee_per_gas,
            max_priority_fee_per_gas: value.max_priority_fee_per_gas,
            paymaster_and_data: keccak256(value.paymaster_and_data.deref()).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_pack_user_op() {
        let mut user_op = UserOperation::new();
        user_op = user_op
            .sender(Address::from_str("0x85ef6db74c13b3bfa12a784702418e5aafad73eb").unwrap())
            .nonce(0i32)
            .call_data(Bytes::from_str("0x23").unwrap())
            .call_gas_limit(999i32)
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
