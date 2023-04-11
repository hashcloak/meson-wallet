use ethers::abi::AbiEncode;
use ethers::abi::Address;
use ethers::contract::{EthAbiCodec, EthAbiType};
use ethers::core::utils::keccak256;
use ethers::prelude::{Bytes, U256};
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
    pub init_code: Bytes,

    /// The data to pass to the sender during the main execution call
    pub call_data: Bytes,

    /// The amount of gas to allocate the main execution call
    pub call_gas_imit: U256,

    /// The amount of gas to allocate for the verification step
    pub verification_gas_limit: U256,

    /// The amount of gas to pay for to compensate the bundler for pre-verification execution and calldata
    pub pre_verification_gas: U256,

    /// Maximum fee per gas (similar to EIP-1559 max_fee_per_gas)
    pub max_fee_per_gas: U256,

    /// Maximum priority fee per gas (similar to EIP-1559 max_priority_fee_per_gas)
    pub max_priority_fee_per_gas: U256,

    /// Address of paymaster sponsoring the transaction, followed by extra data to send to the paymaster (empty for self-sponsored transaction)
    pub paymaster_and_data: Bytes,

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
        self.init_code = init_code.into();
        self
    }

    /// Sets the `call_data` field in the transaction to the provided value
    #[must_use]
    pub fn call_data<T: Into<Bytes>>(mut self, call_data: T) -> Self {
        self.call_data = call_data.into();
        self
    }

    /// Sets the `call_gas_imit` field in the transaction to the provided value
    #[must_use]
    pub fn call_gas_imit<T: Into<U256>>(mut self, call_gas_imit: T) -> Self {
        self.call_gas_imit = call_gas_imit.into();
        self
    }

    /// Sets the `verification_gas_limit` field in the transaction to the provided value
    #[must_use]
    pub fn verification_gas_limit<T: Into<U256>>(mut self, verification_gas_limit: T) -> Self {
        self.verification_gas_limit = verification_gas_limit.into();
        self
    }

    /// Sets the `pre_verification_gas` field in the transaction to the provided value
    #[must_use]
    pub fn pre_verification_gas<T: Into<U256>>(mut self, pre_verification_gas: T) -> Self {
        self.pre_verification_gas = pre_verification_gas.into();
        self
    }

    /// Sets the `max_fee_per_gas` field in the transaction to the provided value
    #[must_use]
    pub fn max_fee_per_gas<T: Into<U256>>(mut self, max_fee_per_gas: T) -> Self {
        self.max_fee_per_gas = max_fee_per_gas.into();
        self
    }

    /// Sets the `max_priority_fee_per_gas` field in the transaction to the provided value
    #[must_use]
    pub fn max_priority_fee_per_gas<T: Into<U256>>(mut self, max_priority_fee_per_gas: T) -> Self {
        self.max_priority_fee_per_gas = max_priority_fee_per_gas.into();
        self
    }

    /// Sets the `paymaster_and_data` field in the transaction to the provided value
    #[must_use]
    pub fn paymaster_and_data<T: Into<Bytes>>(mut self, paymaster_and_data: T) -> Self {
        self.paymaster_and_data = paymaster_and_data.into();
        self
    }

    /// Sets the `signature` field in the transaction to the provided value
    #[must_use]
    pub fn signature<T: Into<Bytes>>(mut self, signature: T) -> Self {
        self.signature = signature.into();
        self
    }

    ///For ighter signature scheme
    pub fn pack_into(mut self) -> Vec<u8> {
        let mut bytes = self.encode();
        bytes.resize(bytes.len() - 32, 0);
        bytes
    }

    pub fn hash(mut self) -> [u8; 32] {
        let bytes = self.pack_into();
        let hash = keccak256(bytes);
        hash
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
            .max_priority_fee_per_gas(999i32);

        let abiencode_op = user_op.pack_into();
        let b = Bytes::try_from(abiencode_op).unwrap().to_string();
        print!("{:?}", b);
    }
}
