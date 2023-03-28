use ethers::abi::AbiEncode;
use ethers::core::utils::{get_create2_address, keccak256};
use ethers::prelude::{k256, Address, Bytes, Selector, U256};
use std::{fmt::Write, num::ParseIntError, str::FromStr};

const CREATE_ACCOUNT_SIGNATURE: &str = "0x5fbfb9cf";
const WALLET_LOGIC_INITIALIZE_SIGNATURE: &str = "0xc4d66de8";
const ACCOUNT_FACTORY_ADDRESS: &str = "0xd9145CCE52D386f254917e481eB44e9943F39138"; //test only
const ACCOUNT_IMPLEMENTATION: &str = "0xc0ffee254729296a45a3885639AC7E10F9d54979"; //test only //wallet logic address

pub fn create_init_code(owner: Address, salt: U256) -> Vec<u8> {
    let mut signature = Bytes::from_str(CREATE_ACCOUNT_SIGNATURE).unwrap().to_vec();
    let mut param = AbiEncode::encode((owner, salt));

    let af_addr = Address::from_str(ACCOUNT_FACTORY_ADDRESS).unwrap();
    let mut init_code = af_addr.as_bytes().to_vec();
    init_code.append(&mut signature);
    init_code.append(&mut param);

    init_code
}

pub fn create2addr(owner: Address, salt: U256) -> Address {
    //creationcode of SmartWalletProxy
    let proxy_creationcode = "0x608060405260405161056f38038061056f83398101604081905261002291610315565b61004d60017f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbd6103e3565b6000805160206105288339815191521461006957610069610404565b6100758282600061007c565b5050610469565b610085836100a8565b6000825111806100925750805b156100a3576100a183836100e8565b505b505050565b6100b181610116565b6040516001600160a01b038216907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a250565b606061010d8383604051806060016040528060278152602001610548602791396101b7565b90505b92915050565b6001600160a01b0381163b6101885760405162461bcd60e51b815260206004820152602d60248201527f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60448201526c1bdd08184818dbdb9d1c9858dd609a1b60648201526084015b60405180910390fd5b60008051602061052883398151915280546001600160a01b0319166001600160a01b0392909216919091179055565b6060600080856001600160a01b0316856040516101d4919061041a565b600060405180830381855af49150503d806000811461020f576040519150601f19603f3d011682016040523d82523d6000602084013e610214565b606091505b50909250905061022686838387610230565b9695505050505050565b6060831561029f578251600003610298576001600160a01b0385163b6102985760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000604482015260640161017f565b50816102a9565b6102a983836102b1565b949350505050565b8151156102c15781518083602001fd5b8060405162461bcd60e51b815260040161017f9190610436565b634e487b7160e01b600052604160045260246000fd5b60005b8381101561030c5781810151838201526020016102f4565b50506000910152565b6000806040838503121561032857600080fd5b82516001600160a01b038116811461033f57600080fd5b60208401519092506001600160401b038082111561035c57600080fd5b818501915085601f83011261037057600080fd5b815181811115610382576103826102db565b604051601f8201601f19908116603f011681019083821181831017156103aa576103aa6102db565b816040528281528860208487010111156103c357600080fd5b6103d48360208301602088016102f1565b80955050505050509250929050565b8181038181111561011057634e487b7160e01b600052601160045260246000fd5b634e487b7160e01b600052600160045260246000fd5b6000825161042c8184602087016102f1565b9190910192915050565b60208152600082518060208401526104558160408501602087016102f1565b601f01601f19169190910160400192915050565b60b1806104776000396000f3fe608060405236601057600e6013565b005b600e5b601f601b6021565b6058565b565b600060537f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc546001600160a01b031690565b905090565b3660008037600080366000845af43d6000803e8080156076573d6000f35b3d6000fdfea264697066735822122065207dc1a60d8131efa0ba219be3fe606ea96daf76f30bc66174f38ce749f15264736f6c63430008130033360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564";
    let mut signature = Bytes::from_str(WALLET_LOGIC_INITIALIZE_SIGNATURE)
        .unwrap()
        .to_vec();
    let mut param = AbiEncode::encode(owner);
    let encode_call = [signature, param].concat();
    let impl_addr = Address::from_str(ACCOUNT_IMPLEMENTATION).unwrap();
    let mut creationcode_param = AbiEncode::encode((impl_addr, Bytes::from(encode_call)));
    let mut init_code = Bytes::from_str(proxy_creationcode).unwrap().to_vec();
    init_code.append(&mut creationcode_param);
    let af_addr = Address::from_str(ACCOUNT_FACTORY_ADDRESS).unwrap();
    let addr = get_create2_address(af_addr, salt.encode(), init_code);
    addr
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fmt::Write, num::ParseIntError, str::FromStr};

    #[test]
    fn test_encode() {
        let call = create_init_code(
            Address::from_str("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4").unwrap(),
            U256::from_dec_str("100").unwrap(),
        );
        let res = encode_hex(&call);
        assert_eq!(&res,"d9145cce52d386f254917e481eb44e9943f391385fbfb9cf0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc40000000000000000000000000000000000000000000000000000000000000064")
    }

    #[test]
    fn test_create2() {
        let addr = create2addr(
            Address::from_str("0x5B38Da6a701c568545dCfcB03FcB875f56beddC4").unwrap(),
            U256::from_dec_str("100").unwrap(),
        );
        assert_eq!(
            encode_hex(&addr.0),
            String::from("26afe755947b80f3ca127b73f98da6f8c1fba202")
        );
    }

    pub fn encode_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            write!(&mut s, "{:02x}", b).unwrap();
        }
        s
    }
}
