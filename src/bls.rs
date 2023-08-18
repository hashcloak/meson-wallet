use crate::erc4337_common::Account;
use crate::erc4337wallet::Erc4337Wallet;
use crate::user_opertaion::UserOperation;
use ethers::abi::AbiEncode;
use ethers::core::types::{Address, Bytes, U256};
use ethers::utils::{get_create2_address, hex, keccak256};
use rand::random;
use serde::{Deserialize, Serialize};
use sig::{PrivateKey, PublicKey, SolPublicKey};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use toml::Value;
pub mod hash_to_point;
pub mod multi_sig;
pub mod sig;

const BLS_CREATE_ACCOUNT_SIGNATURE: &str = "0x19c2a1b2";
const BLS_WALLET_LOGIC_INITIALIZE_SIGNATURE: &str = "0xee472f36";

#[derive(Deserialize, Serialize)]
pub struct BLSAccount {
    address: Address,
    aggregator: Address,
    public_key: SolPublicKey,
    entry_point: Address,
    salt: U256,
    chain_id: U256,
    deployed: bool,
}

impl BLSAccount {
    pub fn new<P: AsRef<Path>>(
        key_store_path: P,
        supported_accounts_path: P,
        entry_point: Address,
        aggregator: Option<Address>,
        chain_id: U256,
        password: &str,
    ) -> Self {
        let salt: u128 = random();
        let salt = U256::from(salt);
        //generate bls sk/pk
        let mut rng = rand::thread_rng();
        let sk = PrivateKey::new(&mut rng);
        let pk = sk.derive_public_key();
        let pk_sol = pk.to_solidity_pk();

        let address: Address =
            Self::bls_create2addr(pk_sol, salt, supported_accounts_path, &chain_id.to_string());

        let aggregator = match aggregator {
            Some(addr) => addr,
            None => Address::zero(),
        };

        //create bls keystore dir
        let addr_str = "0x".to_owned() + &hex::encode(address);
        let dir = key_store_path.as_ref().join("bls").join(&addr_str);
        fs::create_dir_all(&dir).unwrap();

        let account = BLSAccount {
            address: address,
            aggregator: aggregator,
            public_key: pk_sol,
            entry_point: entry_point,
            salt: salt,
            chain_id: chain_id,
            deployed: false,
        };

        //encrypt and store bls private key
        let key_dir = account.get_key_path(&key_store_path);
        Erc4337Wallet::encrypt_key(key_dir, &mut rng, sk.to_bytes(), password).unwrap();

        //store account settings
        let account_dir = account.get_account_path(&key_store_path);
        let contents = serde_json::to_string(&account).unwrap();
        fs::write(account_dir, contents.as_bytes()).unwrap();

        account
    }

    pub fn load_account<P: AsRef<Path>>(key_store_path: P, address: &str) -> Self {
        let dir = key_store_path
            .as_ref()
            .join("bls")
            .join(address)
            .join("account");
        let json_str = fs::read_to_string(dir).unwrap();
        let account: Self = serde_json::from_str(&json_str).unwrap();
        account
    }

    pub fn verify(&self, user_op: &UserOperation, signature: &[u8]) -> bool {
        let pk = self.public_key;
        let pk = PublicKey::from_solidity_pk(pk);
        let user_op_hash;
        if Address::is_zero(&self.aggregator) {
            user_op_hash = keccak256(AbiEncode::encode((
                user_op.hash(),
                self.entry_point,
                self.chain_id,
            )));
        } else {
            //todo: user_op_hash should follow ERC standard, consider update it in contract
            user_op_hash = keccak256(AbiEncode::encode((
                user_op.hash(),
                self.entry_point,
                self.aggregator,
                self.chain_id,
            )));
        }
        sig::verify(&pk, &user_op_hash, signature)
    }

    pub fn bls_create2addr<P: AsRef<Path>>(
        bls_pk: SolPublicKey,
        salt: U256,
        supported_accounts_path: P,
        chain_id: &str,
    ) -> Address {
        //creationcode of SmartWalletProxy
        let proxy_creationcode = "0x608060405260405161056f38038061056f83398101604081905261002291610315565b61004d60017f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbd6103e3565b6000805160206105288339815191521461006957610069610404565b6100758282600061007c565b5050610469565b610085836100a8565b6000825111806100925750805b156100a3576100a183836100e8565b505b505050565b6100b181610116565b6040516001600160a01b038216907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a250565b606061010d8383604051806060016040528060278152602001610548602791396101b7565b90505b92915050565b6001600160a01b0381163b6101885760405162461bcd60e51b815260206004820152602d60248201527f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60448201526c1bdd08184818dbdb9d1c9858dd609a1b60648201526084015b60405180910390fd5b60008051602061052883398151915280546001600160a01b0319166001600160a01b0392909216919091179055565b6060600080856001600160a01b0316856040516101d4919061041a565b600060405180830381855af49150503d806000811461020f576040519150601f19603f3d011682016040523d82523d6000602084013e610214565b606091505b50909250905061022686838387610230565b9695505050505050565b6060831561029f578251600003610298576001600160a01b0385163b6102985760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000604482015260640161017f565b50816102a9565b6102a983836102b1565b949350505050565b8151156102c15781518083602001fd5b8060405162461bcd60e51b815260040161017f9190610436565b634e487b7160e01b600052604160045260246000fd5b60005b8381101561030c5781810151838201526020016102f4565b50506000910152565b6000806040838503121561032857600080fd5b82516001600160a01b038116811461033f57600080fd5b60208401519092506001600160401b038082111561035c57600080fd5b818501915085601f83011261037057600080fd5b815181811115610382576103826102db565b604051601f8201601f19908116603f011681019083821181831017156103aa576103aa6102db565b816040528281528860208487010111156103c357600080fd5b6103d48360208301602088016102f1565b80955050505050509250929050565b8181038181111561011057634e487b7160e01b600052601160045260246000fd5b634e487b7160e01b600052600160045260246000fd5b6000825161042c8184602087016102f1565b9190910192915050565b60208152600082518060208401526104558160408501602087016102f1565b601f01601f19169190910160400192915050565b60b1806104776000396000f3fe608060405236601057600e6013565b005b600e5b601f601b6021565b6058565b565b600060537f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc546001600160a01b031690565b905090565b3660008037600080366000845af43d6000803e8080156076573d6000f35b3d6000fdfea264697066735822122065207dc1a60d8131efa0ba219be3fe606ea96daf76f30bc66174f38ce749f15264736f6c63430008130033360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564";
        let signature = Bytes::from_str(BLS_WALLET_LOGIC_INITIALIZE_SIGNATURE)
            .unwrap()
            .to_vec();
        let param = AbiEncode::encode(bls_pk);
        let encode_call = [signature, param].concat();
        let impl_addr = Address::from_str(&Self::account_impl_address(
            chain_id,
            &supported_accounts_path,
        ))
        .unwrap();
        let mut creationcode_param = AbiEncode::encode((impl_addr, Bytes::from(encode_call)));
        let mut init_code = Bytes::from_str(proxy_creationcode).unwrap().to_vec();
        init_code.append(&mut creationcode_param);
        let af_addr = Address::from_str(&Self::account_factory_address(
            chain_id,
            &supported_accounts_path,
        ))
        .unwrap();
        let addr = get_create2_address(af_addr, salt.encode(), init_code);
        addr
    }

    fn get_key_path<P: AsRef<Path>>(&self, key_store_path: P) -> PathBuf {
        let addr_str = "0x".to_owned() + &hex::encode(self.address);
        key_store_path
            .as_ref()
            .join("bls")
            .join(addr_str)
            .join("key")
    }

    fn get_account_path<P: AsRef<Path>>(&self, key_store_path: P) -> PathBuf {
        let addr_str = "0x".to_owned() + &hex::encode(self.address);
        key_store_path
            .as_ref()
            .join("bls")
            .join(addr_str)
            .join("account")
    }

    //read account factory address from config file
    fn account_factory_address<P: AsRef<Path>>(
        chain_id: &str,
        supported_accounts_path: P,
    ) -> String {
        let toml_str = fs::read_to_string(supported_accounts_path).unwrap();
        let value = &toml_str.parse::<Value>().unwrap();
        let a = value["bls"][chain_id]["BLS_ACCOUNT_FACTORY_ADDRESS"]
            .as_str()
            .unwrap();
        a.to_string()
    }

    //read account implementation address from config file
    fn account_impl_address<P: AsRef<Path>>(chain_id: &str, supported_accounts_path: P) -> String {
        let toml_str = fs::read_to_string(supported_accounts_path).unwrap();
        let value = &toml_str.parse::<Value>().unwrap();
        let a = value["bls"][chain_id]["BLS_ACCOUNT_IMPLEMENTATION"]
            .as_str()
            .unwrap();
        a.to_string()
    }
}

impl Account for BLSAccount {
    fn create_init_code<P: AsRef<Path>>(&self, supported_accounts_path: P) -> Vec<u8> {
        let mut signature = Bytes::from_str(BLS_CREATE_ACCOUNT_SIGNATURE)
            .unwrap()
            .to_vec();
        let mut param = AbiEncode::encode((self.salt, self.public_key));
        let af_addr =
            Self::account_factory_address(&self.chain_id.to_string(), supported_accounts_path);
        let bls_af_addr = Address::from_str(&af_addr).unwrap();
        let mut init_code = bls_af_addr.as_bytes().to_vec();
        init_code.append(&mut signature);
        init_code.append(&mut param);

        init_code
    }

    fn sign<P: AsRef<Path>>(
        &self,
        user_op: &UserOperation,
        password: &str,
        key_store_path: P,
    ) -> Vec<u8> {
        let user_op_hash;
        if Address::is_zero(&self.aggregator) {
            user_op_hash = keccak256(AbiEncode::encode((
                user_op.hash(),
                self.entry_point,
                self.chain_id,
            )));
        } else {
            //todo: user_op_hash should follow ERC standard, consider update it in contract
            user_op_hash = keccak256(AbiEncode::encode((
                user_op.hash(),
                keccak256(AbiEncode::encode(self.public_key)),
                self.aggregator,
                self.chain_id,
            )));
        }
        let key_dir = self.get_key_path(key_store_path);
        let sk = Erc4337Wallet::decrypt_key(key_dir, password).unwrap();
        let sk = PrivateKey::from_bytes(&sk);
        sig::sign(&sk, &user_op_hash)
    }

    fn address(&self) -> Address {
        self.address
    }

    fn deployed(&self) -> bool {
        self.deployed
    }

    fn set_deployed<P: AsRef<Path>>(&mut self, status: bool, key_store_path: P) {
        self.deployed = status;
        let account_dir = self.get_account_path(key_store_path);
        let mut file = fs::File::create(account_dir).unwrap();
        let contents = serde_json::to_string(self).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
    }

    fn entry_point(&self) -> Address {
        self.entry_point
    }

    fn chain_id(&self) -> U256 {
        self.chain_id
    }

    fn salt(&self) -> U256 {
        self.salt
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub fn test_store_sign_bls() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(&wallet_config_path);
        let bls_account = BLSAccount::new(
            &wallet.key_store_path,
            &wallet.supported_accounts_path,
            "0x3cD5A8Ddd0EFb5804978a4Da74D3Fb6d074829F3"
                .parse()
                .unwrap(),
            None,
            U256::from(12345),
            "123456789",
        );
        let addr_str = "0x".to_owned() + &hex::encode(bls_account.address);
        let bls_account2 = BLSAccount::load_account(&wallet.key_store_path, &addr_str);

        let user_op = UserOperation::new();
        let sig = bls_account.sign(&user_op, "123456789", &wallet.key_store_path);
        assert!(bls_account.verify(&user_op, &sig));
        assert!(bls_account2.verify(&user_op, &sig));
    }
}
