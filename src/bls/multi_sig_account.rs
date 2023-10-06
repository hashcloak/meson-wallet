use crate::bls::sig::{PrivateKey, PublicKey};
use crate::bls::{multi_sig, multi_sig::multi_sig_combine_sig, multi_sig::MultiSigPublicKey};
use crate::bls::{BLSAccount, BLSSolPublicKey};
use crate::erc4337_common::Account;
use crate::user_opertaion::UserOperation;
use crate::{error, Erc4337Wallet};
use ark_bn254::{Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::CurveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ethers::abi::AbiEncode;
use ethers::core::types::{Address, Bytes, U256};
use ethers::utils::{hex, keccak256};
use rand::random;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

// BLS smart contract account, implements account trait
#[derive(Deserialize, Serialize)]
pub struct BLSMultiSigAccount {
    address: Address,
    aggregator: Address, // supported erc4337 aggregator contract, 0x00 for no aggregator
    multi_sig_pk: MultiSigPublicKey, //aggregate public key & concatenation of all the public keys used in apk
    accounts_list: Vec<Address>,     // accounts used in the aggregated public key
    entry_point: Address,
    salt: U256,
    chain_id: U256,
    deployed: bool,
}

impl BLSMultiSigAccount {
    // create a new bls multisig account
    pub fn new<P: AsRef<Path>>(
        key_store_path: P,
        supported_accounts_path: P,
        entry_point: Address,
        accounts_list: Vec<Address>,
        aggregator: Option<Address>,
        chain_id: U256,
    ) -> Self {
        let public_keys_list: Vec<PublicKey> = accounts_list
            .iter()
            .map(|addr| {
                PublicKey::from_solidity_pk(
                    &BLSAccount::load_account(
                        key_store_path.as_ref(),
                        &("0x".to_owned() + &hex::encode(addr)),
                    )
                    .public_key,
                )
            })
            .collect();
        let multi_sig_pk = MultiSigPublicKey::new(&public_keys_list);
        let salt: u128 = random();
        let salt = U256::from(salt);
        let address: Address = BLSAccount::bls_create2addr(
            multi_sig_pk.apk,
            salt,
            supported_accounts_path,
            &chain_id.to_string(),
        );

        let aggregator = match aggregator {
            Some(addr) => addr,
            None => Address::zero(),
        };

        //create bls keystore dir
        let addr_str = "0x".to_owned() + &hex::encode(address);
        let dir = key_store_path.as_ref().join("bls_multisig").join(&addr_str);
        fs::create_dir_all(&dir).unwrap();
        let account = BLSMultiSigAccount {
            address,
            aggregator,
            multi_sig_pk,
            accounts_list,
            entry_point,
            salt,
            chain_id,
            deployed: false,
        };

        //store account settings
        let account_dir = account.get_account_path(&key_store_path);
        let contents = serde_json::to_string(&account).unwrap();
        fs::write(account_dir, contents.as_bytes()).unwrap();

        account
    }

    fn sign_piece<P: AsRef<Path>>(
        &self,
        key_store_path: P,
        signing_account: Address,
        user_op: &UserOperation,
        password: &str,
    ) {
        let user_op_hash;
        if Address::is_zero(&self.aggregator) {
            user_op_hash = keccak256(AbiEncode::encode((
                user_op.hash(),
                self.entry_point,
                self.chain_id,
            )));
        } else {
            user_op_hash = keccak256(AbiEncode::encode((
                user_op.hash(),
                keccak256(AbiEncode::encode(self.multi_sig_pk.apk)),
                self.aggregator,
                self.chain_id,
            )));
        }
        let key_dir = Self::get_key_path(signing_account, &key_store_path);
        let sk = Erc4337Wallet::decrypt_key(key_dir, password).unwrap();
        let sk = PrivateKey::from_bytes(&sk);
        let pk = sk.derive_public_key();
        let sig_piece = multi_sig::multi_sig_sign(&self.multi_sig_pk, &sk, &pk, &user_op_hash);
        let mut sig_compressed_bytes = Vec::<u8>::new();
        sig_piece
            .into_affine()
            .serialize_compressed(&mut sig_compressed_bytes)
            .unwrap();
        let user_op_hash = String::from("0x") + &hex::encode(user_op_hash);
        let signing_account = String::from("0x") + &hex::encode(signing_account);

        let sig_path = self.get_sig_path(&key_store_path).join(user_op_hash); //path for signature_piece & user_op
        let sig_piece_path = sig_path.join("sig_piece"); //path for signature_piece

        if !sig_path.exists() {
            // store user_op if not already exists
            fs::create_dir_all(&sig_piece_path).unwrap();
            let op_path = sig_path.join("user_op");
            fs::write(op_path, &serde_json::to_vec(&user_op).unwrap()).unwrap();
        }

        fs::write(sig_piece_path.join(signing_account), &sig_compressed_bytes).unwrap();
    }

    fn combine_sig<P: AsRef<Path>>(&self, key_store_path: P, user_op_hash: &str) -> Vec<u8> {
        //read all signatures
        let sig_path = self
            .get_sig_path(&key_store_path)
            .join(user_op_hash)
            .join("sig_piece");
        let mut sigs = Vec::new();
        let files: Vec<_>;
        match sig_path.read_dir() {
            Ok(entry) => files = entry.collect(),
            Err(_) => panic!("invalid account"),
        }
        for file in files {
            match file {
                Ok(sig_file) => {
                    let sig = fs::read(sig_file.path()).unwrap();
                    let sig = G1Projective::from(
                        G1Affine::deserialize_compressed(sig.as_slice()).unwrap(),
                    );
                    sigs.push(sig);
                }
                Err(error) => panic!("sig file error, {}", error),
            }
        }

        multi_sig_combine_sig(&sigs)
    }

    // get the path for storing account info
    fn get_account_path<P: AsRef<Path>>(&self, key_store_path: P) -> PathBuf {
        let addr_str = "0x".to_owned() + &hex::encode(self.address);
        key_store_path
            .as_ref()
            .join("bls_multisig")
            .join(addr_str)
            .join("account")
    }

    // get the path for storing encrypted key
    fn get_key_path<P: AsRef<Path>>(addr: Address, key_store_path: P) -> PathBuf {
        let addr_str = "0x".to_owned() + &hex::encode(addr);
        key_store_path
            .as_ref()
            .join("bls")
            .join(addr_str)
            .join("key")
    }

    // get the path for storing signature piece
    fn get_sig_path<P: AsRef<Path>>(&self, key_store_path: P) -> PathBuf {
        let addr_str = "0x".to_owned() + &hex::encode(self.address);
        key_store_path
            .as_ref()
            .join("bls_multisig")
            .join(addr_str)
            .join("signature")
    }
}

// implement account trait for bls multisig account
impl Account for BLSMultiSigAccount {
    fn create_init_code<P: AsRef<Path>>(&self, supported_accounts_path: P) -> Vec<u8> {
        let mut signature = Bytes::from_str(super::BLS_CREATE_ACCOUNT_SIGNATURE)
            .unwrap()
            .to_vec();
        let mut param = AbiEncode::encode((self.salt, self.multi_sig_pk.apk));
        let af_addr = BLSAccount::account_factory_address(
            &self.chain_id.to_string(),
            supported_accounts_path,
        );
        let bls_af_addr = Address::from_str(&af_addr).unwrap();
        let mut init_code = bls_af_addr.as_bytes().to_vec();
        init_code.append(&mut signature);
        init_code.append(&mut param);

        init_code
    }

    // combine signature piece
    fn sign<P: AsRef<Path>>(
        &self,
        user_op: &UserOperation,
        _password: &str,
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
            user_op_hash = keccak256(AbiEncode::encode((
                user_op.hash(),
                keccak256(AbiEncode::encode(self.multi_sig_pk.apk)),
                self.aggregator,
                self.chain_id,
            )));
        };
        let user_op_hash = String::from("0x") + &hex::encode(user_op_hash);

        self.combine_sig(key_store_path, &user_op_hash)
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

mod test {
    use super::*;

    impl BLSMultiSigAccount {
        // verify the signature in an user_op
        pub fn verify(&self, user_op: &UserOperation, signature: &[u8]) -> bool {
            let pk = self.multi_sig_pk.apk;
            let pk = PublicKey::from_solidity_pk(&pk);
            let user_op_hash;
            if Address::is_zero(&self.aggregator) {
                user_op_hash = keccak256(AbiEncode::encode((
                    user_op.hash(),
                    self.entry_point,
                    self.chain_id,
                )));
            } else {
                user_op_hash = keccak256(AbiEncode::encode((
                    user_op.hash(),
                    self.entry_point,
                    self.aggregator,
                    self.chain_id,
                )));
            }
            crate::bls::sig::verify(&pk, &user_op_hash, signature)
        }
    }

    #[test]
    pub fn test_sign() {
        let wallet_config_path = PathBuf::from("wallet_config.toml");
        let wallet = Erc4337Wallet::new(&wallet_config_path);
        let bls_account1 = BLSAccount::new(
            &wallet.key_store_path,
            &wallet.supported_accounts_path,
            "0x3cD5A8Ddd0EFb5804978a4Da74D3Fb6d074829F3"
                .parse()
                .unwrap(),
            None,
            U256::from(12345),
            "123456789",
        );
        let bls_account2 = BLSAccount::new(
            &wallet.key_store_path,
            &wallet.supported_accounts_path,
            "0x3cD5A8Ddd0EFb5804978a4Da74D3Fb6d074829F3"
                .parse()
                .unwrap(),
            None,
            U256::from(12345),
            "123456789",
        );
        let bls_account3 = BLSAccount::new(
            &wallet.key_store_path,
            &wallet.supported_accounts_path,
            "0x3cD5A8Ddd0EFb5804978a4Da74D3Fb6d074829F3"
                .parse()
                .unwrap(),
            None,
            U256::from(12345),
            "123456789",
        );
        let accounts_list = vec![
            bls_account1.address,
            bls_account2.address,
            bls_account3.address,
        ];

        let bls_multisig_account = BLSMultiSigAccount::new(
            &wallet.key_store_path,
            &wallet.supported_accounts_path,
            "0x3cD5A8Ddd0EFb5804978a4Da74D3Fb6d074829F3"
                .parse()
                .unwrap(),
            accounts_list,
            None,
            U256::from(12345),
        );
        //let addr_str = "0x".to_owned() + &hex::encode(bls_account.address);
        let user_op = UserOperation::new();
        bls_multisig_account.sign_piece(
            &wallet.key_store_path,
            bls_account1.address,
            &user_op,
            "123456789",
        );
        bls_multisig_account.sign_piece(
            &wallet.key_store_path,
            bls_account2.address,
            &user_op,
            "123456789",
        );
        bls_multisig_account.sign_piece(
            &wallet.key_store_path,
            bls_account3.address,
            &user_op,
            "123456789",
        );

        let sig = bls_multisig_account.sign(&user_op, "0", &wallet.key_store_path);
        assert!(bls_multisig_account.verify(&user_op, &sig));

        bls_account1.delete_account(&wallet.key_store_path, Address::zero(), "123456789");
        bls_account2.delete_account(&wallet.key_store_path, Address::zero(), "123456789");
        bls_account3.delete_account(&wallet.key_store_path, Address::zero(), "123456789");
    }
}
