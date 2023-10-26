use crate::erc4337_common::{Account, GasQueryResult, SkCipher};
use crate::error::MesonWalletError;
use crate::tornado_util::Deposit;
use crate::user_opertaion::UserOperation;
use aes::cipher::{KeyIvInit, StreamCipher};
use base64ct::{Base64, Encoding};
use ethers::abi::AbiEncode;
use ethers::prelude::{Address, Bytes, Provider, U256};
use ethers::providers::Middleware;
use ethers::utils::keccak256;
use ethers::utils::{__serde_json::json, hex};
use rand::{CryptoRng, Rng};
use scrypt::{scrypt, Params as ScryptParams};
use serde::Deserialize;
use sha3::{Digest, Keccak256};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use toml::Value;

// constant used in AES
const DEFAULT_KEY_SIZE: usize = 48usize;
const DEFAULT_IV_SIZE: usize = 16usize;
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 48u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 13u8;
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

type Aes256Ctr = ctr::Ctr64LE<aes::Aes256>;

// Meson erc4337 wallet
#[derive(Deserialize)]
pub struct Erc4337Wallet {
    pub key_store_path: PathBuf,
    pub meson_setting_path: PathBuf,
    pub supported_accounts_path: PathBuf,
    pub entrypoint: String,
}

pub const EXECUTE_SIGNATURE: &str = "b61d27f6";
const NODE_RPC_URL: &str = "http://localhost:8545"; //test only, should handle by meson
const BUNDLER_RPC_URL: &str = "http://localhost:4337"; //test only, should handle by meson

impl Erc4337Wallet {
    // create new meson erc4337wallet instance with given wallet config file path
    pub fn new<P: AsRef<Path>>(wallet_config_path: P) -> Result<Self, MesonWalletError> {
        let toml_str = fs::read_to_string(wallet_config_path)?;
        let smart_wallet: Erc4337Wallet = match toml::from_str(&toml_str) {
            Ok(w) => w,
            Err(e) => return Err(MesonWalletError::ConfigFileError(e.to_string())),
        };

        Ok(smart_wallet)
    }

    // create a erc4337 user operation and signed with the given account
    pub async fn fill_user_op<P: Account>(
        &self,
        account: &P,
        to: Address,
        amount: U256,
        chain_id: U256,
        password: &str,
        data: Option<Vec<u8>>,
    ) -> Result<(UserOperation, String), MesonWalletError> {
        let mut user_op = UserOperation::new();
        let deployed = self.deployed(account.address()).await;
        //only include initcode if not yet deployed
        user_op = if !deployed {
            let initcode = account.create_init_code(&self.supported_accounts_path, chain_id)?;
            user_op.init_code(initcode)
        } else {
            user_op
        };
        user_op = user_op.sender(account.address());

        //query nonce only if deployed
        user_op = user_op.nonce(0);
        if deployed {
            let nonce = self.query_nonce(account.address()).await;
            user_op = user_op.nonce(nonce);
        }

        //create calldata
        let func_signature = Bytes::from_str(EXECUTE_SIGNATURE).unwrap().to_vec();
        let param;
        match data {
            Some(n) => param = AbiEncode::encode((to, amount, Bytes::from(n))),
            None => param = AbiEncode::encode((to, amount, Bytes::default())),
        }
        let call_data = [func_signature, param].concat();
        user_op = user_op.call_data(call_data);
        user_op = user_op.verification_gas_limit(0xffffff);
        user_op = user_op.pre_verification_gas(0xffffff);
        user_op = user_op.max_fee_per_gas(0xffffff);

        //set signature to random data for querying gas
        user_op = user_op.signature(Bytes::from_str("0x43b8da28f2e270442c1618c6594a8b9c3cc44fd321d6135339be632af153e1fa5a00d1b1336d40091ae887b0b8d2a8a6f20b8d9818435196082f38cc46e0bad11b").unwrap());
        let gas_info = self.query_gas_info(account, &user_op).await;
        println!("{gas_info:?}");

        //shoud set the gas price from gas_info (current stackup version doesn't work)
        user_op = user_op
            .call_gas_imit(1500000)
            .verification_gas_limit(1500000)
            .pre_verification_gas(1500000)
            .max_fee_per_gas(100)
            .max_priority_fee_per_gas(100);

        //set signature to empty bytes for signing
        user_op = user_op.signature(Bytes::default());
        let sig = account.sign(&user_op, chain_id, password, &self.key_store_path)?;
        let user_op = user_op.signature(sig);
        let user_op_hash = hex::encode(keccak256(AbiEncode::encode((
            user_op.hash(),
            account.entry_point(),
            chain_id,
        ))));
        Ok((user_op, user_op_hash))
    }

    // create a tornado cash deposit user operation and save the tornado-note
    pub async fn fill_tornado_deposit_user_op<P: Account>(
        &self,
        eth_amount: &str,
        account: &P,
        chain_id: U256,
        password: &str,
        tornado_addr: Address,
    ) -> Result<(UserOperation, String), MesonWalletError> {
        let tor_deposit = Deposit::new();
        let (tx, note_string) = tor_deposit.gen_deposit_tx(None, eth_amount, chain_id.as_u64());
        println!("Note string: {}", note_string);
        self.save_tornado_notes(&note_string, account, chain_id, password)?;
        let amount = match ethers::utils::parse_ether(eth_amount) {
            Ok(a) => a,
            Err(_) => {
                return Err(MesonWalletError::MesonWalletError(
                    "invalid eth amount".into(),
                ))
            }
        };
        let (user_op, hash_str) = self
            .fill_user_op(account, tornado_addr, amount, chain_id, password, Some(tx))
            .await?;

        Ok((user_op, hash_str))
    }

    // create a tornado cash withdraw user operation with the given tornado-note
    pub async fn fill_tornado_withdraw_user_op<P: Account>(
        &self,
        tor_note: &str,
        recipient: Address,
        account: &P,
        chain_id: U256,
        password: &str,
        tornado_addr: Address,
    ) -> Result<(UserOperation, String), MesonWalletError> {
        let tx = Deposit::parse_and_withdraw(tor_note, recipient, None, None, None).await;
        let (user_op, hash_str) = self
            .fill_user_op(
                account,
                tornado_addr,
                0.into(),
                chain_id,
                password,
                Some(tx),
            )
            .await?;

        Ok((user_op, hash_str))
    }

    // encrypt & save a given tornado-note
    pub fn save_tornado_notes<P: Account>(
        &self,
        tor_note: &str,
        account: &P,
        chain_id: U256,
        password: &str,
    ) -> Result<(), MesonWalletError> {
        let addr = "0x".to_owned() + &hex::encode(account.address());
        let dir = self
            .key_store_path
            .join("tornado_note")
            .join(addr)
            .join(chain_id.to_string());
        fs::create_dir_all(&dir)?;

        let note_digest = match std::str::from_utf8(&tor_note.as_bytes()[0..30]) {
            Ok(n) => n,
            Err(_) => {
                return Err(MesonWalletError::MesonWalletError(
                    "invalid tornado note".into(),
                ))
            }
        };
        let dir = dir.join(note_digest);
        let mut rng = rand::thread_rng();
        let tor_note: Vec<u8> = tor_note.bytes().collect();
        Self::encrypt_key(dir, &mut rng, tor_note, password)?;

        Ok(())
    }

    // list the tornado note owned by an account
    pub fn tornado_note_lists<P: Account>(
        &self,
        account: &P,
        chain_id: U256,
    ) -> Result<Vec<String>, MesonWalletError> {
        let addr = "0x".to_owned() + &hex::encode(account.address());
        let dir = self
            .key_store_path
            .join("tornado_note")
            .join(addr)
            .join(chain_id.to_string());
        let files: Result<Vec<String>, MesonWalletError> = match dir.read_dir() {
            Ok(entry) => entry
                .into_iter()
                .map(|f| Ok(f?.file_name().to_str().unwrap().to_owned()))
                .collect(),

            Err(_) => return Ok(vec![]),
        };
        return files;
    }

    // decrypt & load an given tornado-node
    pub fn load_tornado_note<P: Account>(
        &self,
        account: &P,
        note_digest: &str,
        chain_id: U256,
        password: &str,
    ) -> Result<String, MesonWalletError> {
        let addr = "0x".to_owned() + &hex::encode(account.address());
        let dir = self
            .key_store_path
            .join("tornado_note")
            .join(addr)
            .join(chain_id.to_string())
            .join(note_digest);
        let d = Self::decrypt_key(dir, password)?;
        match String::from_utf8(d) {
            Ok(s) => Ok(s),
            Err(_) => {
                return Err(MesonWalletError::MesonWalletError(
                    "invalid tornado note".into(),
                ))
            }
        }
    }

    pub fn delete_tornado_note<P: Account>(
        &self,
        account: &P,
        chain_id: U256,
        note_digest: &str,
    ) -> Result<(), MesonWalletError> {
        let addr = "0x".to_owned() + &hex::encode(account.address());
        let path = self
            .key_store_path
            .join("tornado_note")
            .join(addr)
            .join(chain_id.to_string())
            .join(note_digest);
        fs::remove_file(path)?;
        Ok(())
    }

    // query erc4337 gas info
    // test only, should query through meson
    pub async fn query_gas_info<P: Account>(
        &self,
        account: &P,
        user_op: &UserOperation,
    ) -> GasQueryResult {
        let provider = Provider::try_from(BUNDLER_RPC_URL).unwrap();
        let query_result: GasQueryResult = provider
            .request(
                "eth_estimateUserOperationGas",
                json!([user_op, account.entry_point()]),
            )
            .await
            .unwrap();
        query_result
    }

    // query the nonce of an smart contract account
    // test only, should query through meson
    pub async fn query_nonce(&self, smart_account_addr: Address) -> U256 {
        let provider = Provider::try_from(NODE_RPC_URL).unwrap();
        let smart_account_addr = "0x".to_owned() + &hex::encode(smart_account_addr);
        let nonce: U256 = provider
            .request(
                "eth_call",
                json!([{
                    "to": smart_account_addr,
                    "data": "0xd087d288", // function signature of "getNonce()"
                },"latest"]),
            )
            .await
            .unwrap();

        nonce
    }

    pub async fn deployed(&self, smart_account_addr: Address) -> bool {
        let provider = Provider::try_from(NODE_RPC_URL).unwrap();
        let code = provider.get_code(smart_account_addr, None).await.unwrap();
        code != Bytes::default()
    }

    // send the user operation with an account
    // test only, should query through meson
    pub async fn send_user_op<P: Account>(
        &self,
        user_op: UserOperation,
        account: &mut P,
    ) -> String {
        let rpc_url = BUNDLER_RPC_URL;
        let provider = Provider::try_from(rpc_url).unwrap();
        let result: String = provider
            .request(
                "eth_sendUserOperation",
                json!([user_op, account.entry_point()]),
            )
            .await
            .unwrap();
        result
    }

    // return a list of supported smart contract types (defined in wallet config)
    pub fn supproted_acount_types(&self) -> Vec<String> {
        let toml_str = fs::read_to_string(&self.supported_accounts_path).unwrap();
        let value = &toml_str.parse::<Value>().unwrap();
        let supported = value["supported_list"].as_array().unwrap();
        let suppoeted: Vec<String> = supported
            .into_iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        suppoeted
    }

    // AES-256 encrypt account private key
    pub fn encrypt_key<P, R, S, T>(
        dir: P,
        rng: &mut R,
        mut sk: S,
        password: T,
    ) -> Result<(), MesonWalletError>
    where
        P: AsRef<Path>,
        R: Rng + CryptoRng,
        S: AsMut<[u8]>,
        T: AsRef<[u8]>,
    {
        // Generate a random salt.
        let mut salt = vec![0u8; DEFAULT_KEY_SIZE];
        rng.fill_bytes(salt.as_mut_slice());

        // Key Derivation with scrypt.
        let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
        let scrypt_params = ScryptParams::new(
            DEFAULT_KDF_PARAMS_LOG_N,
            DEFAULT_KDF_PARAMS_R,
            DEFAULT_KDF_PARAMS_P,
        )
        .unwrap();
        if let Err(_) = scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice()) {
            return Err(MesonWalletError::EncryptError);
        };

        // Encrypt the private key using AES-256-CTR.
        let mut iv = vec![0u8; DEFAULT_IV_SIZE];
        rng.fill_bytes(iv.as_mut_slice());
        let ciphertext: &mut [u8] = sk.as_mut();
        let mut encrypter = Aes256Ctr::new((&key[..32]).into(), (&iv[..16]).into());
        encrypter.apply_keystream(ciphertext);

        // Calculate the MAC.
        let mac = Keccak256::new()
            .chain_update(&key[32..48])
            .chain_update(&ciphertext)
            .finalize();
        let mac = Base64::encode_string(&mac);
        let salt = Base64::encode_string(&salt);
        let iv = Base64::encode_string(&iv);

        //store the encrypted cipher
        let enc = SkCipher {
            cipher: Base64::encode_string(&ciphertext),
            mac: mac,
            salt: salt,
            iv: iv,
        };
        let str_json = serde_json::to_string(&enc)?;
        fs::write::<PathBuf, String>(dir.as_ref().to_path_buf(), str_json)?;
        Ok(())
    }

    // AES-256 decrypt account private key
    pub fn decrypt_key<P, S>(dir: P, password: S) -> Result<Vec<u8>, MesonWalletError>
    where
        P: AsRef<Path>,
        S: AsRef<[u8]>,
    {
        let str_json = fs::read_to_string(dir.as_ref())?;
        let json_cipher: SkCipher = serde_json::from_str(&str_json)?;
        let mut cipher = Base64::decode_vec(&json_cipher.cipher)?;
        let mac_from_json = json_cipher.mac;
        let salt = Base64::decode_vec(&json_cipher.salt)?;
        let iv = Base64::decode_vec(&json_cipher.iv)?;

        //Derive the key
        let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
        let scrypt_params = ScryptParams::new(
            DEFAULT_KDF_PARAMS_LOG_N,
            DEFAULT_KDF_PARAMS_R,
            DEFAULT_KDF_PARAMS_P,
        )
        .unwrap();
        if let Err(_) = scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice()) {
            return Err(MesonWalletError::DecryptError);
        };

        //Derive and compare the mac
        let mac = Keccak256::new()
            .chain_update(&key[32..48])
            .chain_update(&cipher)
            .finalize();
        let mac = Base64::encode_string(&mac);

        //Decrypt the private key
        let mut decryptor = Aes256Ctr::new((&key[..32]).into(), (&iv[..16]).into());
        decryptor.apply_keystream(&mut cipher);
        // let sk = PrivateKey::from_bytes(&cipher);

        if mac != mac_from_json {
            return Err(MesonWalletError::DecryptError);
        };
        Ok(cipher)
    }
}

#[cfg(test)]
mod tests {
    use crate::tornado_util;

    use super::*;

    // #[tokio::test]
    // pub async fn test_query_gas() {
    //     let wallet_config_path = PathBuf::from("wallet_config.toml");
    //     let wallet = Erc4337Wallet::new(wallet_config_path);
    //     let owner = Address::from_str("1F0BDb0533b9aB79c891E65aC3ad3df4cd164B50").unwrap();
    //     let account = wallet.create_account(
    //         owner,
    //         Option::Some(
    //             "0xe78A0F7E598Cc8b0Bb87894B0F60dD2a88d6a8Ab"
    //                 .parse()
    //                 .unwrap(),
    //         ),
    //     );
    //     wallet
    //         .fill_user_op(
    //             &account,
    //             "0x0000000000000000000000000000000000000001"
    //                 .parse()
    //                 .unwrap(),
    //             U256::from_dec_str("10").unwrap(),
    //             5777.into(),
    //             None,
    //         )
    //         .await;
    // }

    #[tokio::test]
    pub async fn test_nonce() {
        let wallet_config_path = PathBuf::from("./configuration/wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path).unwrap();
        let nonce = wallet
            .query_nonce(
                "0xca45fe0684c78401e48c853fc911a93ef77a1b31"
                    .parse()
                    .unwrap(),
            )
            .await;
        println!("{}", nonce);
    }

    #[tokio::test]
    pub async fn test_check_deployed() {
        let wallet_config_path = PathBuf::from("./configuration/wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path).unwrap();
        let deployed = wallet
            .deployed(
                "0x3df21301e2b4d3da7ec3762f1cb6f8e8e3092230"
                    .parse()
                    .unwrap(),
            )
            .await;
        println!("{}", deployed);
    }

    use crate::bls::BLSAccount;
    #[tokio::test]
    pub async fn test_bls_send_op() {
        let wallet_config_path = PathBuf::from("./configuration/wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path).unwrap();
        let path = &wallet.key_store_path;
        let addr_str = "0x11a06b6ac30dc0fedfb7c7b8660f032c67c2a7f7";
        let mut bls_account = BLSAccount::load_account(&path, addr_str).unwrap();
        let (user_op, ophash) = wallet
            .fill_user_op(
                &bls_account,
                "0x0000000000000000000000000000000000013579"
                    .parse()
                    .unwrap(),
                111.into(),
                12345.into(),
                "123456789",
                None,
            )
            .await
            .unwrap();

        let result = wallet.send_user_op(user_op, &mut bls_account).await;
        println!("{}", result);
        println!("{}", ophash);
    }

    use crate::simple_account::SimpleAccount;
    #[tokio::test]
    pub async fn test_simple_send_op() {
        let wallet_config_path = PathBuf::from("./configuration/wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path).unwrap();
        let path = &wallet.key_store_path;
        let addr_str = "0xa9f91eba34bcedb773248c06f4ee99a5f69befd2";
        let mut account = SimpleAccount::load_account(&path, addr_str).unwrap();
        let (user_op, ophash) = wallet
            .fill_user_op(
                &account,
                "0x0000000000000000000000000000000000028825"
                    .parse()
                    .unwrap(),
                1.into(),
                12345.into(),
                "123456789",
                None,
            )
            .await
            .unwrap();

        let result = wallet.send_user_op(user_op, &mut account).await;
        println!("{}", result);
        println!("{}", ophash);
    }

    #[tokio::test]
    //test sending tornado cash deposit user_op
    //increase gas if failed
    //for some version of bundler, needs to disable gas query to endable tornado cash
    pub async fn test_g_tornado_deposit() {
        let wallet_config_path = PathBuf::from("./configuration/wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path).unwrap();
        let path = &wallet.key_store_path;
        let addr_str = "0x11a06b6ac30dc0fedfb7c7b8660f032c67c2a7f7";
        let mut account = BLSAccount::load_account(&path, addr_str).unwrap();
        let (user_op, _) = wallet
            .fill_tornado_deposit_user_op(
                "0.1",
                &account,
                12345.into(),
                "123456789",
                tornado_util::TORNADO_ADDRESS.parse().unwrap(),
            )
            .await
            .unwrap();
        let result = wallet.send_user_op(user_op, &mut account).await;
        println!("{}", result);
    }

    #[tokio::test]
    //test sending tornado cash withdraw user_op
    //increase gas if failed
    //for some version of bundler, needs to disable gas query to endable tornado cash
    pub async fn test_g_tornado_withdraw() {
        let wallet_config_path = PathBuf::from("./configuration/wallet_config.toml");
        let wallet = Erc4337Wallet::new(wallet_config_path).unwrap();
        let path = &wallet.key_store_path;
        let addr_str = "0x3df21301e2b4d3da7ec3762f1cb6f8e8e3092230";
        let mut account = BLSAccount::load_account(&path, addr_str).unwrap();
        let (user_op, _) = wallet
        .fill_tornado_withdraw_user_op(
            "tornado-eth-0.1-12345-0x989c9819812d7c4d54914bfe40760fe35cc173d3a628d215838ebc9938d72447809643ee7698bbd6408887000d26c10860fc3c42d8ee39e11d0385e01229",
             "0x1f0bdb0533b9ab79c891e65ac3ad3df4cd164b50".parse().unwrap(),
               &account,
               12345.into(),
               "123456789",
               tornado_util::TORNADO_ADDRESS.parse().unwrap(),
            )
            .await.unwrap();
        let result = wallet.send_user_op(user_op, &mut account).await;
        println!("{}", result);
    }
}
