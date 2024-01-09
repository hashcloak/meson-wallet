#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use crate::error::{MesonError, MesonWalletError, MnemonicError};
use crate::meson_util::meson_provider::MesonProvider;
use crate::{cli, meson_util::bindings};
use aes::cipher::{KeyIvInit, StreamCipher};
use base64ct::{Base64, Encoding};
use dialoguer::{console, Confirm, Input};
use ethers::abi::Address;
use ethers::prelude::{k256::ecdsa::SigningKey, *};
use ethers::signers::coins_bip39::{English, Mnemonic};
use ethers::signers::Wallet;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::utils::hex;
use futures::executor::block_on;
use rand::{CryptoRng, Rng};
use scrypt::{scrypt, Params as ScryptParams};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::error::Error;
use std::ffi::{c_void, CString};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

type Aes128Ctr = ctr::Ctr64LE<aes::Aes128>;

// const MESON_SERVICE: &str = "meson";
const DEFAULT_KEY_SIZE: usize = 32usize;
const DEFAULT_IV_SIZE: usize = 16usize;
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 13u8;
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

// meson eoa wallet
#[derive(serde::Deserialize)]
pub struct MesonWallet {
    key_store_path: PathBuf,
    meson_setting_path: PathBuf,
    chain: HashMap<String, chainInfo>,
}

#[derive(serde::Deserialize, Debug)]
pub struct chainInfo {
    pub ticker: String,
    //endpoint: String,
}

//struct for encrypting mnemonic
#[derive(serde::Serialize, serde::Deserialize)]
struct JsonMnemonic {
    mnemonic: String,
    mac: String,
    salt: String,
    iv: String,
}

pub struct Account {
    pub addr: String,
    pub path: PathBuf,
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl Account {
    pub fn new(addr: String, path: PathBuf) -> Self {
        Account { addr, path }
    }
}

//golang-like defer function using RAII
//https://stackoverflow.com/questions/29963449
struct ScopeCall<F: FnMut()> {
    c: F,
}
impl<F: FnMut()> Drop for ScopeCall<F> {
    fn drop(&mut self) {
        (self.c)();
    }
}

// macro_rules! defer {
//     ($e:expr) => {
//         let _scope_call = ScopeCall {
//             c: || -> () {
//                 $e;
//             },
//         };
//     };
// }

impl MesonWallet {
    pub fn new<P: AsRef<Path>>(wallet_config_path: P) -> Self {
        let toml_str = fs::read_to_string(wallet_config_path).unwrap();
        let meson_wallet: MesonWallet = toml::from_str(&toml_str).unwrap();

        meson_wallet
    }

    pub fn gen_mnemonic() -> Result<String, MnemonicError> {
        let mut rng = rand::thread_rng();
        let phrase = Mnemonic::<English>::new_with_count(&mut rng, 12)?;
        Ok(phrase.to_phrase()?)
    }

    pub fn save_mnemonic(&self, mnemonic: &str, password: &str) -> Result<(), MnemonicError> {
        let mut rng = rand::thread_rng();
        let ketstore_dir = self.key_store_path.join("keystore");
        let _ = fs::remove_dir_all(ketstore_dir);
        let dir = self.key_store_path.join("mnemonic");
        encrypt_mnemonic(dir.as_path(), &mut rng, mnemonic, password.as_bytes())?;
        Ok(())
    }

    pub fn show_mnemonic(&self, password: &str) -> Result<String, MnemonicError> {
        let dir = self.key_store_path.join("mnemonic");
        decrypt_mnemonic(dir, password)
    }

    //derive account from saved mnemonic
    pub fn derive_account(&self, password: &str) -> Result<String, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let dir = self.key_store_path.join("keystore");
        fs::create_dir_all(&dir)?;
        let mut index = 0;
        for _ in dir.read_dir()? {
            index += 1;
        }
        let mne_dir = self.key_store_path.join("mnemonic");
        match decrypt_mnemonic(mne_dir, password) {
            Ok(mnemonic) => {
                let eth_wallet = gen_keypair_from_mnemonic(&mnemonic, index)?;
                let addr = "0x".to_owned() + &hex::encode(eth_wallet.address());
                let secret = eth_wallet.signer().to_bytes();
                eth_keystore::encrypt_key(dir, &mut rng, secret, password, Some(addr.as_str()))?;
                return Ok(addr);
            }
            Err(error) => {
                return Err(Box::new(error));
            }
        }
    }

    pub async fn query_nonce(
        &self,
        addr: Address,
        block: Option<BlockId>,
        chain_id: u64,
    ) -> Result<U256, Box<dyn Error>> {
        let ticker = self.ticker(chain_id)?;
        let meson = MesonProvider::new(&self.meson_setting_path, ticker)?;
        let meson_provider = Provider::new(meson);
        let nonce = meson_provider.get_transaction_count(addr, block).await?;
        Ok(nonce)
    }

    // create a lagacy transaction and query for gas info
    pub async fn new_lagacy_transaction(
        &self,
        from: Address,
        to: Address,
        value: U256,
        chain_id: u64,
        nonce: Option<U256>,
    ) -> Result<TypedTransaction, Box<dyn Error>> {
        let ticker = self.ticker(chain_id)?;
        let meson = MesonProvider::new(&self.meson_setting_path, ticker)?;
        let meson_provider = Provider::new(meson);
        let tx_req = TransactionRequest::new()
            .from(from)
            .to(to)
            .value(value)
            .chain_id(chain_id);
        let mut tx = TypedTransaction::Legacy(tx_req);

        // query nonce
        match nonce {
            Some(n) => tx.set_nonce(n),
            None => {
                let nonce = meson_provider.get_transaction_count(from, None).await?;
                tx.set_nonce(nonce)
            }
        };
        println!("pass nonce");
        // query gas
        meson_provider.fill_transaction(&mut tx, None).await?;

        Ok(tx)
    }

    pub async fn new_eip1559_transaction(
        &self,
        from: Address,
        to: Address,
        value: U256,
        chain_id: u64,
        nonce: Option<U256>,
    ) -> Result<TypedTransaction, Box<dyn Error>> {
        let ticker = self.ticker(chain_id)?;
        let meson = MesonProvider::new(&self.meson_setting_path, ticker)?;
        let meson_provider = Provider::new(meson);
        let tx_req = Eip1559TransactionRequest::new()
            .from(from)
            .to(to)
            .value(value)
            .chain_id(chain_id);
        let mut tx = TypedTransaction::Eip1559(tx_req);

        // query nonce
        match nonce {
            Some(n) => tx.set_nonce(n),
            None => {
                let nonce = meson_provider.get_transaction_count(from, None).await?;
                tx.set_nonce(nonce)
            }
        };

        // query gas
        meson_provider.fill_transaction(&mut tx, None).await?;

        Ok(tx)
    }

    pub fn sign_transaction(
        password: &str,
        account: &Account,
        tx: &TypedTransaction,
    ) -> Result<Bytes, Box<dyn Error>> {
        let wallet = Wallet::decrypt_keystore(&account.path, password)?;
        let signature = block_on(wallet.sign_transaction(&tx))?;
        let raw_tx = tx.rlp_signed(&signature);
        Ok(raw_tx)
    }

    pub async fn send_transaction(
        &self,
        tx: Bytes,
        chain_id: u64,
    ) -> Result<String, Box<dyn Error>> {
        let ticker = self.ticker(chain_id)?;
        let meson = MesonProvider::new(&self.meson_setting_path, ticker)?;
        let meson_provider = Provider::new(meson);
        let tx_hash = meson_provider.send_raw_transaction(tx).await?;
        let tx_hash = "0x".to_string() + &hex::encode(tx_hash.as_bytes());
        Ok(tx_hash.to_string())
    }

    //show all saved accounts
    pub fn saved_accounts(&self) -> Result<Vec<Account>, Box<dyn Error>> {
        let derived_dir = self.key_store_path.join("keystore");
        let import_dir = self.key_store_path.join("imported_keystore");
        let mut accounts = Vec::new();
        let mut files = Vec::new();
        match derived_dir.read_dir() {
            Ok(entry) => files = entry.collect::<Vec<_>>(),
            Err(_) => fs::create_dir_all(&derived_dir)?,
        }
        match import_dir.read_dir() {
            Ok(entry) => files.extend(entry),
            Err(_) => fs::create_dir_all(&import_dir)?,
        }
        for file in files {
            match file {
                Ok(account) => {
                    if let Some(name) = account.file_name().to_str() {
                        let saved = Account::new(name.to_string(), account.path());
                        accounts.push(saved);
                    } else {
                        return Err("file error".into());
                    }
                }
                Err(error) => return Err(Box::new(error)),
            }
        }
        Ok(accounts)
    }

    //show all imported accounts
    pub fn imported_accounts(&self) -> Result<Vec<Account>, Box<dyn Error>> {
        let import_dir = self.key_store_path.join("imported_keystore");
        let mut accounts = Vec::new();
        let mut files = Vec::new();
        match import_dir.read_dir() {
            Ok(entry) => files = entry.collect::<Vec<_>>(),
            Err(_) => fs::create_dir_all(&import_dir)?,
        }
        for file in files {
            match file {
                Ok(account) => {
                    if let Some(name) = account.file_name().to_str() {
                        let saved = Account::new(name.to_string(), account.path());
                        accounts.push(saved);
                    } else {
                        return Err("file error".into());
                    }
                }
                Err(error) => return Err(Box::new(error)),
            }
        }
        Ok(accounts)
    }

    // import and save an account
    pub fn import_account(&self, sk: &str, password: &str) -> Result<String, Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let import_dir = self.key_store_path.join("imported_keystore");
        fs::create_dir_all(&import_dir)?;
        let eth_wallet: Wallet<SigningKey> = sk.parse()?;
        let addr = "0x".to_owned() + &hex::encode(eth_wallet.address());
        let secret = eth_wallet.signer().to_bytes();
        eth_keystore::encrypt_key(import_dir, &mut rng, secret, password, Some(addr.as_str()))?;
        Ok(addr)
    }

    // import and save an mnemonic
    pub fn import_mnemonic(&self, phrase: &str, password: &str) -> Result<(), Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let dir = self.key_store_path.join("mnemonic");
        let _ = Mnemonic::<English>::new_from_phrase(phrase)?;
        let ketstore_dir = self.key_store_path.join("keystore");
        let _ = fs::remove_dir_all(ketstore_dir);
        encrypt_mnemonic(dir.as_path(), &mut rng, &phrase, password.as_bytes())?;
        Ok(())
    }

    pub fn ticker(&self, chain_id: u64) -> Result<&str, MesonError> {
        match self.chain.get(&chain_id.to_string()) {
            Some(info) => return Ok(&info.ticker),
            None => return Err(MesonError::MesonError("Unsupport chain id".into())),
        }
    }

    pub fn delete_account(&self, account: &Account) -> Result<(), Box<dyn Error>> {
        fs::remove_file(&account.path)?;
        Ok(())
    }
}

//Derive keys from given mnemonic and index
fn gen_keypair_from_mnemonic(phrase: &str, index: u32) -> Result<Wallet<SigningKey>, WalletError> {
    let keypair = MnemonicBuilder::<English>::default()
        .phrase(phrase)
        .index(index)?
        .build()?;
    Ok(keypair)
}

//encrypt a mnemonic String with password
fn encrypt_mnemonic<P, R, S>(
    dir: P,
    rng: &mut R,
    mnemonic: &str,
    password: S,
) -> Result<(), MnemonicError>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    S: AsRef<[u8]>,
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
        DEFAULT_KEY_SIZE as usize,
    )?;
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

    // Encrypt the private key using AES-128-CTR.
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];
    rng.fill_bytes(iv.as_mut_slice());
    let mut ciphertext: Vec<u8> = mnemonic.bytes().collect();
    let mut encrypter = Aes128Ctr::new((&key[..16]).into(), (&iv[..16]).into());
    encrypter.apply_keystream(ciphertext.as_mut_slice());

    // Calculate the MAC.
    let mac = Keccak256::new()
        .chain_update(&key[16..32])
        .chain_update(&ciphertext)
        .finalize();
    let mac = Base64::encode_string(&mac);
    let salt = Base64::encode_string(&salt);
    let iv = Base64::encode_string(&iv);

    //store the encrypted mnemonic
    let enc_mac = JsonMnemonic {
        mnemonic: Base64::encode_string(&ciphertext),
        mac: mac,
        salt: salt,
        iv: iv,
    };
    let str_json = serde_json::to_string(&enc_mac)?;
    fs::create_dir_all(&dir).unwrap();
    fs::write::<PathBuf, String>(dir.as_ref().join("mnemonic"), str_json)
        .expect("Unable to write file");

    // println!("cipher {:?}, mac {:?}", ciphertext, mac);
    Ok(())
}

//decrypt a mnemonic String with password
fn decrypt_mnemonic<P, S>(dir: P, password: S) -> Result<String, MnemonicError>
where
    P: AsRef<Path>,
    S: AsRef<[u8]>,
{
    let str_json = fs::read_to_string(dir.as_ref().join("mnemonic"))?;
    let json_mnemonic: JsonMnemonic = serde_json::from_str(&str_json)?;
    let mut cipher_mnemonic = Base64::decode_vec(&json_mnemonic.mnemonic)?;
    let mac_from_json = json_mnemonic.mac;
    let salt = Base64::decode_vec(&json_mnemonic.salt)?;
    let iv = Base64::decode_vec(&json_mnemonic.iv)?;

    //Derive the key
    let mut key = vec![0u8; DEFAULT_KDF_PARAMS_DKLEN as usize];
    let scrypt_params = ScryptParams::new(
        DEFAULT_KDF_PARAMS_LOG_N,
        DEFAULT_KDF_PARAMS_R,
        DEFAULT_KDF_PARAMS_P,
        DEFAULT_KEY_SIZE as usize,
    )?;
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

    //Derive and compare the mac
    let mac = Keccak256::new()
        .chain_update(&key[16..32])
        .chain_update(&cipher_mnemonic)
        .finalize();
    let mac = Base64::encode_string(&mac);
    if mac != mac_from_json {
        return Err(MnemonicError::MacMismatch);
    };

    //Decrypt the mnemonic
    let mut decryptor = Aes128Ctr::new((&key[..16]).into(), (&iv[..16]).into());
    decryptor.apply_keystream(&mut cipher_mnemonic);
    let mnemonic = std::str::from_utf8(&cipher_mnemonic)?.to_owned();

    Ok(mnemonic)
}

fn _ping() {
    let configFile =
        CString::new("./configuration/client.example.toml").expect("CString::new failed");
    unsafe {
        println!("Register");
        bindings::Register(configFile.into_raw());
        println!("NewClient");
        bindings::NewClient(
            CString::new("echo")
                .expect("CString::new failed")
                .into_raw(),
        );
        println!("NewSession");
        bindings::NewSession();
        println!("GetService");
        bindings::GetService(
            CString::new("echo")
                .expect("CString::new failed")
                .into_raw(),
        );
        let hello = String::from("hello");
        println!("Sending: \"{}\"", hello);
        let chello = CString::new(hello).unwrap();
        let chello = chello.as_bytes_with_nul().as_ptr() as *mut c_void;
        let meson_return = bindings::BlockingSendUnreliableMessage(chello, 5);
        let slice_return = &*std::ptr::slice_from_raw_parts_mut(
            meson_return.r0 as *mut u8,
            meson_return.r1.try_into().unwrap(),
        );

        //todo: a better way to parse the packet
        let packet_len: usize = slice_return[3].try_into().unwrap();
        let packet_start: usize = 4;
        let packet = &(slice_return[packet_start..packet_start + packet_len]);
        let message = std::str::from_utf8(packet).unwrap();
        println!("Got: {}", message);
        bindings::Shutdown();
    }
}
fn _ping_unblock() {
    let configFile =
        CString::new("./configuration/client.example.toml").expect("CString::new failed");
    unsafe {
        println!("Register");
        bindings::Register(configFile.into_raw());
        println!("NewClient");
        bindings::NewClient(
            CString::new("echo")
                .expect("CString::new failed")
                .into_raw(),
        );
        println!("NewSession");
        bindings::NewSession();
        println!("GetService");
        bindings::GetService(
            CString::new("echo")
                .expect("CString::new failed")
                .into_raw(),
        );
        let hello = String::from("hello");
        println!("Sending: \"{}\"", hello);
        let chello = CString::new(hello).unwrap();
        let chello = chello.as_bytes_with_nul().as_ptr() as *mut c_void;
        let meson_return = bindings::SendUnreliableMessage(chello, 5);
        let slice_return = &*std::ptr::slice_from_raw_parts_mut(
            meson_return.r0 as *mut u8,
            meson_return.r1.try_into().unwrap(),
        );

        println!("MsgID:{:?}", ethers::utils::hex::encode(slice_return));
        bindings::Shutdown();
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use crate::meson_util::meson_provider::MesonProvider;
    use serde_json::json;
    use std::str::FromStr;
    use tempdir::TempDir;
    #[test]
    fn mnemonic_build() {
        let phrase = "code black hollow banana kite betray rebuild collect fortune clean plug provide setup catch panic steel message code sudden example mechanic you donor diagram";
        let index = 0u32;
        let wallet = gen_keypair_from_mnemonic(phrase, index).unwrap();
        let wallet2: Wallet<SigningKey> =
            "2cd0fc69151afffe19e66db7e31ec34f1fbf10552983711faccba030025fc706"
                .parse()
                .unwrap();
        assert_eq!(wallet, wallet2);
    }

    #[test]
    fn test_enc_dec_mnemonic() {
        let tmp_dir = TempDir::new("mne_test").unwrap();
        let mnemonic1 =
            "planet taxi snap future much climb wild fat clip assault ring torch".to_owned();
        encrypt_mnemonic(
            tmp_dir.path(),
            &mut rand::thread_rng(),
            &mnemonic1,
            "15wefgsze",
        )
        .unwrap();

        let mnemonic2 = decrypt_mnemonic(tmp_dir.path(), "15wefgsze").unwrap();
        assert_eq!(mnemonic1, mnemonic2);
    }

    #[test]
    #[should_panic(expected = "MacMismatch")]
    fn test_failed_dec_mnemonic() {
        let tmp_dir = TempDir::new("mne_test").unwrap();
        let mnemonic1 =
            "planet taxi snap future much climb wild fat clip assault ring torch".to_owned();
        encrypt_mnemonic(
            tmp_dir.path(),
            &mut rand::thread_rng(),
            &mnemonic1,
            "15wefgsze",
        )
        .unwrap();

        decrypt_mnemonic(tmp_dir.path(), "eroi43n2").unwrap();
    }

    #[test]
    fn test_enc_dec_key() {
        let tmp_dir = TempDir::new("key_test").unwrap();
        let sk = ethers::utils::hex::decode(
            "2cd0fc69151afffe19e66db7e31ec34f1fbf10552983711faccba030025fc706",
        )
        .unwrap();
        let _id = eth_keystore::encrypt_key(
            tmp_dir.path(),
            &mut rand::thread_rng(),
            sk,
            "llkasd",
            Some("00001"),
        )
        .unwrap();

        let wallet = Wallet::decrypt_keystore(tmp_dir.path().join("00001"), "llkasd").unwrap();
        let wallet2: Wallet<SigningKey> =
            "2cd0fc69151afffe19e66db7e31ec34f1fbf10552983711faccba030025fc706"
                .parse()
                .unwrap();

        assert_eq!(wallet, wallet2);
    }

    #[tokio::test]
    async fn test_meson_provider() {
        let p = PathBuf::from_str("./configuration/client.example.toml").unwrap();
        let meson = MesonProvider::new(&p, "gor").unwrap();
        let meson_provider = Provider::new(meson);
        let nonce: U256 = meson_provider
            .request(
                "eth_getTransactionCount",
                json!(["0x9A0b9c80dBd6323876bA706e892d27E47cd55FA5", "pending"]),
            )
            .await
            .unwrap();
        println!("nonce:{:?}", nonce);
    }

    // #[tokio::test]
    // pub fn query_nonce_test() {
    //     let toml_str = fs::read_to_string(wallet_config_path).unwrap();
    //     let wallet_config: WalletConfig = toml::from_str(&toml_str).unwrap();
    //     let meson_setting_path = wallet_config.meson_setting_path.clone();
    //     let meson = Arc::new(MesonProvider::new(&meson_setting_path, "null").unwrap());
    //     let wallet = MesonWallet::new(wallet_config, Arc::clone(&meson));
    // }
}
