#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use crate::{cli, meson_common};
use aes::cipher::{KeyIvInit, StreamCipher};
use base64ct::{Base64, Encoding};
use dialoguer::{console, Confirm, Input};
use ethers::abi::Address;
use ethers::prelude::{k256::ecdsa::SigningKey, *};
use ethers::signers::coins_bip39::{English, Mnemonic};
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
use std::str::FromStr;
// pub mod cli;
// pub mod error;
// mod meson_common;
use crate::error::{MesonError, MesonWalletError, MnemonicError};
include!("../bindings.rs");

type Aes128Ctr = ctr::Ctr64LE<aes::Aes128>;

const meson_service: &str = "meson";
const DEFAULT_KEY_SIZE: usize = 32usize;
const DEFAULT_IV_SIZE: usize = 16usize;
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 13u8;
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

#[derive(serde::Deserialize)]
pub struct MesonWallet {
    key_store_path: PathBuf,
    meson_setting_path: PathBuf,
    Chain: HashMap<String, ChainInfo>,
}

#[derive(serde::Deserialize)]
struct ChainInfo {
    Ticker: String,
    Endpoint: String,
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
    addr: String,
    path: PathBuf,
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

macro_rules! defer {
    ($e:expr) => {
        let _scope_call = ScopeCall {
            c: || -> () {
                $e;
            },
        };
    };
}

impl MesonWallet {
    pub fn new<P: AsRef<Path>>(wallet_config_path: P) -> Self {
        let toml_str = fs::read_to_string(wallet_config_path).unwrap();
        let meson_wallet: MesonWallet = toml::from_str(&toml_str).unwrap();

        meson_wallet
    }

    //create random mnemonic
    pub fn new_mnemonic(&self) -> Result<(), Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let phrase = Mnemonic::<English>::new_with_count(&mut rng, 24)?;
        let term = console::Term::stderr();
        term.write_line(&phrase.to_phrase().unwrap())?;
        if Confirm::new()
            .with_prompt("All non-imported accounts will be cleared, continue?")
            .interact_on(&term)?
        {
            let _ = term.clear_last_lines(2);
        } else {
            let _ = term.clear_last_lines(2);
            return Err(Box::new(MesonError::MesonError("".into())));
        }
        let ketstore_dir = self.key_store_path.join("keystore");
        let _ = fs::remove_dir_all(ketstore_dir);
        let password = cli::prompt_password_confirm()?;
        println!("Saving mnemonic...");
        let dir = self.key_store_path.join("mnemonic");
        encrypt_mnemonic(
            dir.as_path(),
            &mut rng,
            phrase.to_phrase().unwrap(),
            password.as_bytes(),
        )?;
        Ok(())
    }

    pub fn show_mnemonic(&self) -> Result<(), Box<dyn Error>> {
        let password = cli::prompt_password()?;
        let term = console::Term::stderr();
        let dir = self.key_store_path.join("mnemonic");
        term.write_line("Decrypting mnemonic...")?;
        match decrypt_mnemonic(dir, password) {
            Ok(mnemonic) => {
                let _ = term.clear_last_lines(1);
                term.write_line(&mnemonic)?;
                Input::<String>::new()
                    .allow_empty(true)
                    .with_prompt("Press enter to continue")
                    .interact_on(&term)?;
            }
            Err(error) => {
                let _ = term.clear_last_lines(1);
                return Err(Box::new(error));
            }
        }
        let _ = term.clear_last_lines(2);
        Ok(())
    }

    //derive account from saved mnemonic
    pub fn derive_account(&self) -> Result<(), Box<dyn Error>> {
        let term = console::Term::stderr();
        let mut rng = rand::thread_rng();
        let dir = self.key_store_path.join("keystore");
        fs::create_dir_all(&dir)?;
        let mut index = 0;
        for _ in dir.read_dir()? {
            index += 1;
        }
        let mne_dir = self.key_store_path.join("mnemonic");
        let password = cli::prompt_password()?;
        term.write_line("Generating new account...")?;
        match decrypt_mnemonic(mne_dir, password.as_str()) {
            Ok(mnemonic) => {
                let eth_wallet = gen_keypair_from_mnemonic(&mnemonic, index)?;
                let addr = "0x".to_owned() + &hex::encode(eth_wallet.address());
                let secret = eth_wallet.signer().to_bytes();
                eth_keystore::encrypt_key(dir, &mut rng, secret, password, Some(addr.as_str()))?;
                let _ = term.clear_last_lines(1);
                println!("Account {} created!", addr)
            }
            Err(error) => {
                return Err(Box::new(error));
            }
        }

        Ok(())
    }

    pub fn send_transaction(&self) -> Result<String, Box<dyn Error>> {
        let accounts = self.saved_accounts()?;
        if accounts.len() == 0 {
            return Err("Empty account list".into());
        }
        let selected_account = cli::select_account(&accounts)?;
        let from_addr = Address::from_str(&selected_account.addr)?;
        let term = console::Term::stderr();
        let to_addr = Input::<String>::new()
            .with_prompt("Send to")
            .interact_on(&term)?;
        let to_addr = Address::from_str(&to_addr)?;
        let value = Input::<String>::new()
            .with_prompt("Value in Wei")
            .interact_on(&term)?;
        let value = U256::from_dec_str(&value)?;
        let chain_id = Input::<U64>::new()
            .with_prompt("Chain ID")
            .interact_on(&term)?;

        meson_register(
            self.meson_setting_path
                .to_str()
                .ok_or(MesonWalletError::MesonWalletError("error".to_string()))?,
        );
        defer!(meson_close_conn());

        println!("Querying gas info through meson...");
        let tx = self.fill_tx(from_addr, to_addr, value, chain_id, "".to_string())?; //query gas info from meson
        let _ = term.clear_last_lines(1);
        cli::confirm_tx(&tx)?;
        let password = cli::prompt_password()?;
        let wallet = Wallet::decrypt_keystore(&selected_account.path, password)?;

        //sign transaction
        let signature = block_on(wallet.sign_transaction(&tx))?;
        let rlp_tx = tx.rlp_signed(&signature);

        println!("Sending transaction through meson...");
        let ticker = self.ticker(chain_id)?;
        let tx_hash = process_transaction(rlp_tx, ticker)?;
        let _ = term.clear_last_lines(1);
        println!("Tx hash: {}", tx_hash);

        Ok(tx_hash)
    }

    //fill tx with gas info
    pub fn fill_tx(
        &self,
        from: Address,
        to: Address,
        value: U256,
        chain_id: U64,
        data: String,
    ) -> Result<TypedTransaction, MesonError> {
        let ticker = self.ticker(chain_id)?;
        let query_return = meson_eth_query(from, to, value, ticker, data)?;
        let gas_info: meson_common::EthQueryResponse = serde_json::from_str(&query_return).unwrap();

        let mut gas = gas_info.GasLimit.strip_prefix("0x").unwrap().to_string();
        if gas.len() % 2 != 0 {
            gas = "0".to_string() + &gas;
        }
        let gas = U256::from_big_endian(&hex::decode(gas).unwrap()[..]);
        let mut gas_price = gas_info.GasPrice.strip_prefix("0x").unwrap().to_string();
        if gas_price.len() % 2 != 0 {
            gas_price = "0".to_string() + &gas_price;
        }
        let gas_price = U256::from_big_endian(&hex::decode(gas_price).unwrap()[..]);
        let mut nonce = gas_info.Nonce.strip_prefix("0x").unwrap().to_string();
        if nonce.len() % 2 != 0 {
            nonce = "0".to_string() + &nonce;
        }
        let nonce = U256::from_big_endian(&hex::decode(nonce).unwrap()[..]);
        let pay_tx = TransactionRequest::new()
            .from(from)
            .to(to)
            .value(value)
            .chain_id(chain_id)
            .gas(gas)
            .gas_price(gas_price)
            .nonce(nonce)
            .into();

        Ok(pay_tx)
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

    //import and save an account
    pub fn import_account(&self) -> Result<(), Box<dyn Error>> {
        let term = console::Term::stderr();
        let mut rng = rand::thread_rng();
        let import_dir = self.key_store_path.join("imported_keystore");
        fs::create_dir_all(&import_dir)?;
        let secret = Input::<String>::new()
            .with_prompt("Secret Key")
            .interact_on(&term)?;
        let _ = term.clear_last_lines(1);
        let password = cli::prompt_password()?;
        let eth_wallet: Wallet<SigningKey> = secret.parse()?;
        let addr = "0x".to_owned() + &hex::encode(eth_wallet.address());
        let secret = eth_wallet.signer().to_bytes();
        eth_keystore::encrypt_key(import_dir, &mut rng, secret, password, Some(addr.as_str()))?;
        println!("Address {} imported!", addr);
        Ok(())
    }

    //import and save an mnemonic
    pub fn import_mnemonic(&self) -> Result<(), Box<dyn Error>> {
        let term = console::Term::stderr();
        let mut rng = rand::thread_rng();
        let dir = self.key_store_path.join("mnemonic");
        let phrase = Input::<String>::new()
            .with_prompt("Mnemonic")
            .interact_on(&term)?;
        let _ = Mnemonic::<English>::new_from_phrase(&phrase)?;
        let _ = term.clear_last_lines(3);
        if !Confirm::new()
            .with_prompt("All non-imported accounts will be cleared, continue?")
            .interact_on(&term)?
        {
            return Err("Cancel".into());
        }
        let password = cli::prompt_password()?;
        let ketstore_dir = self.key_store_path.join("keystore");
        let _ = fs::remove_dir_all(ketstore_dir);
        encrypt_mnemonic(dir.as_path(), &mut rng, phrase, password.as_bytes())?;
        println!("Mnemonic imported!");
        Ok(())
    }

    pub fn ticker(&self, chain_id: U64) -> Result<&str, MesonError> {
        match self.Chain.get(&chain_id.to_string()) {
            Some(info) => return Ok(&info.Ticker),
            None => return Err(MesonError::MesonError("Unsupport chain id".into())),
        }
    }

    pub fn delete_imported_account(&self) -> Result<(), Box<dyn Error>> {
        let import_dir = self.key_store_path.join("imported_keystore");
        let mut accounts = Vec::new();
        let mut files = Vec::new();
        match import_dir.read_dir() {
            Ok(entry) => files = entry.collect::<Vec<_>>(),
            Err(_) => return Err("Empty account list".into()),
        }
        for file in files {
            match file {
                Ok(account) => {
                    if let Some(name) = account.file_name().to_str() {
                        let saved = Account::new(name.to_string(), account.path());
                        accounts.push(saved);
                    } else {
                        return Err(Box::new(MesonWalletError::MesonWalletError("".into())));
                    }
                }
                Err(error) => return Err(Box::new(error)),
            }
        }
        if accounts.len() == 0 {
            return Err("Empty account list".into());
        }
        let selected_account = cli::select_account(&accounts)?;
        let prompt = "Delete account ".to_string() + &selected_account.addr + "?";
        if Confirm::new().with_prompt(prompt).interact()? {
            fs::remove_file(&selected_account.path)?;
            println!("Account deleted");
        } else {
            return Err("".into());
        }

        Ok(())
    }
}

//register on meson through ffi
pub fn meson_register(path: &str) {
    let configFile = CString::new(path).expect("CString::new failed");
    unsafe {
        Register(configFile.into_raw());
        NewClient(
            CString::new(meson_service)
                .expect("CString::new failed")
                .into_raw(),
        );
        NewSession();
        GetService(
            CString::new(meson_service)
                .expect("CString::new failed")
                .into_raw(),
        );
    }
}

//send a meson request
fn meson_send(mut req: Vec<u8>) -> Result<String, MesonError> {
    unsafe {
        let meson_raw_return = BlockingSendUnreliableMessage(
            req.as_mut_ptr() as *mut c_void,
            req.len().try_into().expect("len error"),
        );
        let meson_return = &*std::ptr::slice_from_raw_parts_mut(
            meson_raw_return.r0 as *mut u8,
            meson_raw_return.r1.try_into().expect("len error"),
        );

        let mut meson_return: Vec<u8> = meson_return
            .to_vec()
            .into_iter()
            .rev()
            .skip_while(|&x| x == 0)
            .collect();
        meson_return.reverse(); // clear the tailing zeros
        let meson_response = meson_common::MesonCurrencyResponse::from_json(&meson_return[..]);

        let error = meson_response.Error;
        let response = meson_response.Message;
        if error != "" {
            return Err(MesonError::MesonError(error));
        }
        Ok(response)
    }
}

//qeury gas info from meson
pub fn meson_eth_query(
    from: Address,
    to: Address,
    value: U256,
    ticker: &str,
    data: String,
) -> Result<String, MesonError> {
    let json_value = serde_json::Number::from_string_unchecked(value.to_string()); //for serialize big_number
    let query = meson_common::EthQueryRequest {
        From: from,
        To: to,
        Value: json_value,
        Data: data,
    };
    let query = query.to_json();
    // println!("query: {:?}", std::str::from_utf8(&query[..]));
    let query = base64ct::Base64::encode_string(&query[..]);
    //todo: check if really needs to use base64 query
    let req = meson_common::MesonCurrencyRequest {
        Version: 0,
        Command: meson_common::EthQuery,
        Ticker: ticker.to_owned(),
        Payload: query,
    };
    let resp = meson_send(req.to_json())?;

    Ok(resp)
}

pub fn meson_close_conn() {
    unsafe {
        Shutdown();
    }
}

//encode raw tx to meson request
pub fn process_transaction(tx_bytes: Bytes, ticker: &str) -> Result<String, MesonError> {
    let meson_tx = meson_common::PostTransactionRequest {
        TxHex: tx_bytes.to_string(),
    }
    .to_json();
    let meson_tx = base64ct::Base64::encode_string(&meson_tx[..]);
    let req = meson_common::MesonCurrencyRequest {
        Version: 0,
        Command: meson_common::PostTransaction,
        Ticker: ticker.to_owned(),
        Payload: meson_tx,
    };
    let resp = meson_send(req.to_json())?;

    Ok(resp)
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
    mnemonic: String,
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
    )?;
    scrypt(password.as_ref(), &salt, &scrypt_params, key.as_mut_slice())?;

    // Encrypt the private key using AES-128-CTR.
    let mut iv = vec![0u8; DEFAULT_IV_SIZE];
    rng.fill_bytes(iv.as_mut_slice());
    let mut ciphertext = mnemonic.into_bytes();
    let mut encrypter = Aes128Ctr::new((&key[..16]).into(), (&iv[..16]).into());
    encrypter.apply_keystream(&mut ciphertext);

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

pub fn ping() {
    let configFile = CString::new(
        "/Users/liaoyuchen/Developer/hashcloak/meson/meson-wallet/meson-wallet/client.example.toml",
    )
    .expect("CString::new failed");
    unsafe {
        println!("Register");
        Register(configFile.into_raw());
        println!("NewClient");
        NewClient(
            CString::new("echo")
                .expect("CString::new failed")
                .into_raw(),
        );
        println!("NewSession");
        NewSession();
        println!("GetService");
        GetService(
            CString::new("echo")
                .expect("CString::new failed")
                .into_raw(),
        );
        let hello = String::from("hello");
        println!("Sending: \"{}\"", hello);
        let chello = CString::new(hello).unwrap();
        let chello = chello.as_bytes_with_nul().as_ptr() as *mut c_void;
        let meson_return = BlockingSendUnreliableMessage(chello, 5);
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
        Shutdown();

        //todo: where to free the memory?
        // let c_str = unsafe { CStr::from_ptr(meson_return) };
        // let str_slice = c_str.to_str().unwrap();
    }
}
pub fn ping_unblock() {
    let configFile = CString::new(
        "/Users/liaoyuchen/Developer/hashcloak/meson/meson-wallet/meson-wallet/client.example.toml",
    )
    .expect("CString::new failed");
    unsafe {
        println!("Register");
        Register(configFile.into_raw());
        println!("NewClient");
        NewClient(
            CString::new("echo")
                .expect("CString::new failed")
                .into_raw(),
        );
        println!("NewSession");
        NewSession();
        println!("GetService");
        GetService(
            CString::new("echo")
                .expect("CString::new failed")
                .into_raw(),
        );
        let hello = String::from("hello");
        println!("Sending: \"{}\"", hello);
        let chello = CString::new(hello).unwrap();
        let chello = chello.as_bytes_with_nul().as_ptr() as *mut c_void;
        let meson_return = SendUnreliableMessage(chello, 5);
        let slice_return = &*std::ptr::slice_from_raw_parts_mut(
            meson_return.r0 as *mut u8,
            meson_return.r1.try_into().unwrap(),
        );

        println!("MsgID:{:?}", ethers::utils::hex::encode(slice_return));
        Shutdown();
    }
}

#[cfg(test)]

mod tests {
    use super::*;
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
            mnemonic1.clone(),
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
            mnemonic1.clone(),
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
        let id = eth_keystore::encrypt_key(
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
}
