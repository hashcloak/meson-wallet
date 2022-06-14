#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use base64ct::{Base64, Encoding};
use ethers::prelude::{k256::ecdsa::SigningKey, *};
use ethers::signers::coins_bip39::{English, Mnemonic};
use ethers::utils::hex;
use futures::executor::block_on;
use rand::{CryptoRng, Rng};
use scrypt::{scrypt, Params as ScryptParams};
use sha3::{Digest, Keccak256};
use std::error::Error;
use std::ffi::CStr;
use std::ffi::{c_void, CString};
use std::fs;
use std::path::{Path, PathBuf};
use tempdir::TempDir;

mod error;
mod meson_common;
use error::{MesonError, MnemonicError};
include!("../bindings.rs");

type Aes128Ctr = ctr::Ctr64LE<aes::Aes128>;

const DEFAULT_KEY_SIZE: usize = 32usize;
const DEFAULT_IV_SIZE: usize = 16usize;
const DEFAULT_KDF_PARAMS_DKLEN: u8 = 32u8;
const DEFAULT_KDF_PARAMS_LOG_N: u8 = 13u8;
const DEFAULT_KDF_PARAMS_R: u32 = 8u32;
const DEFAULT_KDF_PARAMS_P: u32 = 1u32;

//todo: what should be in the meson wallet
struct MesonWallet {
    config: meson_config,
    path: Path,
}

//struct for encrypting mnemonic
#[derive(serde::Serialize, serde::Deserialize)]
struct JsonMnemonic {
    mnemonic: String,
    mac: String,
    salt: String,
    iv: String,
}

//todo: setup meson config
struct meson_config {}

const meson_service: &str = "meson";

//create a signed tx
async fn create_signed_tx(
    wallet: &Wallet<SigningKey>,
    to: Address,
    value: U256,
    gas: U256,
    gas_price: U256,
    nonce: U256,
    chain_id: U64,
) -> Result<Bytes, WalletError> {
    let pay_tx = TransactionRequest::new()
        .to(to)
        .value(value)
        .chain_id(chain_id)
        .gas(gas)
        .gas_price(gas_price)
        .nonce(nonce)
        .into();
    let signature = wallet.sign_transaction(&pay_tx).await?;
    let rlp_tx = pay_tx.rlp_signed(&signature);
    Ok(rlp_tx)
}

fn meson_regist_and_send(mut req: Vec<u8>) -> Result<String, error::MesonError> {
    let configFile = CString::new(
        "/Users/liaoyuchen/Developer/hashcloak/meson/meson-wallet/meson-wallet/client.example.toml",
    )
    .expect("CString::new failed");
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
            return Err(error::MesonError::MesonError(error));
        }
        //Shutdown();
        Ok(response)
    }
}

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

fn meson_send(mut req: Vec<u8>) -> Result<String, error::MesonError> {
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
            return Err(error::MesonError::MesonError(error));
        }
        Ok(response)
    }
}

pub fn meson_eth_query(
    from: Address,
    to: Address,
    value: U256,
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
    let query = base64ct::Base64::encode_string(&query[..]);
    //todo: check if really needs to use base64 query
    let req = meson_common::MesonCurrencyRequest {
        Version: 0,
        Command: meson_common::EthQuery,
        Ticker: "gor".to_owned(),
        Payload: query,
    };
    println!("{:?}", req.to_json());
    let resp = meson_send(req.to_json())?;
    println!("resp:{}", resp);

    Ok(resp)
}

pub async fn fill_tx(
    wallet: &Wallet<SigningKey>,
    to: Address,
    value: U256,
    chain_id: U64,
    data: String,
) -> Result<Bytes, MesonError> {
    let query_return = meson_eth_query(wallet.address(), to, value, data)?;
    let gas_info: meson_common::EthQueryResponse = serde_json::from_str(&query_return).unwrap();
    let gas = U256::from_big_endian(
        &hex::decode(gas_info.GasLimit.strip_prefix("0x").unwrap()).unwrap()[..],
    );
    println!("{:?}", gas);
    let gas_price = U256::from_big_endian(
        &hex::decode(gas_info.GasPrice.strip_prefix("0x").unwrap()).unwrap()[..],
    );
    println!("{:?}", gas_price);
    let mut nonce = gas_info.Nonce.strip_prefix("0x").unwrap().to_string();
    if nonce.len() % 2 != 0 {
        nonce = "0".to_string() + &nonce;
    }

    let nonce = U256::from_big_endian(&hex::decode(nonce).unwrap()[..]);
    println!("{:?}", nonce);
    let pay_tx = TransactionRequest::new()
        .to(to)
        .value(value)
        .chain_id(chain_id)
        .gas(gas)
        .gas_price(gas_price)
        .nonce(nonce)
        .into();

    let signature = wallet.sign_transaction(&pay_tx).await.unwrap();
    let rlp_tx = pay_tx.rlp_signed(&signature);
    Ok(rlp_tx)
}

pub fn process_transaction(
    wallet: &Wallet<SigningKey>,
    to: Address,
    value: U256,
    chain_id: U64,
    data: String,
) -> Result<String, MesonError> {
    let tx_bytes = block_on(fill_tx(wallet, to, value, chain_id, data)).unwrap();
    let tx = hex::encode(tx_bytes.0.as_ref());
    let tx_string = "0x".to_string() + &tx;
    let meson_tx = meson_common::PostTransactionRequest { TxHex: tx_string }.to_json();
    let meson_tx = base64ct::Base64::encode_string(&meson_tx[..]);
    let req = meson_common::MesonCurrencyRequest {
        Version: 0,
        Command: meson_common::PostTransaction,
        Ticker: "gor".to_owned(),
        Payload: meson_tx,
    };
    println!("{:?}", req.to_json());
    let resp = meson_send(req.to_json())?;
    println!("resp:{}", resp);

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

impl MesonWallet {
    pub fn new(password: &str, path: PathBuf) -> Result<(), Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let phrase = Mnemonic::<English>::new_with_count(&mut rng, 12)?;
        //emcrypt
        fs::write::<PathBuf, String>(path.join("mnemonic"), phrase.to_phrase().unwrap())
            .expect("Unable to write file");
        // let wallet = MnemonicBuilder::<English>::default()
        //     .phrase(phrase)
        //     .index(index)?
        //     // Use this if your mnemonic is encrypted
        //     .write_to(path)
        //     .build()?;
        Ok(())
    }
}

//encrypt a hex encoded private key with given password
fn encrypt_sk<P, R, S>(
    dir: P,
    rng: &mut R,
    sk: &str,
    password: S,
    name: Option<&str>,
) -> Result<String, eth_keystore::KeystoreError>
where
    P: AsRef<Path>,
    R: Rng + CryptoRng,
    S: AsRef<[u8]>,
{
    let sk = ethers::utils::hex::decode(sk).unwrap();
    let id = eth_keystore::encrypt_key(dir, rng, sk, password, name)?;
    match name {
        None => return Ok(id),
        Some(name) => return Ok(name.to_owned()),
    };
}

//decrypt a private key with given password
fn decrypt_sk<P, S>(dir: P, password: S) -> Result<Wallet<SigningKey>, WalletError>
where
    P: AsRef<Path>,
    S: AsRef<[u8]>,
{
    let wallet = Wallet::decrypt_keystore(dir, password)?;
    Ok(wallet)
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

pub fn test_tx() {
    let tx: Vec<u8> = vec![
        123, 34, 86, 101, 114, 115, 105, 111, 110, 34, 58, 48, 44, 34, 67, 111, 109, 109, 97, 110,
        100, 34, 58, 48, 44, 34, 84, 105, 99, 107, 101, 114, 34, 58, 34, 103, 111, 114, 34, 44, 34,
        80, 97, 121, 108, 111, 97, 100, 34, 58, 34, 101, 121, 74, 85, 101, 69, 104, 108, 101, 67,
        73, 54, 73, 106, 66, 52, 90, 106, 103, 50, 77, 122, 103, 119, 79, 68, 81, 50, 78, 68, 85,
        48, 77, 68, 104, 108, 78, 84, 103, 121, 78, 84, 73, 119, 79, 68, 107, 48, 78, 50, 86, 104,
        78, 109, 73, 120, 89, 106, 104, 104, 89, 84, 70, 108, 90, 106, 65, 50, 89, 109, 86, 108,
        90, 68, 89, 53, 77, 106, 81, 53, 79, 68, 66, 107, 79, 71, 74, 109, 77, 122, 103, 52, 79,
        84, 103, 51, 90, 106, 100, 106, 89, 122, 66, 104, 79, 68, 65, 121, 90, 87, 69, 119, 90,
        109, 69, 53, 89, 122, 77, 53, 78, 84, 86, 105, 77, 68, 73, 121, 89, 109, 89, 122, 79, 71,
        73, 119, 77, 84, 103, 122, 90, 87, 77, 52, 77, 50, 77, 121, 77, 68, 86, 105, 77, 84, 104,
        106, 79, 68, 86, 106, 78, 87, 90, 106, 90, 68, 104, 104, 78, 71, 69, 52, 78, 84, 107, 50,
        89, 50, 69, 121, 78, 50, 70, 107, 78, 50, 73, 51, 90, 106, 70, 105, 77, 87, 73, 53, 90, 71,
        69, 119, 78, 84, 90, 107, 77, 71, 77, 119, 89, 106, 65, 120, 78, 87, 77, 52, 79, 84, 70,
        107, 90, 109, 86, 108, 78, 71, 85, 121, 89, 122, 89, 121, 78, 106, 103, 49, 78, 50, 77, 52,
        78, 68, 69, 121, 78, 109, 85, 121, 78, 50, 82, 106, 78, 109, 86, 107, 89, 122, 74, 105, 77,
        109, 90, 105, 79, 71, 74, 108, 79, 71, 73, 51, 89, 84, 90, 105, 79, 84, 77, 49, 90, 68, 69,
        122, 78, 83, 74, 57, 34, 125,
    ];

    let resp = meson_send(tx).unwrap();
    println!("{}", resp);
}

#[cfg(test)]

mod tests {
    use std::str::FromStr;

    use super::*;
    use futures::executor::block_on;
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
    //todo : create a better test
    //todo: change value type
    fn create_tx() {
        let wallet: Wallet<SigningKey> =
            "2cd0fc69151afffe19e66db7e31ec34f1fbf10552983711faccba030025fc706"
                .parse()
                .unwrap();
        let tx = block_on(create_signed_tx(
            &wallet,
            "0x7ea6b1b8aa1ef06beed6924980d8bf388987f7cc"
                .parse()
                .unwrap(),
            10.into(),
            U256::from(2_000_000),
            U256::from_dec_str("200000000").unwrap(),
            0.into(),
            5.into(),
        ))
        .unwrap();

        println!("{}", tx);
    }

    #[test]
    fn test_new() {
        MesonWallet::new("asda", PathBuf::from("./")).unwrap();
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
        let name = encrypt_sk(
            tmp_dir.path(),
            &mut rand::thread_rng(),
            "2cd0fc69151afffe19e66db7e31ec34f1fbf10552983711faccba030025fc706",
            "llkasd",
            Some("00001"),
        )
        .unwrap();

        let wallet = decrypt_sk(tmp_dir.path().join(name), "llkasd").unwrap();
        let wallet2: Wallet<SigningKey> =
            "2cd0fc69151afffe19e66db7e31ec34f1fbf10552983711faccba030025fc706"
                .parse()
                .unwrap();

        assert_eq!(wallet, wallet2);
    }

    // fn test_eth_query() {
    //     let res = meson_eth_query(
    //         Address::from_str("0x64440a8ca29D455029E28cDa94096f3EaB7b248a").unwrap(),
    //         Address::from_str("0x85ef6db74c13B3bfa12A784702418e5aAfad73EB").unwrap(),
    //         U256::from_dec_str("123"),
    //         "".to_owned(),
    //     );

    #[test]

    fn test_tx() {
        let tx: Vec<u8> = vec![
            123, 34, 86, 101, 114, 115, 105, 111, 110, 34, 58, 48, 44, 34, 67, 111, 109, 109, 97,
            110, 100, 34, 58, 48, 44, 34, 84, 105, 99, 107, 101, 114, 34, 58, 34, 103, 111, 114,
            34, 44, 34, 80, 97, 121, 108, 111, 97, 100, 34, 58, 34, 101, 121, 74, 85, 101, 69, 104,
            108, 101, 67, 73, 54, 73, 106, 66, 52, 90, 106, 103, 50, 77, 122, 103, 119, 79, 68, 81,
            50, 78, 68, 85, 48, 77, 68, 104, 108, 78, 84, 103, 121, 78, 84, 73, 119, 79, 68, 107,
            48, 78, 50, 86, 104, 78, 109, 73, 120, 89, 106, 104, 104, 89, 84, 70, 108, 90, 106, 65,
            50, 89, 109, 86, 108, 90, 68, 89, 53, 77, 106, 81, 53, 79, 68, 66, 107, 79, 71, 74,
            109, 77, 122, 103, 52, 79, 84, 103, 51, 90, 106, 100, 106, 89, 122, 66, 104, 79, 68,
            65, 121, 90, 87, 69, 119, 90, 109, 69, 53, 89, 122, 77, 53, 78, 84, 86, 105, 77, 68,
            73, 121, 89, 109, 89, 122, 79, 71, 73, 119, 77, 84, 103, 122, 90, 87, 77, 52, 77, 50,
            77, 121, 77, 68, 86, 105, 77, 84, 104, 106, 79, 68, 86, 106, 78, 87, 90, 106, 90, 68,
            104, 104, 78, 71, 69, 52, 78, 84, 107, 50, 89, 50, 69, 121, 78, 50, 70, 107, 78, 50,
            73, 51, 90, 106, 70, 105, 77, 87, 73, 53, 90, 71, 69, 119, 78, 84, 90, 107, 77, 71, 77,
            119, 89, 106, 65, 120, 78, 87, 77, 52, 79, 84, 70, 107, 90, 109, 86, 108, 78, 71, 85,
            121, 89, 122, 89, 121, 78, 106, 103, 49, 78, 50, 77, 52, 78, 68, 69, 121, 78, 109, 85,
            121, 78, 50, 82, 106, 78, 109, 86, 107, 89, 122, 74, 105, 77, 109, 90, 105, 79, 71, 74,
            108, 79, 71, 73, 51, 89, 84, 90, 105, 79, 84, 77, 49, 90, 68, 69, 122, 78, 83, 74, 57,
            34, 125,
        ];

        let resp = meson_send(tx).unwrap();
        println!("{}", resp);
    }
}
