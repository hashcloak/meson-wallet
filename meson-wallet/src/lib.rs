#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use base64ct::{Base64, Encoding};
use ethers::prelude::{k256::ecdsa::SigningKey, *};
use ethers::signers::coins_bip39::{English, Mnemonic};
use rand::{CryptoRng, Rng};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::error::Error;
use std::ffi::{c_void, CString};
use std::fs;
use std::path::{Path, PathBuf};
use tempdir::TempDir;

mod error;
use error::MnemonicError;
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
#[derive(Serialize, Deserialize)]
struct JsonMnemonic {
    mnemonic: String,
    mac: String,
    salt: String,
    iv: String,
}

//todo: setup meson config
struct meson_config {}

//create a signed tx
async fn create_signed_tx(
    wallet: &Wallet<SigningKey>,
    to: H160,
    value: u128,
    gas: u128,
    gas_price: u128,
    nonce: u128,
    chain_id: u64,
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
        "/Users/liaoyuchen/Developer/hashcloak/meson/meson-wallet/examples/client.example.toml",
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
        let chello = CString::new(hello).unwrap();
        let chello = chello.as_bytes_with_nul().as_ptr() as *mut c_void;
        let meson_return = BlockingSendUnreliableMessage(chello, 5);
        println!("{}", *meson_return.r0 as u8 as char);
        Shutdown();
    }
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
            10,
            2_000_000,
            21_000_000_000,
            0,
            5,
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
}
