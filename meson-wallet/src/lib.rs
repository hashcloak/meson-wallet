#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
use ethers::prelude::{k256::ecdsa::SigningKey, *};
use ethers::signers::coins_bip39::English;
use futures::executor::block_on;
use std::ffi::{c_void, CString};
include!("../bindings.rs");

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

fn build_wallet_from_mnemonic(phrase: &str, index: u32) -> Result<Wallet<SigningKey>, WalletError> {
    let wallet = MnemonicBuilder::<English>::default()
        .phrase(phrase)
        .index(index)?
        .build()?;
    Ok(wallet)
}

// fn through_meson( tx: Byte,)

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
    use super::*;

    #[test]
    fn mnemonic_build_no_password() {
        let phrase = "code black hollow banana kite betray rebuild collect fortune clean plug provide setup catch panic steel message code sudden example mechanic you donor diagram";
        let index = 0u32;
        let wallet = build_wallet_from_mnemonic(phrase, index).unwrap();
        let wallet2: Wallet<SigningKey> =
            "2cd0fc69151afffe19e66db7e31ec34f1fbf10552983711faccba030025fc706"
                .parse()
                .unwrap();
        assert_eq!(wallet, wallet2);
    }

    #[test]

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
}
