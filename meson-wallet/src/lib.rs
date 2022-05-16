#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use ethers::prelude::{k256::ecdsa::SigningKey, *};
include!("../bindings.rs");
async fn create_signed_tx(
    wallet: &Wallet<SigningKey>,
    to: H160,
    value: u128,
) -> Result<Bytes, WalletError> {
    let pay_tx = TransactionRequest::new().to(to).value(value).into();
    let signature = wallet.sign_transaction(&pay_tx).await?;
    let rlp_tx = pay_tx.rlp_signed(&signature);
    Ok(rlp_tx)
}

// fn through_meson( tx: Byte,)
