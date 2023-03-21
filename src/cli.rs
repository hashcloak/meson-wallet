use crate::wallet::Account;
use dialoguer::console::Term;
use ethers::prelude::NameOrAddress;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::utils::hex;
use std::io;

pub fn select_func() -> Result<u8, io::Error> {
    let selections = vec![
        "Import mnemonic",
        "Create new mnemonic",
        "Import account",
        "Create account",
        "Send transaction",
        "Show mnemonic",
        "Delete imported account",
    ];
    let selection = dialoguer::Select::new()
        .with_prompt("\nMeson wallet")
        .items(&selections)
        .default(0)
        .interact_on_opt(&Term::stderr())?;

    match selection {
        Some(index) => return Ok(index as u8),
        None => return Err(io::Error::new(io::ErrorKind::Other, "")),
    }
}

pub fn prompt_password_confirm() -> Result<String, io::Error> {
    let password = dialoguer::Password::default()
        .with_prompt("Enter Password")
        .with_confirmation("Repeat password", "Error: the passwords don't match.")
        .interact()?;
    Ok(password)
}

pub fn prompt_password() -> Result<String, io::Error> {
    let password = dialoguer::Password::default()
        .with_prompt("Enter Password")
        .interact()?;
    Ok(password)
}

pub fn select_account(accounts: &[Account]) -> Result<&Account, io::Error> {
    let selection = dialoguer::Select::new()
        .with_prompt("Select an account")
        .items(accounts)
        .default(0)
        .interact_on_opt(&Term::stderr())?;

    match selection {
        Some(index) => return Ok(&accounts[index]),
        None => return Err(io::Error::new(io::ErrorKind::Other, "")),
    }
}

pub fn confirm_tx(tx: &TypedTransaction) -> Result<(), io::Error> {
    let from = tx
        .from()
        .ok_or(io::Error::new(io::ErrorKind::Other, "blank value"))?;
    let from = "0x".to_owned() + &hex::encode(from);

    let name_or_addr = tx
        .to()
        .ok_or(io::Error::new(io::ErrorKind::Other, "blank value"))?;

    let value = tx
        .value()
        .ok_or(io::Error::new(io::ErrorKind::Other, "blank value"))?
        .to_string();
    let value = "0x".to_owned() + &hex::encode(value);

    let gas = tx
        .gas()
        .ok_or(io::Error::new(io::ErrorKind::Other, "blank value"))?
        .to_string();

    let gas_price = tx
        .gas_price()
        .ok_or(io::Error::new(io::ErrorKind::Other, "blank value"))?
        .to_string();

    let chain_id = tx
        .chain_id()
        .ok_or(io::Error::new(io::ErrorKind::Other, "blank value"))?
        .to_string();

    println!("====================================");
    println!("Using account: {}", from);
    match name_or_addr {
        NameOrAddress::Name(val) => {
            println!("To: {}", val)
        }
        NameOrAddress::Address(val) => {
            let val = "0x".to_owned() + &hex::encode(val);
            println!("To: {}", val)
        }
    }
    println!("Value: {}", value);
    println!("Chain: {}", chain_id);
    println!("GasLimit: {}", gas);
    println!("GasPrice: {}", gas_price);
    println!("====================================");
    let term = Term::stderr();

    if dialoguer::Confirm::new()
        .with_prompt("Confirm transaction?")
        .interact_on(&term)?
    {
        Ok(())
    } else {
        return Err(io::Error::new(io::ErrorKind::Other, ""));
    }
}
