use crate::user_opertaion::UserOperation;
use crate::wallet::Account;
use dialoguer::console::Term;
use ethers::prelude::NameOrAddress;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::utils::hex;
use std::io;

// select between eoa wallet/ account abstraction wallet
pub fn select_wallet_type() -> Result<u8, io::Error> {
    let selections = vec!["EOA Wallet", "Account Abstraction Wallet", "Quit"];
    let selection = dialoguer::Select::new()
        .with_prompt("\nMeson Wallet")
        .items(&selections)
        .default(0)
        .interact_on_opt(&Term::stderr())?;

    match selection {
        Some(index) => return Ok(index as u8),
        None => return Err(io::Error::new(io::ErrorKind::Other, "")),
    }
}

// select account abstraction wallet type
pub fn select_aa_wallet_type(selections: &[String]) -> Result<u8, io::Error> {
    let selection = dialoguer::Select::new()
        .items(&selections)
        .default(0)
        .interact_on_opt(&Term::stderr())?;

    match selection {
        Some(index) => return Ok(index as u8),
        None => return Err(io::Error::new(io::ErrorKind::Other, "")),
    }
}

// select account abstraction wallet function
pub fn select_aa_func() -> Result<u8, io::Error> {
    let selections = vec![
        "Create account",
        "Send transaction",
        "Tornado: Deposit",
        "Tornado: Withdraw",
        "Delete account",
        "Back",
    ];
    let selection = dialoguer::Select::new()
        .items(&selections)
        .default(0)
        .interact_on_opt(&Term::stderr())?;

    match selection {
        Some(index) => return Ok(index as u8),
        None => return Err(io::Error::new(io::ErrorKind::Other, "")),
    }
}

// select multisig wallet function
pub fn select_multisig_func() -> Result<u8, io::Error> {
    let selections = vec![
        "Create account",
        "Create transaction",
        "Confirm transaction",
        "Send transaction",
        "Delete account",
        "Back",
    ];
    let selection = dialoguer::Select::new()
        .items(&selections)
        .default(0)
        .interact_on_opt(&Term::stderr())?;

    match selection {
        Some(index) => return Ok(index as u8),
        None => return Err(io::Error::new(io::ErrorKind::Other, "")),
    }
}

//todo: consider using this in all account types
//select transaction type (currently only used in multisig wallet)
pub fn select_transaction_type() -> Result<u8, io::Error> {
    let selections = vec!["Eth transaction", "Tornado Deposit", "Tornado Withdraw"];
    let selection = dialoguer::Select::new()
        .items(&selections)
        .default(0)
        .interact_on_opt(&Term::stderr())?;

    match selection {
        Some(index) => return Ok(index as u8),
        None => return Err(io::Error::new(io::ErrorKind::Other, "")),
    }
}

// select eoa wallet function
pub fn select_eoa_func() -> Result<u8, io::Error> {
    let selections = vec![
        "Import mnemonic",
        "Create new mnemonic",
        "Import account",
        "Create account",
        "Send transaction",
        "Show mnemonic",
        "Delete imported account",
        "Back",
    ];
    let selection = dialoguer::Select::new()
        .items(&selections)
        .default(0)
        .interact_on_opt(&Term::stderr())?;

    match selection {
        Some(index) => return Ok(index as u8),
        None => return Err(io::Error::new(io::ErrorKind::Other, "")),
    }
}

// prompt for password with repeated password confirmation
pub fn prompt_password_confirm() -> Result<String, io::Error> {
    let password = dialoguer::Password::default()
        .with_prompt("Enter Password")
        .with_confirmation("Repeat password", "Error: the passwords don't match.")
        .interact()?;
    Ok(password)
}

// prompt for password
pub fn prompt_password() -> Result<String, io::Error> {
    let password = dialoguer::Password::default()
        .with_prompt("Enter Password")
        .interact()?;
    Ok(password)
}

// select an eoa account wallet
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

// select an aa account wallet
pub fn select_aa_account(accounts: &[String]) -> Result<&str, io::Error> {
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

// select an element from a string slice
pub fn select_string_slice<'a>(
    lists: &'a [String],
    prompt: Option<&'a str>,
) -> Result<&'a str, io::Error> {
    let selection;
    match prompt {
        Some(t) => {
            selection = dialoguer::Select::new()
                .with_prompt(t)
                .items(lists)
                .default(0)
                .interact_on_opt(&Term::stderr())?;
        }

        None => {
            selection = dialoguer::Select::new()
                .items(lists)
                .default(0)
                .interact_on_opt(&Term::stderr())?;
        }
    }

    match selection {
        Some(index) => return Ok(&lists[index]),
        None => return Err(io::Error::new(io::ErrorKind::Other, "")),
    }
}

//select multiple account abstraction wallet
pub fn select_multiple_aa_account(accounts: &[String]) -> Result<Vec<usize>, io::Error> {
    let selections = dialoguer::MultiSelect::new()
        .with_prompt("Press space to select owners")
        .items(accounts)
        .interact_on_opt(&Term::stderr())?;

    match selections {
        Some(indices) => return Ok(indices),
        None => return Err(io::Error::new(io::ErrorKind::Other, "")),
    }
}

// select a tornato cash note
pub fn select_tor_note(notes: &[String]) -> Result<&str, io::Error> {
    let selection = dialoguer::Select::new()
        .with_prompt("Select a note")
        .items(notes)
        .default(0)
        .interact_on_opt(&Term::stderr())?;

    match selection {
        Some(index) => return Ok(&notes[index]),
        None => return Err(io::Error::new(io::ErrorKind::Other, "")),
    }
}

// prompt for eoa transaction confirmation
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

// prompt for erc4337 user operation confirmation
pub fn confirm_user_op(user_op: &UserOperation, user_op_hash: &str) -> Result<(), io::Error> {
    let sender = "0x".to_owned() + &hex::encode(user_op.sender.as_bytes());
    let nonce = user_op.nonce.to_string();
    let call_gas_limit = user_op.callGasLimit.to_string();
    let verification_gas_limit = user_op.verificationGasLimit.to_string();
    let pre_verfication_gas = user_op.preVerificationGas.to_string();
    let max_fee_per_gas = user_op.maxFeePerGas.to_string();
    let max_priority_fee_per_gas = user_op.maxPriorityFeePerGas.to_string();
    let data = user_op.paymasterAndData.to_string();
    let to = user_op.get_receipient();
    let amount = user_op.get_amount();
    _ = user_op.get_data();
    _ = user_op.get_function_signature();

    println!("====================================");
    println!("userOp hash:{}", user_op_hash);
    println!("sender: {}", sender);
    println!("receiver: {}", to);
    println!("amount: {} wei", amount);
    println!("nonce: {}", nonce);
    println!("call gas limit: {}", call_gas_limit);
    println!("verification gas limit: {}", verification_gas_limit);
    println!("pre verfication gas: {}", pre_verfication_gas);
    println!("max fee per gas: {}", max_fee_per_gas);
    println!("max priority fee per gas: {}", max_priority_fee_per_gas);
    println!("paymaster and data: {}", data);
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
