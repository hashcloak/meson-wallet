use std::env;

use crate::bls::BLSAccount;
use dialoguer::{console, Confirm, Input};
use erc4337_common::Account;
use erc4337wallet::Erc4337Wallet;
use ethers::types::{Address, U256};
use ethers::utils::hex;
use simple_account::SimpleAccount;
use std::error::Error;
use std::fs;
use std::str::FromStr;
use wallet::MesonWallet;
mod bls;
mod cli;
mod erc4337_common;
use tokio::runtime::Runtime;
mod erc4337wallet;
mod error;
mod meson_common;
mod simple_account;
mod tornado_util;
mod user_opertaion;
mod wallet;

fn main() {
    let args: Vec<String> = env::args().collect();
    let wallet_config_path: &str;
    match args.get(1) {
        Some(path) => wallet_config_path = path,
        None => wallet_config_path = "wallet_config.toml",
    }
    let wallet = MesonWallet::new(wallet_config_path);
    let aa_wallet = Erc4337Wallet::new(wallet_config_path);
    loop {
        match cli::select_wallet_type() {
            Ok(input) => {
                //EOA wallet
                if input == 0 {
                    if let Ok(input) = cli::select_eoa_func() {
                        parse_eoa_input(input, &wallet);
                    };
                //Account Abstraction wallet
                } else if input == 1 {
                    let mut supported_list = aa_wallet.supproted_acount_types();
                    supported_list.push("Back".to_string());
                    if let Ok(input) = cli::select_aa_wallet_type(&supported_list) {
                        if let Err(e) = parse_aa_type(input, &aa_wallet) {
                            println!("{}", e);
                            continue;
                        }
                    };
                } else if input == 2 {
                    break;
                }
            }
            Err(_) => {
                break;
            }
        }
    }
}

fn parse_eoa_input(input: u8, wallet: &MesonWallet) {
    if input == 0 {
        //import mnemonic
        if let Err(_) = wallet.import_mnemonic() {
            println!("Unable to import mnemonic");
        }
    } else if input == 1 {
        //Create new mnemonic

        println!("Creating mnemonic...");
        match wallet.new_mnemonic() {
            Ok(_) => {
                println!("Success!")
            }
            Err(_) => {
                println!("Unabel to create mnemonic, please try again!");
            }
        };
    } else if input == 2 {
        //Import account
        if let Err(_) = wallet.import_account() {
            println!("Unable to import account");
        }
    } else if input == 3 {
        //Create account
        if let Err(_) = wallet.derive_account() {
            println!("Unable to create account");
        };
    } else if input == 4 {
        //Send transaction
        if let Err(error) = wallet.send_transaction() {
            println!("{}", error);
        }
    } else if input == 5 {
        //Show mnemonic
        if let Err(_) = wallet.show_mnemonic() {
            println!("Unable to decrypt mnemonic");
        }
    } else if input == 6 {
        if let Err(error) = wallet.delete_imported_account() {
            println!("{}", error);
        }
    }
}

fn parse_aa_type(input: u8, aa_wallet: &Erc4337Wallet) -> Result<(), Box<dyn Error>> {
    //Simple Account
    if input == 0 {
        simple_account(aa_wallet)?;
    }
    //BLS Account
    else if input == 1 {
        bls_account(aa_wallet)?;
    }

    Ok(())
}

fn simple_account(aa_wallet: &Erc4337Wallet) -> Result<(), Box<dyn Error>> {
    if let Ok(i) = cli::select_aa_func() {
        if i == 0 {
            //Create account
            let term = console::Term::stderr();
            let entry_point = Input::<String>::new()
                .with_prompt("Entry Point (Blank for default")
                .default(aa_wallet.entrypoint.clone())
                .interact_on(&term)?;
            let entry_point = Address::from_str(&entry_point)?;

            let owner_sk = Input::<String>::new()
                .with_prompt("Wallet owner private key")
                .interact_on(&term)?;
            let mut owner_sk = hex::decode(owner_sk)?;

            let chain_id = Input::<String>::new()
                .with_prompt("Chain ID")
                .interact_on(&term)?;
            let password = cli::prompt_password_confirm()?;
            let account = SimpleAccount::new(
                &aa_wallet.key_store_path,
                &aa_wallet.supported_accounts_path,
                entry_point,
                owner_sk.as_mut(),
                U256::from_dec_str(&chain_id)?,
                &password,
            );
            let account_addr = "0x".to_owned() + &hex::encode(account.address());
            println!("New account: {}", account_addr);
        } else if i == 1 {
            //Send transaction
            let term = console::Term::stderr();
            let accounts = SimpleAccount::account_list(&aa_wallet.key_store_path);
            let address = cli::select_aa_account(&accounts)?;
            let mut simple_account =
                SimpleAccount::load_account(&aa_wallet.key_store_path, address);
            let to = Input::<String>::new()
                .with_prompt("Send to")
                .interact_on(&term)?;
            let to_addr = Address::from_str(&to)?;
            let amount = Input::<String>::new()
                .with_prompt("Amount")
                .interact_on(&term)?;
            let password = cli::prompt_password()?;
            let rt = Runtime::new().unwrap();
            let (user_op, user_op_hash) = rt.block_on(aa_wallet.fill_user_op(
                &simple_account,
                to_addr,
                U256::from_dec_str(&amount)?,
                &password,
                None,
            ));
            cli::confirm_user_op(&user_op, &to, &amount, &user_op_hash)?;
            let result = rt.block_on(aa_wallet.g_send_op(user_op, &mut simple_account));
            println!("sent: {}", result);
        } else if i == 2 {
            //Tornado: Deposit
            let accounts = SimpleAccount::account_list(&aa_wallet.key_store_path);
            let address = cli::select_aa_account(&accounts)?;
            let password = cli::prompt_password()?;
            let mut simple_account =
                SimpleAccount::load_account(&aa_wallet.key_store_path, address);
            let rt = Runtime::new().unwrap();
            let (user_op, user_op_hash) = rt.block_on(aa_wallet.fill_tornado_deposit_user_op(
                "0.1",
                &simple_account,
                &password,
                tornado_util::TORNADO_ADDRESS.parse()?,
            ));
            cli::confirm_user_op(
                &user_op,
                tornado_util::TORNADO_ADDRESS,
                "0.1",
                &user_op_hash,
            )?;
            let result = rt.block_on(aa_wallet.g_send_op(user_op, &mut simple_account));
            println!("sent: {}", result);
        } else if i == 3 {
            //Tornado: Withdraw
            let accounts = SimpleAccount::account_list(&aa_wallet.key_store_path);
            let address = cli::select_aa_account(&accounts)?;
            let password = cli::prompt_password()?;
            let term = console::Term::stderr();
            let to = Input::<String>::new()
                .with_prompt("recipient")
                .interact_on(&term)?;
            let mut simple_account =
                SimpleAccount::load_account(&aa_wallet.key_store_path, address);
            let notes = aa_wallet.tornado_note_lists(&simple_account);
            if notes.len() == 0 {
                return Err("No tornado note under this account".into());
            };
            let note_digest = cli::select_tor_note(&notes)?;
            let note = aa_wallet.load_tornado_note(&simple_account, note_digest, &password);
            println!("Generating proof...");
            let rt = Runtime::new().unwrap();
            let (user_op, user_op_hash) = rt.block_on(aa_wallet.fill_tornado_withdraw_user_op(
                &note,
                to.parse()?,
                &simple_account,
                &password,
                tornado_util::TORNADO_ADDRESS.parse()?,
            ));
            cli::confirm_user_op(&user_op, tornado_util::TORNADO_ADDRESS, "0", &user_op_hash)?;
            let result = rt.block_on(aa_wallet.g_send_op(user_op, &mut simple_account));
            aa_wallet.delete_tornado_note(&simple_account, note_digest);
            println!("sent: {}", result);
        } else if i == 4 {
            //Delete account
            let accounts = SimpleAccount::account_list(&aa_wallet.key_store_path);
            let address = cli::select_aa_account(&accounts)?;
            let password = cli::prompt_password()?;
            let key_dir = aa_wallet
                .key_store_path
                .join("simple_account")
                .join(address)
                .join("key");
            if let Err(_) = Erc4337Wallet::decrypt_key(key_dir, &password) {
                return Err("wrong password".into());
            };
            let prompt = "Delete account ".to_string() + address + "?";
            if Confirm::new().with_prompt(prompt).interact()? {
                fs::remove_dir_all(
                    aa_wallet
                        .key_store_path
                        .join("simple_account")
                        .join(address),
                )?;
                println!("Account deleted");
            } else {
                return Err("".into());
            }
        }
    }
    return Ok(());
}

fn bls_account(aa_wallet: &Erc4337Wallet) -> Result<(), Box<dyn Error>> {
    if let Ok(i) = cli::select_aa_func() {
        if i == 0 {
            //Create account
            let term = console::Term::stderr();
            let entry_point = Input::<String>::new()
                .with_prompt("Entry Point (Blank for default")
                .default(aa_wallet.entrypoint.clone())
                .interact_on(&term)?;
            let chain_id = Input::<String>::new()
                .with_prompt("Chain ID")
                .interact_on(&term)?;
            let password = cli::prompt_password_confirm()?;
            let account = BLSAccount::new(
                &aa_wallet.key_store_path,
                &aa_wallet.supported_accounts_path,
                entry_point.parse()?,
                None,
                U256::from_dec_str(&chain_id)?,
                &password,
            );
            let account_addr = "0x".to_owned() + &hex::encode(account.address());
            println!("New account: {}", account_addr);
        } else if i == 1 {
            //Send transaction
            let term = console::Term::stderr();
            let accounts = BLSAccount::account_list(&aa_wallet.key_store_path);
            let address = cli::select_aa_account(&accounts)?;
            let mut bls_account = BLSAccount::load_account(&aa_wallet.key_store_path, address);
            let to = Input::<String>::new()
                .with_prompt("Send to")
                .interact_on(&term)?;
            let to_addr = Address::from_str(&to)?;
            let amount = Input::<String>::new()
                .with_prompt("Amount")
                .interact_on(&term)?;
            let password = cli::prompt_password()?;
            let rt = Runtime::new().unwrap();
            let (user_op, user_op_hash) = rt.block_on(aa_wallet.fill_user_op(
                &bls_account,
                to_addr,
                U256::from_dec_str(&amount)?,
                &password,
                None,
            ));
            cli::confirm_user_op(&user_op, &to, &amount, &user_op_hash)?;
            let result = rt.block_on(aa_wallet.g_send_op(user_op, &mut bls_account));
            println!("sent: {}", result);
        } else if i == 2 {
            //Tornado: Deposit
            let accounts = BLSAccount::account_list(&aa_wallet.key_store_path);
            let address = cli::select_aa_account(&accounts)?;
            let password = cli::prompt_password()?;
            let mut bls_account = BLSAccount::load_account(&aa_wallet.key_store_path, address);
            let rt = Runtime::new().unwrap();
            let (user_op, user_op_hash) = rt.block_on(aa_wallet.fill_tornado_deposit_user_op(
                "0.1",
                &bls_account,
                &password,
                tornado_util::TORNADO_ADDRESS.parse()?,
            ));
            cli::confirm_user_op(
                &user_op,
                tornado_util::TORNADO_ADDRESS,
                "0.1",
                &user_op_hash,
            )?;
            let result = rt.block_on(aa_wallet.g_send_op(user_op, &mut bls_account));
            println!("sent: {}", result);
        } else if i == 3 {
            //Tornado: Withdraw
            let accounts = BLSAccount::account_list(&aa_wallet.key_store_path);
            let address = cli::select_aa_account(&accounts)?;
            let password = cli::prompt_password()?;
            let term = console::Term::stderr();
            let to = Input::<String>::new()
                .with_prompt("recipient")
                .interact_on(&term)?;
            let mut bls_account = BLSAccount::load_account(&aa_wallet.key_store_path, address);
            let notes = aa_wallet.tornado_note_lists(&bls_account);
            if notes.len() == 0 {
                return Err("No tornado note under this account".into());
            };
            let note_digest = cli::select_tor_note(&notes)?;
            let note = aa_wallet.load_tornado_note(&bls_account, note_digest, &password);
            println!("Generating proof...");
            let rt = Runtime::new().unwrap();
            let (user_op, user_op_hash) = rt.block_on(aa_wallet.fill_tornado_withdraw_user_op(
                &note,
                to.parse()?,
                &bls_account,
                &password,
                tornado_util::TORNADO_ADDRESS.parse()?,
            ));
            cli::confirm_user_op(&user_op, tornado_util::TORNADO_ADDRESS, "0", &user_op_hash)?;
            let result = rt.block_on(aa_wallet.g_send_op(user_op, &mut bls_account));
            aa_wallet.delete_tornado_note(&bls_account, note_digest);
            println!("sent: {}", result);
        } else if i == 4 {
            //Delete account
            let accounts = BLSAccount::account_list(&aa_wallet.key_store_path);
            let address = cli::select_aa_account(&accounts)?;
            let password = cli::prompt_password()?;
            let key_dir = aa_wallet
                .key_store_path
                .join("bls")
                .join(address)
                .join("key");
            if let Err(_) = Erc4337Wallet::decrypt_key(key_dir, &password) {
                return Err("wrong password".into());
            };
            let prompt = "Delete account ".to_string() + address + "?";
            if Confirm::new().with_prompt(prompt).interact()? {
                fs::remove_dir_all(aa_wallet.key_store_path.join("bls").join(address))?;
                println!("Account deleted");
            } else {
                return Err("".into());
            }
        }
    }

    return Ok(());
}
