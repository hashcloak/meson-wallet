use std::env;
mod bls;
mod cli;
mod create_sender_util;
mod erc4337_common;
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
    let wallet = wallet::MesonWallet::new(wallet_config_path);
    loop {
        match cli::select_func() {
            Ok(input) => {
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
                            continue;
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
            Err(_) => {
                println!("Please try again.");
                continue;
            }
        }
    }
}
