use dialoguer::console::Term;
use dialoguer::{console, Confirm, Input};
use ethers::types::{Address, U256};
use ethers::utils::hex;
use meson_wallet::bls::{multi_sig_account::BLSMultiSigAccount, BLSAccount};
use meson_wallet::cli;
use meson_wallet::erc4337_common::Account;
use meson_wallet::erc4337wallet::Erc4337Wallet;
use meson_wallet::simple_account::SimpleAccount;
use meson_wallet::tornado_util;
use meson_wallet::tornado_util::Deposit;
use meson_wallet::wallet::MesonWallet;
use std::env;
use std::error::Error;
use std::str::FromStr;
use tokio::runtime::Runtime;

fn main() {
    let args: Vec<String> = env::args().collect();
    let wallet_config_path: &str;
    match args.get(1) {
        Some(path) => wallet_config_path = path,
        None => wallet_config_path = "./configuration/wallet_config.toml",
    }
    let wallet = MesonWallet::new(wallet_config_path);
    let aa_wallet = Erc4337Wallet::new(wallet_config_path).expect("invalid wallet config");
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

// parse user selected eoa function
fn parse_eoa_input(input: u8, wallet: &MesonWallet) {
    if input == 0 {
        //import mnemonic
        let term = console::Term::stderr();
        let phrase = Input::<String>::new()
            .with_prompt("Mnemonic")
            .interact_on(&term)
            .unwrap();
        let _ = term.clear_last_lines(3);
        if !Confirm::new()
            .with_prompt("All non-imported accounts will be cleared, continue?")
            .interact_on(&term)
            .unwrap()
        {
            return;
        }
        let password = cli::prompt_password().unwrap();
        if let Err(_) = wallet.import_mnemonic(&phrase, &password) {
            println!("Unable to import mnemonic");
        }
    } else if input == 1 {
        //Create new mnemonic
        println!("Creating mnemonic...");
        let mnemonic = match MesonWallet::gen_mnemonic() {
            Ok(m) => m,
            Err(_) => {
                println!("Unabel to create mnemonic, please try again!");
                return;
            }
        };
        let term = console::Term::stderr();
        let _ = term.write_line(&mnemonic);
        if Confirm::new()
            .with_prompt("All non-imported accounts will be cleared, continue?")
            .interact_on(&term)
            .unwrap()
        {
            let _ = term.clear_last_lines(2);
        } else {
            let _ = term.clear_last_lines(2);
            println!("Cancel");
            return;
        }
        let password = cli::prompt_password_confirm().unwrap();
        match wallet.save_mnemonic(&mnemonic, &password) {
            Ok(_) => {
                println!("Success!")
            }
            Err(_) => {
                println!("Unabel to create mnemonic, please try again!");
            }
        };
    } else if input == 2 {
        //Import account
        let term = console::Term::stderr();
        let sk = Input::<String>::new()
            .with_prompt("Private Key")
            .interact_on(&term)
            .unwrap();
        let _ = term.clear_last_lines(1);
        let password = cli::prompt_password().unwrap();
        match wallet.import_account(&sk, &password) {
            Ok(addr) => println!("Address {} imported!", addr),
            Err(_) => println!("Unable to import account"),
        }
    } else if input == 3 {
        //Create account
        let term = console::Term::stderr();
        let password = cli::prompt_password().unwrap();
        let _ = term.write_line("Generating new account...");
        match wallet.derive_account(&password) {
            Ok(addr) => println!("Account {} created!", addr),
            Err(_) => println!("Unable to create account"),
        }
    } else if input == 4 {
        //Send transaction
        let rt = Runtime::new().unwrap();
        let accounts = match wallet.saved_accounts() {
            Ok(accounts) => accounts,
            Err(_) => {
                println!("Unable to get saved accounts");
                return;
            }
        };
        if accounts.len() == 0 {
            println!("Empty account list");
            return;
        }
        let selected_account = match cli::select_account(&accounts) {
            Ok(a) => a,
            Err(_) => return,
        };
        let from = Address::from_str(&selected_account.addr).unwrap();
        let term = console::Term::stderr();
        let to = Input::<String>::new()
            .with_prompt("Send to")
            .interact_on(&term)
            .unwrap();
        let to = Address::from_str(&to).unwrap();
        let value = Input::<String>::new()
            .with_prompt("Value in Wei")
            .interact_on(&term)
            .unwrap();
        let value = U256::from_dec_str(&value).unwrap();
        let chain_id = Input::<u64>::new()
            .with_prompt("Chain ID")
            .interact_on(&term)
            .unwrap();

        println!("Querying gas info...");
        // let ticker = wallet.ticker(chain_id).unwrap();
        // let meson_provider = MesonProvider::new(&wallet.meson_setting_path, ticker)?;
        let tx = match rt.block_on(wallet.new_lagacy_transaction(from, to, value, chain_id, None)) {
            Ok(tx) => tx,
            Err(e) => {
                println!("{}", e);
                return;
            }
        };

        cli::confirm_tx(&tx).unwrap();
        let password = cli::prompt_password().unwrap();
        println!("Signing transaction...");
        let raw_tx = match MesonWallet::sign_transaction(&password, selected_account, &tx) {
            Ok(raw_tx) => raw_tx,
            Err(e) => {
                println!("{}", e);
                return;
            }
        };

        println!("Sending transaction...");
        let tx_hash = match rt.block_on(wallet.send_transaction(raw_tx, chain_id)) {
            Ok(hash) => hash,
            Err(e) => {
                println!("{}", e);
                return;
            }
        };

        println!("Tx hash: {}", tx_hash);
    } else if input == 5 {
        //Show mnemonic
        let password = cli::prompt_password().unwrap();
        let term = console::Term::stderr();
        _ = term.write_line("Decrypting mnemonic...");
        match wallet.show_mnemonic(&password) {
            Ok(mnemonic) => {
                _ = term.clear_last_lines(1);
                _ = term.write_line(&mnemonic);
                _ = Input::<String>::new()
                    .allow_empty(true)
                    .with_prompt("Press enter to continue")
                    .interact_on(&term);
            }
            Err(_) => {
                _ = term.clear_last_lines(1);
                println!("Unable to decrypt mnemonic");
            }
        }
        _ = term.clear_last_lines(2);
    } else if input == 6 {
        let accounts = match wallet.imported_accounts() {
            Ok(accounts) => accounts,
            Err(_) => {
                println!("Unable to get saved accounts");
                return;
            }
        };
        if accounts.len() == 0 {
            println!("Empty account list");
            return;
        }
        let selected_account = match cli::select_account(&accounts) {
            Ok(a) => a,
            Err(_) => return,
        };
        let prompt = "Delete account ".to_string() + &selected_account.addr + "?";
        if Confirm::new().with_prompt(prompt).interact().unwrap() {
            if let Err(error) = wallet.delete_account(selected_account) {
                println!("{}", error);
            }
            println!("Account deleted");
        } else {
            return;
        }
    }
}

// parse user selected account abstraction wallet type
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

// main logic of an erc4337 simple account
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
            let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
            let password = cli::prompt_password_confirm()?;
            let account = SimpleAccount::new(
                &key_store_path,
                &aa_wallet.supported_accounts_path,
                entry_point,
                owner_sk.as_mut(),
                U256::from_dec_str(&chain_id)?,
                &password,
            )?;
            let account_addr = "0x".to_owned() + &hex::encode(account.address());
            println!("New account: {}", account_addr);
        } else if i == 1 {
            //Send transaction
            let term = console::Term::stderr();
            let chain_id = Input::<String>::new()
                .with_prompt("Chain ID")
                .interact_on(&term)?;
            let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
            let accounts = SimpleAccount::account_list(&key_store_path)?;
            let address = cli::select_aa_account(&accounts)?;
            let mut simple_account = SimpleAccount::load_account(&key_store_path, address)?;
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
                U256::from_dec_str(&chain_id)?,
                &password,
                None,
            ))?;
            cli::confirm_user_op(&user_op, &user_op_hash)?;
            let result = rt.block_on(aa_wallet.send_user_op(user_op, &mut simple_account));
            println!("sent: {}", result);
        } else if i == 2 {
            //Tornado: Deposit
            let term = console::Term::stderr();
            let chain_id = Input::<String>::new()
                .with_prompt("Chain ID")
                .interact_on(&term)?;
            let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
            let accounts = SimpleAccount::account_list(&key_store_path)?;
            let address = cli::select_aa_account(&accounts)?;
            let password = cli::prompt_password()?;
            let mut simple_account = SimpleAccount::load_account(&key_store_path, address)?;
            let rt = Runtime::new().unwrap();
            let (user_op, user_op_hash) = rt.block_on(aa_wallet.fill_tornado_deposit_user_op(
                "0.1",
                &simple_account,
                U256::from_dec_str(&chain_id)?,
                &password,
                tornado_util::TORNADO_ADDRESS.parse()?,
            ))?;
            cli::confirm_user_op(&user_op, &user_op_hash)?;
            let result = rt.block_on(aa_wallet.send_user_op(user_op, &mut simple_account));
            println!("sent: {}", result);
        } else if i == 3 {
            //Tornado: Withdraw
            let term = console::Term::stderr();
            let chain_id = Input::<String>::new()
                .with_prompt("Chain ID")
                .interact_on(&term)?;
            let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
            let accounts = SimpleAccount::account_list(&key_store_path)?;
            let address = cli::select_aa_account(&accounts)?;
            let password = cli::prompt_password()?;
            let term = console::Term::stderr();
            let to = Input::<String>::new()
                .with_prompt("recipient")
                .interact_on(&term)?;
            let chain_id = U256::from_dec_str(&chain_id)?;
            let mut simple_account = SimpleAccount::load_account(&key_store_path, address)?;
            let notes = aa_wallet.tornado_note_lists(&simple_account, chain_id)?;
            if notes.len() == 0 {
                return Err("No tornado note under this account".into());
            };
            let note_digest = cli::select_tor_note(&notes)?;
            let note =
                aa_wallet.load_tornado_note(&simple_account, note_digest, chain_id, &password)?;
            println!("Generating proof...");
            let rt = Runtime::new().unwrap();
            let (user_op, user_op_hash) = rt.block_on(aa_wallet.fill_tornado_withdraw_user_op(
                &note,
                to.parse()?,
                &simple_account,
                chain_id,
                &password,
                tornado_util::TORNADO_ADDRESS.parse()?,
            ))?;
            cli::confirm_user_op(&user_op, &user_op_hash)?;
            let result = rt.block_on(aa_wallet.send_user_op(user_op, &mut simple_account));
            aa_wallet.delete_tornado_note(&simple_account, chain_id, note_digest)?;
            println!("sent: {}", result);
        } else if i == 4 {
            //Delete account
            let term = console::Term::stderr();
            let chain_id = Input::<String>::new()
                .with_prompt("Chain ID")
                .interact_on(&term)?;
            let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
            let accounts = SimpleAccount::account_list(&key_store_path)?;
            let address = cli::select_aa_account(&accounts)?;
            let password = cli::prompt_password()?;
            let account = SimpleAccount::load_account(&key_store_path, address)?;
            let prompt = "Delete account ".to_string() + address + "?";
            if Confirm::new().with_prompt(prompt).interact()? {
                account.delete_account(&key_store_path, Address::zero(), &password)?;
                println!("Account deleted");
            } else {
                return Err("".into());
            }
        }
    }
    return Ok(());
}

// main logic of an erc4337 bls account
fn bls_account(aa_wallet: &Erc4337Wallet) -> Result<(), Box<dyn Error>> {
    let selection = dialoguer::Select::new()
        .items(&["BLS Account", "BLS MultiSig Account", "Back"])
        .default(0)
        .interact_on_opt(&Term::stderr())?;

    // select bls account or multisig account
    if let Some(s) = selection {
        if s == 0 {
            // bls account
            if let Ok(i) = cli::select_aa_func() {
                if i == 0 {
                    //Create account
                    let term = console::Term::stderr();
                    let chain_id = Input::<String>::new()
                        .with_prompt("Chain ID")
                        .interact_on(&term)?;
                    let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
                    let entry_point = Input::<String>::new()
                        .with_prompt("Entry Point (Blank for default")
                        .default(aa_wallet.entrypoint.clone())
                        .interact_on(&term)?;
                    let password = cli::prompt_password_confirm()?;
                    let account = BLSAccount::new(
                        &key_store_path,
                        &aa_wallet.supported_accounts_path,
                        entry_point.parse()?,
                        None,
                        U256::from_dec_str(&chain_id)?,
                        &password,
                    )?;
                    let account_addr = "0x".to_owned() + &hex::encode(account.address());
                    println!("New account: {}", account_addr);
                } else if i == 1 {
                    //Send transaction
                    let term = console::Term::stderr();
                    let chain_id = Input::<String>::new()
                        .with_prompt("Chain ID")
                        .interact_on(&term)?;
                    let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
                    let accounts = BLSAccount::account_list(&key_store_path)?;
                    let address = cli::select_aa_account(&accounts)?;
                    let mut bls_account = BLSAccount::load_account(&key_store_path, address)?;
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
                        U256::from_dec_str(&chain_id)?,
                        &password,
                        None,
                    ))?;
                    cli::confirm_user_op(&user_op, &user_op_hash)?;
                    let result = rt.block_on(aa_wallet.send_user_op(user_op, &mut bls_account));
                    println!("sent: {}", result);
                } else if i == 2 {
                    //Tornado: Deposit
                    let term = console::Term::stderr();
                    let chain_id = Input::<String>::new()
                        .with_prompt("Chain ID")
                        .interact_on(&term)?;
                    let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
                    let accounts = BLSAccount::account_list(&key_store_path)?;
                    let address = cli::select_aa_account(&accounts)?;
                    let password = cli::prompt_password()?;
                    let mut bls_account = BLSAccount::load_account(&key_store_path, address)?;
                    let rt = Runtime::new().unwrap();
                    let (user_op, user_op_hash) =
                        rt.block_on(aa_wallet.fill_tornado_deposit_user_op(
                            "0.1",
                            &bls_account,
                            U256::from_dec_str(&chain_id)?,
                            &password,
                            tornado_util::TORNADO_ADDRESS.parse()?,
                        ))?;
                    cli::confirm_user_op(&user_op, &user_op_hash)?;
                    let result = rt.block_on(aa_wallet.send_user_op(user_op, &mut bls_account));
                    println!("sent: {}", result);
                } else if i == 3 {
                    //Tornado: Withdraw
                    let term = console::Term::stderr();
                    let chain_id = Input::<String>::new()
                        .with_prompt("Chain ID")
                        .interact_on(&term)?;
                    let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
                    let accounts = BLSAccount::account_list(&key_store_path)?;
                    let address = cli::select_aa_account(&accounts)?;
                    let chain_id = U256::from_dec_str(&chain_id)?;
                    let password = cli::prompt_password()?;
                    let term = console::Term::stderr();
                    let to = Input::<String>::new()
                        .with_prompt("recipient")
                        .interact_on(&term)?;
                    let mut bls_account = BLSAccount::load_account(&key_store_path, address)?;
                    let notes = aa_wallet.tornado_note_lists(&bls_account, chain_id)?;
                    if notes.len() == 0 {
                        return Err("No tornado note under this account".into());
                    };
                    let note_digest = cli::select_tor_note(&notes)?;
                    let note = aa_wallet.load_tornado_note(
                        &bls_account,
                        note_digest,
                        chain_id,
                        &password,
                    )?;
                    println!("Generating proof...");
                    let rt = Runtime::new().unwrap();
                    let (user_op, user_op_hash) =
                        rt.block_on(aa_wallet.fill_tornado_withdraw_user_op(
                            &note,
                            to.parse()?,
                            &bls_account,
                            chain_id,
                            &password,
                            tornado_util::TORNADO_ADDRESS.parse()?,
                        ))?;
                    cli::confirm_user_op(&user_op, &user_op_hash)?;
                    let result = rt.block_on(aa_wallet.send_user_op(user_op, &mut bls_account));
                    aa_wallet.delete_tornado_note(&bls_account, chain_id, note_digest)?;
                    println!("sent: {}", result);
                } else if i == 4 {
                    //Delete account
                    let term = console::Term::stderr();
                    let chain_id = Input::<String>::new()
                        .with_prompt("Chain ID")
                        .interact_on(&term)?;
                    let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
                    let accounts = BLSAccount::account_list(&key_store_path)?;
                    let address = cli::select_aa_account(&accounts)?;
                    let password = cli::prompt_password()?;
                    let account = BLSAccount::load_account(&key_store_path, address)?;
                    let prompt = "Delete account ".to_string() + address + "?";
                    if Confirm::new().with_prompt(prompt).interact()? {
                        account.delete_account(&key_store_path, Address::zero(), &password)?;
                        println!("Account deleted");
                    } else {
                        return Err("".into());
                    }
                }
            }
        } else if s == 1 {
            // bls multisig account
            if let Ok(i) = cli::select_multisig_func() {
                if i == 0 {
                    // Create account
                    let term = console::Term::stderr();
                    let chain_id = Input::<String>::new()
                        .with_prompt("Chain ID")
                        .interact_on(&term)?;
                    let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
                    let entry_point = Input::<String>::new()
                        .with_prompt("Entry Point (Blank for default")
                        .default(aa_wallet.entrypoint.clone())
                        .interact_on(&term)?;
                    let entry_point = Address::from_str(&entry_point)?;
                    let accounts = BLSAccount::account_list(&key_store_path)?;
                    let selected_indices = cli::select_multiple_aa_account(&accounts)?;
                    if selected_indices.len() < 2 {
                        return Err("Must select at least two owner".into());
                    }
                    let accounts: Vec<Address> = selected_indices
                        .iter()
                        .map(|i| Address::from_str(&accounts[*i]).unwrap())
                        .collect();
                    let account = BLSMultiSigAccount::new(
                        &key_store_path,
                        &aa_wallet.supported_accounts_path,
                        entry_point,
                        accounts,
                        None,
                        U256::from_dec_str(&chain_id)?,
                    )?;
                    let account_addr = "0x".to_owned() + &hex::encode(account.address());
                    println!("New account: {}", account_addr);
                } else if i == 1 {
                    //Create transaction
                    let tx_type = cli::select_transaction_type()?;
                    if tx_type == 0 {
                        //eth transaction
                        let term = console::Term::stderr();
                        let chain_id = Input::<String>::new()
                            .with_prompt("Chain ID")
                            .interact_on(&term)?;
                        let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
                        let accounts = BLSMultiSigAccount::account_list(&key_store_path)?;
                        let address = cli::select_aa_account(&accounts)?;
                        let multi_sig_account =
                            BLSMultiSigAccount::load_account(&key_store_path, address)?;
                        let to = Input::<String>::new()
                            .with_prompt("Send to")
                            .interact_on(&term)?;
                        let amount = Input::<String>::new()
                            .with_prompt("Amount")
                            .interact_on(&term)?;
                        let (user_op, user_op_hash) = multi_sig_account.create_user_op(
                            &aa_wallet,
                            Address::from_str(&to)?,
                            U256::from_dec_str(&amount)?,
                            U256::from_dec_str(&chain_id)?,
                            None,
                            None,
                        )?;
                        cli::confirm_user_op(&user_op, &user_op_hash)?;
                        multi_sig_account.store_user_op(
                            &user_op,
                            &user_op_hash,
                            &key_store_path,
                        )?;
                    } else if tx_type == 1 {
                        //tornado deposit
                        let term = console::Term::stderr();
                        let chain_id = Input::<String>::new()
                            .with_prompt("Chain ID")
                            .interact_on(&term)?;
                        let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
                        let accounts = BLSMultiSigAccount::account_list(&key_store_path)?;
                        let address = cli::select_aa_account(&accounts)?;
                        let multi_sig_account =
                            BLSMultiSigAccount::load_account(&key_store_path, address)?;
                        let chain_id = U256::from_dec_str(&chain_id)?;
                        let password = cli::prompt_password()?;
                        let tor_deposit = Deposit::new();
                        let (tx, note_string) =
                            tor_deposit.gen_deposit_tx(None, "0.1", chain_id.as_u64());
                        println!("Note string: {}", note_string);
                        aa_wallet.save_tornado_notes(
                            &note_string,
                            &multi_sig_account,
                            chain_id,
                            &password,
                        )?;
                        let (user_op, user_op_hash) = multi_sig_account.create_user_op(
                            &aa_wallet,
                            tornado_util::TORNADO_ADDRESS.parse()?,
                            ethers::utils::parse_ether("0.1").unwrap(),
                            chain_id,
                            None,
                            Some(tx),
                        )?;
                        cli::confirm_user_op(&user_op, &user_op_hash)?;
                        multi_sig_account.store_user_op(
                            &user_op,
                            &user_op_hash,
                            &key_store_path,
                        )?;
                    } else if tx_type == 2 {
                        //tornado withdraw
                        let term = console::Term::stderr();
                        let chain_id = Input::<String>::new()
                            .with_prompt("Chain ID")
                            .interact_on(&term)?;
                        let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
                        let accounts = BLSMultiSigAccount::account_list(&key_store_path)?;
                        let address = cli::select_aa_account(&accounts)?;
                        let multi_sig_account =
                            BLSMultiSigAccount::load_account(&key_store_path, address)?;
                        let password = cli::prompt_password()?;
                        let term = console::Term::stderr();
                        let to = Input::<String>::new()
                            .with_prompt("recipient")
                            .interact_on(&term)?;
                        let chain_id = U256::from_dec_str(&chain_id)?;
                        let notes = aa_wallet.tornado_note_lists(&multi_sig_account, chain_id)?;
                        if notes.len() == 0 {
                            return Err("No tornado note under this account".into());
                        };
                        let note_digest = cli::select_tor_note(&notes)?;
                        let note = aa_wallet.load_tornado_note(
                            &multi_sig_account,
                            note_digest,
                            chain_id,
                            &password,
                        )?;
                        println!("Generating proof...");
                        let rt = Runtime::new().unwrap();
                        let tx = rt.block_on(Deposit::parse_and_withdraw(
                            &note,
                            to.parse()?,
                            None,
                            None,
                            None,
                        ));
                        let (user_op, user_op_hash) = multi_sig_account.create_user_op(
                            &aa_wallet,
                            tornado_util::TORNADO_ADDRESS.parse()?,
                            0.into(),
                            chain_id,
                            None,
                            Some(tx),
                        )?;
                        cli::confirm_user_op(&user_op, &user_op_hash)?;
                        multi_sig_account.store_user_op(
                            &user_op,
                            &user_op_hash,
                            &key_store_path,
                        )?;
                    }
                } else if i == 2 {
                    //Confirm transaction
                    let term = console::Term::stderr();
                    let chain_id = Input::<String>::new()
                        .with_prompt("Chain ID")
                        .interact_on(&term)?;
                    let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
                    let accounts = BLSMultiSigAccount::account_list(&key_store_path)?;
                    let address = cli::select_aa_account(&accounts)?;
                    let multi_sig_account =
                        BLSMultiSigAccount::load_account(&key_store_path, address)?;
                    let multi_sig_members = multi_sig_account.members_list();
                    let signer_str =
                        cli::select_string_slice(&multi_sig_members, Some("Select a member"))?;
                    let signer = Address::from_str(signer_str)?;
                    let password = cli::prompt_password()?;
                    let user_ops = multi_sig_account.user_op_list(&key_store_path)?;
                    let user_op_hash =
                        cli::select_string_slice(&user_ops, Some("Select a userOp"))?;
                    let user_op = multi_sig_account.load_user_op(user_op_hash, &key_store_path)?;
                    multi_sig_account.sign_piece(
                        &key_store_path,
                        signer,
                        &user_op,
                        U256::from_dec_str(&chain_id)?,
                        &password,
                    )?;
                    println!("{} is confirmed by {}", user_op_hash, signer_str);
                } else if i == 3 {
                    //Send transaction
                    let term = console::Term::stderr();
                    let chain_id = Input::<String>::new()
                        .with_prompt("Chain ID")
                        .interact_on(&term)?;
                    let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);
                    let accounts = BLSMultiSigAccount::account_list(&key_store_path)?;
                    let address = cli::select_aa_account(&accounts)?;
                    let mut multi_sig_account =
                        BLSMultiSigAccount::load_account(&key_store_path, address)?;
                    let user_ops = multi_sig_account.user_op_list(&key_store_path)?;
                    let user_op_hash =
                        cli::select_string_slice(&user_ops, Some("Select a userOp"))?;

                    // check if there are sufficient signatures
                    let multi_sig_members_len = multi_sig_account.members_list().len();
                    let sig_path = multi_sig_account
                        .get_sig_path(&key_store_path)
                        .join(user_op_hash)
                        .join("sig_piece");
                    let sig_num = match sig_path.read_dir() {
                        Ok(entry) => entry.count(),
                        Err(_) => panic!("invalid account"),
                    };
                    if sig_num < multi_sig_members_len {
                        return Err("insufficient confirmations".into());
                    }

                    let sig = multi_sig_account.combine_sig(&key_store_path, user_op_hash)?;
                    let user_op = multi_sig_account.load_user_op(user_op_hash, &key_store_path)?;
                    let user_op = user_op.signature(sig);

                    cli::confirm_user_op(&user_op, &user_op_hash)?;
                    let rt = Runtime::new().unwrap();
                    let result =
                        rt.block_on(aa_wallet.send_user_op(user_op, &mut multi_sig_account));
                    println!("sent: {}", result);
                } else if i == 4 {
                    // Delete account
                    let term = console::Term::stderr();
                    let chain_id = Input::<String>::new()
                        .with_prompt("Chain ID")
                        .interact_on(&term)?;
                    let key_store_path = aa_wallet.key_store_path.as_path().join(&chain_id);

                    // select account to delete
                    let multisig_accounts = BLSMultiSigAccount::account_list(&key_store_path)?;
                    let address = cli::select_aa_account(&multisig_accounts)?;

                    // select the member to execute the deletion
                    let multisig_account =
                        BLSMultiSigAccount::load_account(&key_store_path, address)?;
                    let bls_accounts = multisig_account.members_list();
                    let signer_str = cli::select_string_slice(
                        &bls_accounts,
                        Some("Select the member to execute the deletion"),
                    )?;
                    let password = cli::prompt_password()?;

                    let prompt = "Delete account ".to_string() + address + "?";
                    if Confirm::new().with_prompt(prompt).interact()? {
                        multisig_account.delete_account(
                            &key_store_path,
                            Address::from_str(signer_str)?,
                            &password,
                        )?;
                        println!("Account deleted");
                    } else {
                        return Err("".into());
                    }
                }
            }
        }
    }

    return Ok(());
}
