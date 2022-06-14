use clap::Parser;
use ethers::prelude::{k256::ecdsa::SigningKey, *};
use ethers::signers::coins_bip39::{English, Mnemonic};
use std::path::PathBuf;
use std::str::FromStr;
mod meson_common;
use futures::executor::block_on;
/// A basic meson wallet build on rust
#[derive(Parser, Debug)]
struct Cli {
    /// Create a new random mnemonic seed
    #[clap(short, long)]
    new: bool,

    ///Outputfile for mnemonic
    #[clap(short, long, default_value_t = String::from("./"))]
    out: String,

    /// Import a mnemonic
    #[clap(short, long, parse(from_os_str))]
    import: Option<PathBuf>,

    ///Account index
    #[clap(short, long)]
    index: Option<u32>,

    ///Config file
    #[clap(short, long, default_value_t = String::from("./config"))]
    config: String,
}

fn main() {
    // let cli = Cli::parse();

    // if cli.new {
    //     println!("Out file : {}", cli.out);
    // } else {
    //     println!("Nothing");
    // }
    //meson_wallet::ping_unblock();
    //meson_wallet::ping();
    meson_wallet::meson_register("client.example.toml");
    let res = meson_wallet::meson_eth_query(
        Address::from_str("64440a8ca29D455029E28cDa94096f3EaB7b248a").unwrap(),
        Address::from_str("85ef6db74c13B3bfa12A784702418e5aAfad73EB").unwrap(),
        U256::from_dec_str("10").unwrap(),
        "".to_owned(),
    )
    .unwrap();

    println!("{:?}", res);

    // let wallet: Wallet<SigningKey> =
    //     "2cd0fc69151afffe19e66db7e31ec34f1fbf10552983711faccba030025fc706"
    //         .parse()
    //         .unwrap();
    // let res = meson_wallet::process_transaction(
    //     &wallet,
    //     "0x7ea6b1b8aa1ef06beed6924980d8bf388987f7cc"
    //         .parse()
    //         .unwrap(),
    //     U256::from(10i32),
    //     ethers::prelude::U64::from(5i32),
    //     "".into(),
    // )
    // .unwrap();
    // println!("{:?}", res);
    // let res = meson_wallet::test_tx();
}
