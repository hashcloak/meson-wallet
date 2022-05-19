use clap::Parser;
use std::path::PathBuf;

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
    let cli = Cli::parse();

    if cli.new {
        println!("Out file : {}", cli.out);
    } else {
        println!("Nothing");
    }
}
