use arweave_wallet::Wallet;
use clap::Parser;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "arweave-wallet",
    about = "Generate an Arweave RSA-4096 JWK wallet",
    long_about = "Creates a new Arweave wallet: a 4096-bit RSA key pair in JWK form \
(public exponent 65537). The keyfile is the private key — keep it secret and back it up."
)]
struct Args {
    /// Write the JWK keyfile to this path (default: arweave-keyfile-<address>.json)
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Print the wallet as JSON (address + JWK) to stdout instead of writing a file
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    eprint!("Generating RSA-4096 Arweave wallet (this can take a few seconds)... ");
    let wallet = Wallet::generate()?;
    eprintln!("done.");

    if args.json {
        println!("{}", wallet.to_json()?);
        if args.output.is_none() {
            return Ok(());
        }
    } else {
        eprintln!("Address: {}", wallet.address);
        eprintln!("Keep the JWK private. Anyone with this file can spend the wallet's AR.");
    }

    let path = args
        .output
        .unwrap_or_else(|| PathBuf::from(wallet.default_filename()));

    write_keyfile(&path, wallet.to_jwk_json()?.as_bytes())?;
    if !args.json {
        eprintln!("Wrote {}", path.display());
    }
    Ok(())
}

fn write_keyfile(path: &PathBuf, json: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|err| {
        format!(
            "could not create {}: {err} (refusing to overwrite an existing file)",
            path.display()
        )
    })?;
    file.write_all(json)?;
    file.write_all(b"\n")?;
    Ok(())
}
