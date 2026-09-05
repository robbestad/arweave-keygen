use arweave_keygen::Wallet;
use clap::{Parser, Subcommand};
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "arweave-keygen",
    about = "Generate an Arweave RSA-4096 JWK wallet",
    long_about = "Creates a new Arweave wallet: a 4096-bit RSA key pair in JWK form \
(public exponent 65537). The keyfile is the private key — keep it secret and back it up."
)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Write the JWK keyfile to this path (default: arweave-keyfile-<address>.json)
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,

    /// Print the wallet as JSON (address + JWK) to stdout instead of writing a file
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Print the Arweave address derived from a JWK keyfile
    Address {
        /// Path to the JWK keyfile
        #[arg(value_name = "KEYFILE")]
        keyfile: PathBuf,
    },
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

    if let Some(Command::Address { keyfile }) = args.command {
        println!("{}", address_from_keyfile(&keyfile)?);
        return Ok(());
    }

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

fn address_from_keyfile(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let json = fs::read_to_string(path)
        .map_err(|err| format!("could not read {}: {err}", path.display()))?;
    Ok(Wallet::from_jwk_json(&json)?.address)
}

fn write_keyfile(path: &Path, json: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
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
    file.sync_all()?;
    // file.sync_all persists contents, not the new directory entry.
    #[cfg(unix)]
    File::open(parent_dir(path))?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "arweave-keygen-{}-{:016x}.json",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn derives_address_from_jwk_keyfile() {
        let path = test_path();
        let wallet = Wallet::generate().unwrap();
        write_keyfile(&path, wallet.to_jwk_json().unwrap().as_bytes()).unwrap();
        let result = address_from_keyfile(&path);
        fs::remove_file(&path).unwrap();
        assert_eq!(result.unwrap(), wallet.address);
    }

    #[test]
    fn rejects_invalid_keyfile() {
        let path = test_path();
        write_keyfile(&path, br#"{"kty":"RSA","e":"AQAB","n":"AQI","d":"x","p":"x","q":"x","dp":"x","dq":"x","qi":"x"}"#).unwrap();
        let result = address_from_keyfile(&path);
        fs::remove_file(&path).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn writes_private_file_and_refuses_overwrite() {
        let path = test_path();
        write_keyfile(&path, b"original").unwrap();
        let overwrite = write_keyfile(&path, b"replacement");
        let contents = fs::read(&path).unwrap();
        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(&path).unwrap().permissions().mode() & 0o777
        };
        fs::remove_file(&path).unwrap();
        assert!(overwrite.is_err());
        assert_eq!(contents, b"original\n");
        #[cfg(unix)]
        assert_eq!(permissions & 0o177, 0);
    }
}
