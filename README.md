# arweave-keygen

Generate an Arweave wallet on your own machine, in about a second, without a browser, a website, or Node.js.

Arweave keys are not a 12-word seed. They are a **4096-bit RSA key pair** stored as a JSON Web Key. Most people create that in `arweave.app` or `arweave-js`. This tool does the same job locally, in pure Rust, and writes a keyfile those wallets already understand.

## Why use this

**You want the key to exist only where you created it.** Browser wallets generate RSA-4096 in JavaScript and keep a copy in local storage. This binary never talks to the network. Generate it on an air-gapped machine if you want a cold wallet.

**You want a key the network will actually accept.** Arweave rejects transactions unless the public exponent is **65537**. This generator hard-codes that. The address is `base64url(SHA-256(n))`, checked against Arweave’s own documented sample wallet.

**You do not want to wait a minute for JavaScript.** RSA-4096 keygen is slow in JS (often 30–120 seconds). In release mode this is typically around a second.

**You want a file you can import, not a custom format.** Output is the canonical JWK keyfile (`kty`, `e`, `n`, `d`, `p`, `q`, `dp`, `dq`, `qi`). Import it in ArConnect, arweave.app, `arweave-js`, or any other tool that takes an Arweave keyfile.

**You want to script it.** `--json` prints `{ address, jwk }` on stdout. No extra flags required to pipe a wallet into a deploy script, a test harness, or an offline backup flow.

**You want boring safety defaults.** The keyfile is created with mode `0600` and the program refuses to overwrite an existing file.

## Install

```bash
cargo install --path .
```

Or run from the repo:

```bash
cargo run --release
```

Always use `--release`. Debug builds spend most of their time in big-integer math.

## Usage

```bash
# Write arweave-keyfile-<address>.json in the current directory
arweave-wallet

# Choose the path
arweave-wallet -o ./wallet.json

# Print address + JWK as JSON (no file, unless you also pass -o)
arweave-wallet --json
```

`--json` output:

```json
{
  "address": "z5gK4f7xkSKEdwKKuY_ly27cAzCzu9wgrcM-JuJLCjA",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "n": "...",
    "d": "...",
    "p": "...",
    "q": "...",
    "dp": "...",
    "dq": "...",
    "qi": "..."
  }
}
```

The JWK **is** the private key. Anyone with that file can spend the wallet’s AR. Back it up offline; there is no recovery phrase.

## Library

```rust
use arweave_wallet::Wallet;

let wallet = Wallet::generate()?;
println!("{}", wallet.address);
println!("{}", wallet.to_jwk_json()?); // keyfile JSON
println!("{}", wallet.to_json()?);     // { address, jwk }
```

## What this is not

It does not send AR, sign transactions, or talk to a gateway. It only creates a wallet. It does not derive keys from a BIP39 mnemonic — those schemes are not interoperable across Arweave tools. This matches the original Arweave keyfile: one random RSA-4096 pair, one address.

## License

MIT. See [LICENSE](LICENSE).
