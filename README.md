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
cargo install arweave-keygen
```

From this repo:

```bash
cargo install --path .
cargo run --release
```

Always use `--release` when running from source. Debug builds spend most of their time in big-integer math.

## Usage

```bash
# Write arweave-keyfile-<address>.json in the current directory
arweave-keygen

# Choose the path
arweave-keygen -o ./wallet.json

# Print address + JWK as JSON (no file, unless you also pass -o)
arweave-keygen --json

# Print only the receiving address from an existing JWK keyfile
arweave-keygen address ./wallet.json
```

`address` writes only the address to standard output, so it is safe to use when
you need a recipient address without exposing the private JWK:

```bash
arweave-keygen address ./wallet.json
# z5gK4f7xkSKEdwKKuY_ly27cAzCzu9wgrcM-JuJLCjA
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
use arweave_keygen::Wallet;

let wallet = Wallet::generate()?;
println!("{}", wallet.address);
println!("{}", wallet.to_jwk_json()?); // keyfile JSON
println!("{}", wallet.to_json()?);     // { address, jwk }
```

## What this is not

It does not send AR, sign transactions, or talk to a gateway. It only creates a wallet. It does not derive keys from a BIP39 mnemonic — those schemes are not interoperable across Arweave tools. This matches the original Arweave keyfile: one random RSA-4096 pair, one address.

## Copy-paste for LLMs

```
You are using arweave-keygen (https://github.com/robbestad/arweave-keygen).

It generates an Arweave wallet locally: one random RSA-4096 key pair as a canonical JWK keyfile. It does not talk to the network, sign transactions, send AR, or derive keys from a BIP39 mnemonic.

Protocol (required or the network rejects the key):
- RSA-4096, public exponent 65537 (JWK e = "AQAB")
- JWK fields: kty, e, n, d, p, q, dp, dq, qi
- Address = base64url(SHA-256(n bytes)), 43 characters, no padding
- The JWK is the private key. There is no recovery phrase.

CLI (always --release; debug RSA-4096 is slow):
  cargo install arweave-keygen
  arweave-keygen
  arweave-keygen -o ./wallet.json
  arweave-keygen --json
  arweave-keygen address ./wallet.json

Default file: arweave-keyfile-<address>.json, mode 0600, never overwrites.
--json prints { "address", "jwk" } on stdout and skips the file unless -o is also set.
`address KEYFILE` prints only the address derived from an existing JWK keyfile.

Rust:
  use arweave_keygen::Wallet;
  let w = Wallet::generate()?;
  w.address; w.to_jwk_json()?; w.to_json()?;

Import the keyfile in ArConnect, arweave.app, or arweave-js. Do not print the JWK unless the user asked. Treat it as a secret.
```

## License

MIT. See [LICENSE](LICENSE).
