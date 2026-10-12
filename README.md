# MyPGP - Encryption Tool

MyPGP is a modular Python command-line encryption tool inspired by PGP. It exposes symmetric, asymmetric, and hybrid encryption workflows through one consistent CLI. Every algorithm is implemented by hand, without any cryptographic library.

## Requirements

- Python 3
- GNU Make (optional, for the shortcuts below)

## Quick start

Build the executable wrapper.
Makefile rules below :

```bash
make
make clean
make fclean
make re
make tests_run
```

## CLI usage

```text
./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]
```

`CRYPTO_SYSTEM` must be one of:

- `xor`: XOR encryption and decryption.
- `aes`: AES-128 encryption and decryption.
- `rsa`: RSA key generation (`-g P Q`), encryption and decryption.
- `pgp-xor`: hybrid workflow, RSA protects an XOR key.
- `pgp-aes`: hybrid workflow, RSA protects an AES key.

Modes and options:

```text
-c             Encrypt a clear message read from standard input.
-d             Decrypt a message read from standard input.
-b             Use one-block mode for XOR, AES, and PGP workflows.
-g P Q         RSA only: generate keys from the prime parameters P and Q.
-h, --help     Display the usage text.
key            Key used for encryption or decryption (format depends on the system).
```

Quick example:

```bash
$> echo "All men must die" | ./my_pgp aes -c -b 57696e74657220697320636f6d696e67
744ce22c385958348f0df26eceb62eef
```

## Documentation

- [CLI reference](docs/cli_reference.md): commands, key formats, and examples for every system.
- [Architecture](docs/architecture.md): code layout and responsibilities.
- [Cryptographic design](docs/cryptography.md): how each algorithm works in this project.
