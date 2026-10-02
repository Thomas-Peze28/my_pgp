# MyPGP - Encryption Tool

MyPGP is a modular Python command-line encryption tool inspired by PGP. It is designed to expose simple symmetric, asymmetric, and hybrid encryption workflows through one consistent CLI.

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
- `aes`: AES workflow, not implemented yet.
- `rsa`: RSA workflow, including key generation with `-g`, not implemented yet.
- `pgp-xor`: hybrid RSA + XOR workflow, not implemented yet.
- `pgp-aes`: hybrid RSA + AES workflow, not implemented yet.

Modes and options:

```text
-c             Encrypt a clear message read from standard input.
-d             Decrypt a message read from standard input.
-b             Use one-block mode for XOR, AES, and PGP workflows.
-g P Q         RSA only: generate keys from the prime parameters P and Q.
-h, --help     Display the usage text.
key            Hexadecimal key used for encryption or decryption.
```

## Documentation

- [CLI reference](docs/cli_reference.md)
- [Architecture](docs/architecture.md)
- [Cryptographic design](docs/cryptography.md)