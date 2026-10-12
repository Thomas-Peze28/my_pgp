# Architecture

[<- Back to README](../README.md)

## Repository layout

```text
.
├── Makefile
├── src/
│   ├── main.py             # Entry point, exit codes (0 / 84)
│   ├── cli/
│   │   ├── parser.py       # Argument validation
│   │   ├── controller.py   # Dispatch and per-system handlers
│   │   └── io_handler.py   # stdin / stdout
│   ├── cipher/
│   │   ├── xor.py          # XorCipher
│   │   ├── aes.py          # AesCipher
│   │   └── rsa.py          # RsaCipher
│   └── utils/
│       └── endian.py       # Hex / bytes / int conversions
├── tests/
└── docs/
```

## Execution flow

```text
parse_arguments() --> Controller.dispatch()
                        ├── run_xor      --> XorCipher
                        ├── run_aes      --> AesCipher
                        ├── run_rsa      --> RsaCipher
                        ├── run_pgp_xor  --> RsaCipher + XorCipher
                        └── run_pgp_aes  --> RsaCipher + AesCipher
```

Any exception is caught in `main.py`: message on stderr, exit code `84`.

## Responsibilities

| Module | Does | Does not |
| --- | --- | --- |
| `parser.py` | check system, modes, key, `-b`, `-g P Q` | cryptographic checks |
| `controller.py` | read input, call the cipher, write output | cryptographic computation |
| `io_handler.py` | read stdin (one line or full stream), write stdout | validate data |
| `cipher/` | pure algorithms, raise `ValueError` on bad input | I/O, exit codes |

`_xor_process` and `_aes_process` handle block/stream mode for a symmetric cipher. They are shared by the plain and PGP handlers.

`XorCipher` and `AesCipher` expose the same methods: `cipher_block`, `decipher_block`, `cipher_stream`, `decipher_stream`.

## Tests

`make tests_run` (`unittest`).

- Unit tests: `test_xor`, `test_aes`, `test_rsa_*`, `test_endian`, `test_parser`.
- Integration tests (run the real CLI): `test_pgp_xor`, `test_pgp_aes`, CLI part of `test_aes`.
- Reference values: subject examples and FIPS-197 for AES.
