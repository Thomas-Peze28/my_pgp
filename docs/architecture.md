# Architecture

[<- Back to README](../README.md)

MyPGP follows a small command-line architecture. Argument parsing, input/output, dispatching, and cryptographic computation are kept separate so that each part can be tested independently.

## Repository layout

```text
.
├── Makefile
├── README.md
├── my_pgp                  # Generated executable wrapper
├── src/
│   ├── main.py             # Process entry point and exit-code handling
│   ├── cli/
│   │   ├── controller.py   # Operation dispatcher
│   │   ├── io_handler.py   # Standard input/output handling
│   │   └── parser.py       # Command-line validation
│   ├── cipher/
│   │   └── xor.py          # XOR cipher implementation
│   └── utils/
│       └── endian.py       # Integer, byte, and hexadecimal conversions
└── tests/
    ├── test_endian.py
    ├── test_parser.py
    └── test_xor.py
```

## Execution flow

```text
sys.argv
   |
   v
parse_arguments()
   |
   v
Controller.dispatch(args)
   |
   +--> run_xor()    --> XorCipher
   +--> run_aes()    --> AES implementation
   +--> run_rsa()    --> RSA implementation
   +--> run_pgp_xor()
   +--> run_pgp_aes()
   |
   v
IOHandler writes stdout or stderr
```

`src/main.py` owns the process boundary. It parses arguments, dispatches the selected operation, returns `0` on success, and converts any exception into an error message with exit code `84`.

## Controller / Dispatcher

`Controller.dispatch` is the single routing point for cryptographic systems. It maps the parsed `crypto_system` value to one handler method, such as `run_xor` or `run_aes`. This keeps CLI selection separate from the implementation of each cryptographic system and gives every future system the same entry contract: receive parsed arguments and perform one operation.

Adding a system should therefore involve registering a handler in the dispatch table and implementing the corresponding cryptographic layer. The dispatcher should not contain key generation, block processing, or stream formatting logic.

## Responsibility boundaries

### `io_handler.py`

`IOHandler` is responsible only for standard input and output:

- Reading binary data from `stdin.buffer`.
- Reading a single line for block mode and decryption.
- Reading the complete binary stream for stream encryption.
- Writing formatted hexadecimal output with a newline.
- Writing decrypted raw bytes without adding formatting.

It should not validate cryptographic keys or perform encryption.

### `parser.py`

The parser validates `sys.argv` before an operation starts. It checks the supported system, mode conflicts, required key, `-b`, and the RSA-only `-g P Q` form. It returns a small `cliArgs` object consumed by the controller.

The parser should remain concerned with syntax and CLI-level validation. Prime testing, key-size checks, and cryptographic validity belong to their respective cipher modules.

### `cipher/`

Cipher modules contain pure cryptographic engines. They should receive bytes and explicit parameters, return values, and raise meaningful exceptions for invalid data. They should not read from standard input, write to standard output, inspect `sys.argv`, or decide process exit codes.

This boundary makes the cryptographic code reusable and lets unit tests exercise algorithms without spawning the CLI.

### `utils/`

Utilities such as endian conversion provide deterministic, low-level transformations shared by cipher modules. They should stay independent from CLI concerns.

## Testing strategy

- Test parsers with valid and invalid argument arrays.
- Test cipher primitives with known vectors and boundary sizes.
- Test I/O and controller integration separately when new systems are added.
- Preserve the existing `unittest` discovery command: `make tests_run`.
