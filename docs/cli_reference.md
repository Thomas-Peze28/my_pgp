# CLI Reference

[<- Back to README](../README.md)

## Syntax

```bash
./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]
```

Build with `make`. The message is read from standard input.

## Crypto systems

| System | Purpose | Key format |
| --- | --- | --- |
| `xor` | XOR symmetric encryption | `KEY` (hexadecimal) |
| `aes` | AES-128 symmetric encryption | `KEY` (hexadecimal, exactly 16 bytes) |
| `rsa` | RSA key generation, encryption and decryption | `E-N` to encrypt, `D-N` to decrypt |
| `pgp-xor` | XOR payload, XOR key protected by RSA | `SYMMETRIC_KEY:RSA_KEY` |
| `pgp-aes` | AES payload, AES key protected by RSA | `SYMMETRIC_KEY:RSA_KEY` |

## Modes and options

| Option | Meaning |
| --- | --- |
| `-c` | Encrypt clear input. |
| `-d` | Decrypt ciphered input. |
| `-b` | Process one block. The message and the symmetric key must have the same length. |
| `-g P Q` | Generate RSA keys from `P` and `Q`; valid only with `rsa`. |
| `-h`, `--help` | Print the usage text and exit successfully. |

`-c` and `-d` are exclusive. Flags can be combined (`-cb`).

## Data formats

- **Numbers** (keys, ciphertexts): hexadecimal, little endian (`0x01234567` is written `67452301`).
- **`-b`**: one line, final newline removed; message size = key size (16 bytes for AES).
- **Stream**: whole input, blocks padded with zeros; decryption keeps the padding zeros.
- **RSA**: one line; the message must be smaller than `N`.
- **PGP**: `-c` prints 2 lines (encrypted symmetric key, encrypted message). `-d` takes `ENCRYPTED_SYMMETRIC_KEY:D-N` as key and the encrypted message on stdin.

## Examples

Examples from the subject, all covered by the tests.

### XOR

```bash
$> echo "You know nothing, Jon Snow" > message
$> ./my_pgp xor -c -b 576861742069732064656164206d6179206e6576657220646965 < message > ciphered
$> cat ciphered
20070f2700071c6a4449060a490515164e4e12190b190011063c
$> ./my_pgp xor -d -b 576861742069732064656164206d6179206e6576657220646965 < ciphered
You know nothing, Jon Snow
```

### AES

```bash
$> echo "All men must die" > message
$> ./my_pgp aes -c -b 57696e74657220697320636f6d696e67 < message > ciphered
$> cat ciphered
744ce22c385958348f0df26eceb62eef
$> ./my_pgp aes -d -b 57696e74657220697320636f6d696e67 < ciphered
All men must die
```

### RSA

```bash
$> ./my_pgp rsa -g d3 e3
public key: 0101-19bb
private key: 9d5b-19bb
$> echo "WF" | ./my_pgp rsa -c 0101-19bb
8f84
$> echo "8f84" | ./my_pgp rsa -d 9d5b-19bb
WF
```

### PGP-AES

`$PUBLIC` / `$PRIVATE`: the 256-bit key pair from the subject.

```bash
$> echo "All men must die" | ./my_pgp pgp-aes -c -b 57696e74657220697320636f6d696e67:$PUBLIC
97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e6916afe5c5f9b9d6eaa0a870374b686f1a024f9bbb88c23c766654579339caf55afd149d41d
744ce22c385958348f0df26eceb62eef
$> echo "744ce22c385958348f0df26eceb62eef" | ./my_pgp pgp-aes -d -b 97f2af4c...afd149d41d:$PRIVATE
All men must die
```

`pgp-xor` works the same way, with an XOR key instead of an AES key.

### Help

```bash
./my_pgp --help
```

## Errors

Exit code `0` on success. On any error (arguments, key, block size, input): message on stderr and exit code `84`.
