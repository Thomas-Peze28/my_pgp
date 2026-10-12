# Cryptographic Design

[<- Back to README](../README.md)

All algorithms are implemented by hand and follow the subject's formats.

- **Numbers** (keys, RSA values, ciphertexts): hexadecimal, little endian.
- **Messages**: sequences of bytes.

## XOR — `cipher/xor.py`

- **Block (`-b`)**: message and key have the same length. Output byte `i` = `message[n-1-i] XOR key[i]` (subject convention).
- **Stream**: blocks of the key length, last block padded with zeros.

**Limit:** a repeated key is weak, `message XOR ciphertext` reveals it.

## AES-128 — `cipher/aes.py`

16-byte blocks, 16-byte key, 10 rounds. The state is a 4x4 matrix filled column by column.

| Step | Role | Inverse |
| --- | --- | --- |
| `add_round_key` | XOR with the round key | itself |
| `sub_bytes` | S-box substitution (non-linear) | `inv_sub_bytes` |
| `shift_rows` | rotate row `r` left by `r` | `inv_shift_rows` |
| `mix_columns` | mix each column (`MIX_MATRIX`, `gmul`) | `inv_mix_columns` |

- `key_expansion`: 11 round keys from the key (`RotWord`, `SubWord`, `RCON`).
- `encrypt_block` / `decrypt_block`: standard AES, tested against FIPS-197.
- **Subject convention** (`swap_words`): key and ciphertext have their bytes reversed in each 4-byte group. The clear message is not converted.
- **Stream**: 16-byte blocks encrypted independently (ECB), last block padded with zeros.

**Limit:** ECB leaks patterns (identical blocks give identical output).

## RSA — `cipher/rsa.py`

Key generation (`-g P Q`):

1. `n = p * q`
2. `λ(n) = lcm(p - 1, q - 1)` (Carmichael)
3. `e` = largest Fermat prime (65537, 257, 17, 5, 3) smaller than `λ(n)` and coprime with it
4. `d = e⁻¹ mod λ(n)`

Public key `e-n`, private key `d-n`. The message is read as a little-endian number `m < n`:

- encrypt: `c = m^e mod n`
- decrypt: `m = c^d mod n`

**Limit:** textbook RSA, no padding (OAEP would be needed in practice).

## PGP — `run_pgp_xor` / `run_pgp_aes`

```text
-c  key = SYM_KEY:PUBLIC    line 1 = RSA(SYM_KEY)    line 2 = XOR/AES(message)
-d  key = RSA(SYM_KEY):PRIVATE    stdin = line 2     output = message
```

RSA drops the leading zeros of a number, so the decrypted symmetric key is padded back with zeros: to 16 bytes for AES, to the message size for XOR in block mode.
