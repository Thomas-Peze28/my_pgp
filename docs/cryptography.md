# Cryptographic Design

[<- Back to README](../README.md)

MyPGP is structured around a layered cryptographic design. The payload cipher handles the message, while a future hybrid layer will protect the payload key with RSA.

## XOR

The implemented XOR engine supports two modes:

- **Block mode:** the message and key have exactly the same byte length. Each byte is XORed with the corresponding key byte.
- **Stream mode:** the message is split into chunks matching the key length. An incomplete final chunk is padded with zero bytes before XOR.

The CLI accepts hexadecimal keys. Encrypted output is also hexadecimal so it can be safely transported as text. The low-level implementation lives in `src/cipher/xor.py`; conversion details are delegated to `src/utils/endian.py`.

```python
from cipher.xor import XorCipher

ciphertext = XorCipher.cipher_stream(b"12345678", "57686174")
plaintext = XorCipher.decipher_stream(ciphertext, "57686174")
```

For production use, a repeated XOR key is not cryptographically secure. It is implemented here as a learning-oriented symmetric primitive and as the payload cipher for the planned `pgp-xor` workflow.

## AES

The planned AES module should provide a standard AES-128 implementation with an explicit mode and padding policy. The implementation should:

1. Validate a 16-byte key.
2. Define the block mode, preferably an authenticated mode such as GCM for a complete application.
3. Treat nonce or IV handling as part of the ciphertext format.
4. Reject malformed padding, authentication tags, and ciphertext sizes.
5. Expose pure byte-oriented methods to the controller.

The `aes` controller entry point is currently a placeholder and must not be presented as production encryption.

## RSA

The planned RSA module should support key generation from the `P` and `Q` parameters accepted by `rsa -g P Q`, then expose public-key encryption and private-key decryption. It must validate that:

- `P` and `Q` are valid, distinct primes.
- The modulus and exponent satisfy the selected RSA scheme.
- Messages fit the chosen padding scheme.
- Generated keys are serialized in a documented format.

Textbook RSA must not be used for application encryption. OAEP should be preferred for encryption, and all randomness should come from a secure system source.

## Hybrid PGP workflows

A hybrid workflow encrypts the message with a fresh symmetric session key and encrypts that session key with RSA:

1. Generate a random session key.
2. Encrypt the payload with XOR or AES.
3. Encrypt or wrap the session key with the recipient's RSA public key.
4. Serialize the algorithm identifier, wrapped key, nonce or metadata, and payload.
5. During decryption, recover the session key with the RSA private key and decrypt the payload.

`pgp-xor` should use the XOR payload engine, while `pgp-aes` should use AES. Both handlers should share serialization and key-management helpers without duplicating controller or I/O code.
