from utils.endian import EndianUtils


class XorCipher:
    """A class for performing XOR encryption and decryption."""

    @staticmethod
    def xor_block(data: bytes, key: bytes) -> bytes:
        """Encrypts the given data using XOR cipher with the provided key.

        @param data: The data to be encrypted as bytes.
        @param key: The encryption key as bytes.
        @return: The encrypted data as bytes.
        """
        if len(data) != len(key):
            raise ValueError(
                f"Data and key must be of the same length for XOR encryption. "
                f"(data: {len(data)}, key: {len(key)})"
            )
        return bytes(d ^ k for d, k in zip(data, key))

    @staticmethod
    def cipher_block(message: bytes, key_hex: str) -> str:
        """Encrypts a single block of message using XOR with the given key.

        @param message: The message block to be encrypted as bytes.
        @param key_hex: The encryption key as a little-endian hexadecimal string.
        @return: The encrypted message as a little-endian hexadecimal string.
        """
        key_bytes_len = len(key_hex.strip()) // 2
        if len(message) != key_bytes_len:
            raise ValueError(
                f"Data and key must be of the same length for XOR encryption. "
                f"(data: {len(message)}, key: {key_bytes_len})"
            )

        m_int = EndianUtils.bytes_to_int(message)
        k_int = EndianUtils.hex_to_int(key_hex)
        c_int = m_int ^ k_int

        return EndianUtils.int_to_hex(c_int, length=key_bytes_len)

    @staticmethod
    def decipher_block(ciphered_hex: str, key_hex: str) -> bytes:
        """Decrypts a single block of ciphered text using XOR with the given key.

        @param ciphered_hex: The encrypted block as a little-endian hexadecimal string.
        @param key_hex: The decryption key as a little-endian hexadecimal string.
        @return: The decrypted message block as raw bytes.
        """
        key_bytes_len = len(key_hex.strip()) // 2
        ciphered_len = len(ciphered_hex.strip()) // 2
        if ciphered_len != key_bytes_len:
            raise ValueError(
                f"Data and key must be of the same length for XOR decryption. "
                f"(data: {ciphered_len}, key: {key_bytes_len})"
            )

        c_int = EndianUtils.hex_to_int(ciphered_hex)
        k_int = EndianUtils.hex_to_int(key_hex)
        m_int = c_int ^ k_int

        return EndianUtils.int_to_bytes(m_int, length=key_bytes_len)

    @staticmethod
    def cipher_stream(message: bytes, key_hex: str) -> str:
        """Encrypts the given message in stream mode by chunks matching the key size.

        If the last block is smaller than the key, it is padded with zero bytes.

        @param message: The clear message as bytes.
        @param key_hex: The key as a little-endian hexadecimal string.
        @return: The encrypted message as a hexadecimal string.
        """
        key_bytes = EndianUtils.hex_to_bytes(key_hex)
        key_len = len(key_bytes)
        if key_len == 0:
            raise ValueError("Key cannot be empty for XOR encryption.")

        remainder = len(message) % key_len
        if remainder != 0:
            message += b"\x00" * (key_len - remainder)

        chunks = []
        for i in range(0, len(message), key_len):
            block = message[i : i + key_len]
            chunks.append(XorCipher.cipher_block(block, key_hex))

        return "".join(chunks)

    @staticmethod
    def decipher_stream(ciphered_hex: str, key_hex: str) -> bytes:
        """Decrypts the given ciphered stream by chunks matching the key size.

        @param ciphered_hex: The ciphered message as a hexadecimal string.
        @param key_hex: The key as a little-endian hexadecimal string.
        @return: The decrypted bytes.
        """
        key_bytes = EndianUtils.hex_to_bytes(key_hex)
        key_len = len(key_bytes)
        if key_len == 0:
            raise ValueError("Key cannot be empty for XOR decryption.")

        ciphered_bytes = EndianUtils.hex_to_bytes(ciphered_hex)
        if len(ciphered_bytes) % key_len != 0:
            raise ValueError("Cipher text length must be a multiple of the key length.")

        block_hex_len = key_len * 2
        result = bytearray()
        for i in range(0, len(ciphered_hex), block_hex_len):
            chunk_hex = ciphered_hex[i : i + block_hex_len]
            result.extend(XorCipher.decipher_block(chunk_hex, key_hex))

        return bytes(result)
