from utils.endian import EndianUtils

FERMAT_PRIMES = (65537, 257, 17, 5, 3)


class RsaCipher:
    """A class for performing RSA encryption and decryption."""

    @staticmethod
    def gcd(a: int, b: int) -> int:
        """Compute the greatest common divisor (GCD) of two integers using the Euclidean algorithm."""

        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def lcm(a: int, b: int) -> int:
        """Compute the least common multiple (LCM) of two integers."""
        return (a * b) // RsaCipher.gcd(a, b)

    @staticmethod
    def generate_keys(p_hex: str, q_hex: str) -> tuple[str, str, str]:
        """Generate RSA public and private keys from two prime numbers in hexadecimal little-endian format.

        @param p_hex: A prime number in hexadecimal format.
        @param q_hex: Another prime number in hexadecimal format.
        @return: A tuple containing the public key (e, n), private key (d, n), and modulus (n) as hexadecimal strings.
        """

        p = EndianUtils.hex_to_int(p_hex)
        q = EndianUtils.hex_to_int(q_hex)

        if p <= 1 or q <= 1 or p == q:
            raise ValueError("p and q must be distinct prime numbers greater than 1.")

        n = p * q
        carmichael_n = RsaCipher.lcm(p - 1, q - 1)

        e = None
        for prime in FERMAT_PRIMES:
            if prime < carmichael_n and RsaCipher.gcd(prime, carmichael_n) == 1:
                e = prime
                break
        if e is None:
            raise ValueError("No valid Fermat prime found for e.")

        d = pow(e, -1, carmichael_n)

        e_hex = EndianUtils.int_to_hex(e)
        d_hex = EndianUtils.int_to_hex(d)
        n_hex = EndianUtils.int_to_hex(n)

        return e_hex, d_hex, n_hex

    @staticmethod
    def cipher(message: bytes, key_str: str) -> str:
        """Cipher a message using public key formatted as '<e>-<N>'.

        @param message: Raw byte sequence to encrypt.
        @param key_str: Public key in format '<e>-<N>'.
        @return: Ciphered number in little-endian hex.
        """
    
        parts = key_str.strip().split("-")
        if len(parts) != 2:
            raise ValueError("RSA key must follow the '<e>-<N>' format.")

        e = EndianUtils.hex_to_int(parts[0])
        n = EndianUtils.hex_to_int(parts[1])

        message_int = EndianUtils.bytes_to_int(message, byteorder="little")
        if message_int >= n:
            raise ValueError("Message is too large for the RSA modulus.")

        ciphered_int = pow(message_int, e, n)
        return EndianUtils.int_to_hex(ciphered_int)

    @staticmethod
    def decipher(ciphered_hex: str, key_str: str) -> bytes:
        """Decipher a number using private key formatted as '<d>-<N>'.

        @param ciphered_hex: Ciphered number in little-endian hex.
        @param key_str: Private key in format '<d>-<N>'.
        @return: Clear message bytes.
        """
    
        parts = key_str.strip().split("-")
        if len(parts) != 2:
            raise ValueError("RSA key must follow the '<d>-<N>' format.")

        d = EndianUtils.hex_to_int(parts[0])
        n = EndianUtils.hex_to_int(parts[1])

        ciphered_int = EndianUtils.hex_to_int(ciphered_hex)
        message_int = pow(ciphered_int, d, n)

        return EndianUtils.int_to_bytes(message_int, byteorder="little")
