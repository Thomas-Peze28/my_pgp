import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from cipher.xor import XorCipher


class TestXorBlock(unittest.TestCase):

    def test_subject_block_example_cipher_and_decipher(self):
        # Exemple officiel page 4 du sujet
        key_hex = "576861742069732064656164206d6179206e6576657220646965"
        message = b"You know nothing, Jon Snow"
        expected_cipher_hex = "20070f2700071c6a4449060a490515164e4e12190b190011063c"

        ciphered = XorCipher.cipher_block(message, key_hex)
        self.assertEqual(ciphered, expected_cipher_hex)

        deciphered = XorCipher.decipher_block(ciphered, key_hex)
        self.assertEqual(deciphered, message)

    def test_block_size_mismatch_too_short(self):
        key_hex = "57686174"  # 4 octets
        message = b"Hi"  # 2 octets
        with self.assertRaises(ValueError):
            XorCipher.cipher_block(message, key_hex)

    def test_block_size_mismatch_too_long(self):
        key_hex = "57686174"  # 4 octets
        message = b"Hello World"  # 11 octets
        with self.assertRaises(ValueError):
            XorCipher.cipher_block(message, key_hex)

    def test_decipher_block_size_mismatch(self):
        key_hex = "57686174"  # 4 octets
        with self.assertRaises(ValueError):
            XorCipher.decipher_block("0102", key_hex)  # 2 octets chiffrés


class TestXorStream(unittest.TestCase):

    def test_stream_with_padding_zeroes(self):
        # Clé de 4 octets ("What") et message de 26 octets
        # 26 % 4 = 2 -> 2 octets 0x00 ajoutés en padding (total = 28 octets = 7 blocs de 4)
        key_hex = "57686174"
        message = b"You know nothing, Jon Snow"
        expected_hex = "771d0e2d20070f1f23070f543006081c38224158393b411a5768161b"

        ciphered = XorCipher.cipher_stream(message, key_hex)
        self.assertEqual(ciphered, expected_hex)
        self.assertEqual(len(ciphered), 28 * 2)

        deciphered = XorCipher.decipher_stream(ciphered, key_hex)
        self.assertEqual(deciphered, message + b"\x00\x00")

    def test_stream_single_block_matches_block_mode(self):
        # Un message d'exactement la taille de la clé doit donner le même résultat en bloc et stream
        key_hex = "576861742069732064656164206d6179206e6576657220646965"
        message = b"You know nothing, Jon Snow"
        expected_cipher_hex = "20070f2700071c6a4449060a490515164e4e12190b190011063c"

        ciphered_stream = XorCipher.cipher_stream(message, key_hex)
        ciphered_block = XorCipher.cipher_block(message, key_hex)

        self.assertEqual(ciphered_stream, expected_cipher_hex)
        self.assertEqual(ciphered_stream, ciphered_block)
        self.assertEqual(XorCipher.decipher_stream(ciphered_stream, key_hex), message)

    def test_stream_exact_multiple_no_padding(self):
        key_hex = "57686174"  # 4 octets
        message = b"12345678"  # 8 octets (2 blocs complets)

        ciphered = XorCipher.cipher_stream(message, key_hex)
        self.assertEqual(len(ciphered), 8 * 2)

        deciphered = XorCipher.decipher_stream(ciphered, key_hex)
        self.assertEqual(deciphered, message)

    def test_stream_empty_key_raises_error(self):
        with self.assertRaises(ValueError):
            XorCipher.cipher_stream(b"ValidMessage", "")
        with self.assertRaises(ValueError):
            XorCipher.decipher_stream("00", "")

    def test_stream_invalid_ciphertext_length(self):
        key_hex = "57686174"  # 4 octets (8 hex chars)
        # Longueur non multiple du bloc (ex : 6 hex chars = 3 octets) -> rejet strict
        with self.assertRaises(ValueError):
            XorCipher.decipher_stream("010203040506", key_hex)


if __name__ == "__main__":
    unittest.main()
