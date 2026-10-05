import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from cipher.rsa import RsaCipher


class TestRsaCipher(unittest.TestCase):
    """Tests unitaires pour le chiffrement et le déchiffrement RSA."""

    def setUp(self):
        # Clés 8 bits officielles
        self.pub_8bit = "0101-19bb"
        self.priv_8bit = "9d5b-19bb"

        # Clés 256 bits officielles
        self.pub_256bit = (
            "010001-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de"
            "139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3"
        )
        self.priv_256bit = (
            "81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a"
            "11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209-"
            "c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de"
            "139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3"
        )

    def test_subject_example_8bit_cipher(self):
        """Vérifie le vecteur officiel b'WF' -> '8f84'."""
        ciphered = RsaCipher.cipher(b"WF", self.pub_8bit)
        self.assertEqual(ciphered, "8f84")

    def test_subject_example_8bit_decipher(self):
        """Vérifie le déchiffrement '8f84' -> b'WF'."""
        deciphered = RsaCipher.decipher("8f84", self.priv_8bit)
        self.assertEqual(deciphered, b"WF")

    def test_subject_example_256bit_cipher(self):
        """Vérifie le chiffrement du texte officiel sur 256 bits."""
        message = b"The night is dark and full of terrors"
        expected_hex = (
            "445b349e7318ad6af16b0bbb718be88ba1c41751f95751cd58857f88fe31f970"
            "405c6ec3f16d79172543bf4e571b5596d212f3e79cd08ef14abd244e325b80"
        )
        ciphered = RsaCipher.cipher(message, self.pub_256bit)
        self.assertEqual(ciphered, expected_hex)

    def test_subject_example_256bit_decipher(self):
        """Vérifie le déchiffrement du texte officiel sur 256 bits."""
        ciphered_hex = (
            "445b349e7318ad6af16b0bbb718be88ba1c41751f95751cd58857f88fe31f970"
            "405c6ec3f16d79172543bf4e571b5596d212f3e79cd08ef14abd244e325b80"
        )
        deciphered = RsaCipher.decipher(ciphered_hex, self.priv_256bit)
        self.assertEqual(deciphered, b"The night is dark and full of terrors")

    def test_message_too_large_for_modulus(self):
        """Un message m >= N doit lever une ValueError."""
        # Avec le module 19bb (47897), un message de 3 octets dépasse systématiquement N
        with self.assertRaises(ValueError):
            RsaCipher.cipher(b"XYZ", self.pub_8bit)

    def test_invalid_key_format(self):
        """Une clé mal formée (sans tiret ou incomplète) doit lever une ValueError."""
        with self.assertRaises(ValueError):
            RsaCipher.cipher(b"WF", "0101 19bb")
        with self.assertRaises(ValueError):
            RsaCipher.decipher("8f84", "invalidkey")


if __name__ == "__main__":
    unittest.main()
