import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from cipher.rsa import RsaCipher
from utils.endian import EndianUtils


class TestRsaKeyGeneration(unittest.TestCase):
    """Tests unitaires pour la génération de paires de clés RSA (-g P Q)."""

    def test_subject_small_keys_example(self):
        """Exemple officiel page 8 du sujet avec des nombres premiers 8 bits (P=d3, Q=e3)."""
        e_hex, d_hex, n_hex = RsaCipher.generate_keys("d3", "e3")

        self.assertEqual(e_hex, "0101")
        self.assertEqual(d_hex, "9d5b")
        self.assertEqual(n_hex, "19bb")

    def test_subject_large_keys_256bit_example(self):
        """Exemple officiel page 8 du sujet avec des nombres premiers 256 bits."""
        p_hex = "4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1"
        q_hex = "bb3ca1e126f7c8751bd81bc8daa226494efb3d128f72ed9f6cacbe96e14166cb"

        expected_e_hex = "010001"
        expected_n_hex = (
            "c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de"
            "139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3"
        )
        expected_d_hex = (
            "81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a"
            "11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209"
        )

        e_hex, d_hex, n_hex = RsaCipher.generate_keys(p_hex, q_hex)

        self.assertEqual(e_hex, expected_e_hex)
        self.assertEqual(n_hex, expected_n_hex)
        self.assertEqual(d_hex, expected_d_hex)

    def test_appendix_32bit_primes_carmichael_rule(self):
        """Test avec des nombres premiers 32 bits issus de l'annexe page 12 (13d3c01d et 0b1e8a1e)."""
        p_hex = "13d3c01d"
        q_hex = "0b1e8a1e"

        e_hex, d_hex, n_hex = RsaCipher.generate_keys(p_hex, q_hex)

        # 65537 est inférieur à lambda(N) et premier avec lui -> e sélectionné = 010001
        self.assertEqual(e_hex, "010001")
        self.assertEqual(d_hex, "9b938511ad7006")
        self.assertEqual(n_hex, "d14b43e22ba68c03")

    def test_mathematical_properties_of_generated_keys(self):
        """Vérifie que la relation e * d = 1 mod lambda(N) est strictement respectée."""
        p_hex = "e9"
        q_hex = "f1"

        e_hex, d_hex, n_hex = RsaCipher.generate_keys(p_hex, q_hex)

        p = EndianUtils.hex_to_int(p_hex)
        q = EndianUtils.hex_to_int(q_hex)
        e = EndianUtils.hex_to_int(e_hex)
        d = EndianUtils.hex_to_int(d_hex)
        n = EndianUtils.hex_to_int(n_hex)

        # Vérification du module
        self.assertEqual(n, p * q)

        # Vérification de l'indicatrice de Carmichael
        carmichael_n = RsaCipher.lcm(p - 1, q - 1)
        self.assertEqual((e * d) % carmichael_n, 1)

    def test_fermat_prime_fallback_selection(self):
        """Vérifie que l'algorithme sélectionne bien un Fermat inférieur quand 65537 est trop grand."""
        # Pour p=d3 (211) et q=e3 (227), lambda(N) = 23730
        # 65537 > 23730, le plus grand Fermat valide est 257 (0x0101)
        e_hex, _, _ = RsaCipher.generate_keys("d3", "e3")
        e = EndianUtils.hex_to_int(e_hex)
        self.assertEqual(e, 257)

    def test_invalid_identical_primes(self):
        """Doit lever une exception si P et Q sont identiques."""
        with self.assertRaises(ValueError):
            RsaCipher.generate_keys("d3", "d3")

    def test_invalid_primes_lower_than_two(self):
        """Doit lever une exception si P ou Q est inférieur ou égal à 1."""
        with self.assertRaises(ValueError):
            RsaCipher.generate_keys("01", "d3")
        with self.assertRaises(ValueError):
            RsaCipher.generate_keys("00", "e3")

    def test_appendix_1024bit_primes_performance(self):
        """Test avec les deux clés de 1024 bits de l'annexe page 12 (module de 2048 bits)."""
        p_hex = (
            "d7c9d58c694fe7ad5d77d888c98d71e7f6a58b4f4dc90582668fd28c0bc20f51"
            "c667ba7b70cb94842006eb5b223065346f7a6bb307ef572fee882c8ef420410b"
            "8b8fa8278ae6a300e63123b28ba1d47259bc308827fcd509585bcee1d98b461f"
            "9eff9c20559540b8c0d6036eff7caf0107d935ecefd5faab87b802bf74c041c8"
        )
        q_hex = (
            "e9dfe6b53248c4dc0f391fdda5694bd9f68e111dac5e921a942a157ec92431dc"
            "4833e1a327d36cebcc4ac9b76f2ac2a643db8a04c14963759a800f75915de3ff"
            "beccf86118923b388b352f7e3d20edfd5bb6609fd0b6416da6a56050b000ae9e"
            "14065f06f46ccfaa84c755689e8d95525bb1de8b8a43d380f4db68baac92e0bf"
        )

        e_hex, d_hex, n_hex = RsaCipher.generate_keys(p_hex, q_hex)

        # e doit être 65537 (010001) car il est bien inférieur à lambda(N)
        self.assertEqual(e_hex, "010001")
        self.assertEqual(len(n_hex), 512)  # 2048 bits = 256 octets = 512 caractères hex

    def test_cli_integration_format(self):
        """Vérifie le format textuel complet attendu par la CLI (tiret séparateur)."""
        e_hex, d_hex, n_hex = RsaCipher.generate_keys("d3", "e3")
        pub_line = f"public key: {e_hex}-{n_hex}"
        priv_line = f"private key: {d_hex}-{n_hex}"

        self.assertEqual(pub_line, "public key: 0101-19bb")
        self.assertEqual(priv_line, "private key: 9d5b-19bb")


if __name__ == "__main__":
    unittest.main()
