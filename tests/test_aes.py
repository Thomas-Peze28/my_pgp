import os
import subprocess
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from cipher.aes import AesCipher, SBOX, INV_SBOX

MAIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "main.py"))

# Vecteurs officiels FIPS-197, annexe B
FIPS_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
FIPS_INPUT = "3243f6a8885a308d313198a2e0370734"
FIPS_OUTPUT = "3925841d02dc09fbdc118597196a0b32"

# Vecteurs officiels FIPS-197, annexe C.1
C1_KEY = "000102030405060708090a0b0c0d0e0f"
C1_INPUT = "00112233445566778899aabbccddeeff"
C1_OUTPUT = "69c4e0d86a7b0430d8cdb78070b4c55a"

# Exemple officiel page 5 du sujet
SUBJECT_KEY = "57696e74657220697320636f6d696e67"
SUBJECT_MESSAGE = b"All men must die"
SUBJECT_CIPHER = "744ce22c385958348f0df26eceb62eef"


def apply(func, hex_state: str) -> str:
    """Applique une étape AES à un état donné en hex et renvoie le résultat en hex."""
    state = AesCipher.bytes_to_state(bytes.fromhex(hex_state))
    return AesCipher.state_to_bytes(func(state)).hex()


def run_pgp(args, stdin: bytes) -> subprocess.CompletedProcess:
    """Lance le programme comme la CLI (./my_pgp ...) et renvoie le résultat."""
    return subprocess.run(
        [sys.executable, MAIN, *args], input=stdin, capture_output=True
    )


class TestAesState(unittest.TestCase):
    """Tests de la conversion octets <-> matrice 4x4."""

    def test_bytes_are_stored_column_by_column(self):
        """Les octets remplissent la matrice colonne par colonne."""
        state = AesCipher.bytes_to_state(bytes(range(16)))
        self.assertEqual(state[0], [0, 4, 8, 12])
        self.assertEqual(state[3], [3, 7, 11, 15])

    def test_state_round_trip(self):
        """bytes_to_state puis state_to_bytes redonne les mêmes octets."""
        data = bytes.fromhex(FIPS_INPUT)
        self.assertEqual(AesCipher.state_to_bytes(AesCipher.bytes_to_state(data)), data)


class TestAesSteps(unittest.TestCase):
    """Tests de chaque étape d'un tour, avec les valeurs du 1er tour de FIPS-197 (annexe B)."""

    def test_add_round_key(self):
        """XOR de l'entrée avec la clé : début du 1er tour."""
        state = AesCipher.bytes_to_state(bytes.fromhex(FIPS_INPUT))
        key = AesCipher.bytes_to_state(bytes.fromhex(FIPS_KEY))
        result = AesCipher.state_to_bytes(AesCipher.add_round_key(state, key)).hex()
        self.assertEqual(result, "193de3bea0f4e22b9ac68d2ae9f84808")

    def test_sub_bytes(self):
        """Substitution par la S-box."""
        result = apply(AesCipher.sub_bytes, "193de3bea0f4e22b9ac68d2ae9f84808")
        self.assertEqual(result, "d42711aee0bf98f1b8b45de51e415230")

    def test_shift_rows(self):
        """Décalage de la ligne r de r cases vers la gauche."""
        result = apply(AesCipher.shift_rows, "d42711aee0bf98f1b8b45de51e415230")
        self.assertEqual(result, "d4bf5d30e0b452aeb84111f11e2798e5")

    def test_mix_columns(self):
        """Mélange de chaque colonne."""
        result = apply(AesCipher.mix_columns, "d4bf5d30e0b452aeb84111f11e2798e5")
        self.assertEqual(result, "046681e5e0cb199a48f8d37a2806264c")

    def test_gmul(self):
        """Multiplication dans GF(2^8) : exemple FIPS-197 et cas de dépassement."""
        self.assertEqual(AesCipher.gmul(0x57, 0x13), 0xFE)
        self.assertEqual(AesCipher.gmul(0x80, 2), 0x1B)
        self.assertEqual(AesCipher.gmul(0x42, 1), 0x42)


class TestAesInverseSteps(unittest.TestCase):
    """Chaque étape inverse doit annuler l'étape correspondante."""

    def test_sbox_tables(self):
        """La S-box contient 256 valeurs distinctes et INV_SBOX est son inverse."""
        self.assertEqual(sorted(SBOX), list(range(256)))
        for x in range(256):
            self.assertEqual(INV_SBOX[SBOX[x]], x)

    def test_inv_sub_bytes(self):
        result = apply(AesCipher.inv_sub_bytes, "d42711aee0bf98f1b8b45de51e415230")
        self.assertEqual(result, "193de3bea0f4e22b9ac68d2ae9f84808")

    def test_inv_shift_rows(self):
        result = apply(AesCipher.inv_shift_rows, "d4bf5d30e0b452aeb84111f11e2798e5")
        self.assertEqual(result, "d42711aee0bf98f1b8b45de51e415230")

    def test_inv_mix_columns(self):
        result = apply(AesCipher.inv_mix_columns, "046681e5e0cb199a48f8d37a2806264c")
        self.assertEqual(result, "d4bf5d30e0b452aeb84111f11e2798e5")


class TestAesKeyExpansion(unittest.TestCase):
    """Tests de la génération des clés de tour (FIPS-197, annexe A.1)."""

    def setUp(self):
        self.round_keys = AesCipher.key_expansion(bytes.fromhex(FIPS_KEY))

    def test_eleven_round_keys(self):
        self.assertEqual(len(self.round_keys), 11)

    def test_round_key_0_is_cipher_key(self):
        self.assertEqual(AesCipher.state_to_bytes(self.round_keys[0]).hex(), FIPS_KEY)

    def test_round_key_1(self):
        self.assertEqual(
            AesCipher.state_to_bytes(self.round_keys[1]).hex(),
            "a0fafe1788542cb123a339392a6c7605",
        )

    def test_round_key_10(self):
        self.assertEqual(
            AesCipher.state_to_bytes(self.round_keys[10]).hex(),
            "d014f9a8c9ee2589e13f0cc8b6630ca6",
        )


class TestAesRawBlock(unittest.TestCase):
    """Tests du chiffrement d'un bloc au format standard AES (sans la convention du sujet)."""

    def test_encrypt_fips_appendix_b(self):
        result = AesCipher.encrypt_block(bytes.fromhex(FIPS_INPUT), bytes.fromhex(FIPS_KEY))
        self.assertEqual(result.hex(), FIPS_OUTPUT)

    def test_encrypt_fips_appendix_c1(self):
        result = AesCipher.encrypt_block(bytes.fromhex(C1_INPUT), bytes.fromhex(C1_KEY))
        self.assertEqual(result.hex(), C1_OUTPUT)

    def test_decrypt_fips_appendix_b(self):
        result = AesCipher.decrypt_block(bytes.fromhex(FIPS_OUTPUT), bytes.fromhex(FIPS_KEY))
        self.assertEqual(result.hex(), FIPS_INPUT)

    def test_decrypt_fips_appendix_c1(self):
        result = AesCipher.decrypt_block(bytes.fromhex(C1_OUTPUT), bytes.fromhex(C1_KEY))
        self.assertEqual(result.hex(), C1_INPUT)

    def test_round_trip_random_blocks(self):
        """Chiffrer puis déchiffrer des blocs aléatoires redonne le bloc d'origine."""
        for _ in range(50):
            block, key = os.urandom(16), os.urandom(16)
            self.assertEqual(AesCipher.decrypt_block(AesCipher.encrypt_block(block, key), key), block)


class TestAesSubjectBlock(unittest.TestCase):
    """Tests du mode bloc (-b) avec la convention du sujet."""

    def test_swap_words(self):
        """Les octets sont inversés à l'intérieur de chaque groupe de 4."""
        self.assertEqual(
            AesCipher.swap_words(bytes.fromhex("0102030405060708")),
            bytes.fromhex("0403020108070605"),
        )

    def test_swap_words_twice_is_identity(self):
        data = bytes.fromhex(SUBJECT_KEY)
        self.assertEqual(AesCipher.swap_words(AesCipher.swap_words(data)), data)

    def test_subject_example_cipher(self):
        self.assertEqual(AesCipher.cipher_block(SUBJECT_MESSAGE, SUBJECT_KEY), SUBJECT_CIPHER)

    def test_subject_example_decipher(self):
        self.assertEqual(AesCipher.decipher_block(SUBJECT_CIPHER, SUBJECT_KEY), SUBJECT_MESSAGE)

    def test_message_wrong_size(self):
        with self.assertRaises(ValueError):
            AesCipher.cipher_block(b"Too short", SUBJECT_KEY)

    def test_key_wrong_size(self):
        with self.assertRaises(ValueError):
            AesCipher.cipher_block(SUBJECT_MESSAGE, "57696e74")

    def test_cipher_wrong_size(self):
        with self.assertRaises(ValueError):
            AesCipher.decipher_block("744ce22c", SUBJECT_KEY)


class TestAesStream(unittest.TestCase):
    """Tests du mode stream (sans -b) : blocs de 16 octets, padding par des zéros."""

    def test_stream_with_padding(self):
        """38 octets -> 3 blocs ; valeur calculée avec une implémentation de référence."""
        message = b"The night is dark and full of terrors\n"
        expected = (
            "af1c960216ed91a9d45cead5523cea40"
            "712eab7c7d78cc87f8d819adfe5acc4d"
            "3f6369434d75775519155eab4a543912"
        )
        self.assertEqual(AesCipher.cipher_stream(message, SUBJECT_KEY), expected)

    def test_stream_round_trip_keeps_padding(self):
        """Le déchiffrement redonne le message suivi des zéros de padding."""
        message = b"The night is dark and full of terrors\n"
        ciphered = AesCipher.cipher_stream(message, SUBJECT_KEY)
        self.assertEqual(
            AesCipher.decipher_stream(ciphered, SUBJECT_KEY), message + b"\x00" * 10
        )

    def test_stream_single_block_matches_block_mode(self):
        """Un message de 16 octets donne le même résultat en stream et en -b."""
        self.assertEqual(AesCipher.cipher_stream(SUBJECT_MESSAGE, SUBJECT_KEY), SUBJECT_CIPHER)

    def test_stream_invalid_cipher_length(self):
        with self.assertRaises(ValueError):
            AesCipher.decipher_stream("744ce22c", SUBJECT_KEY)


class TestAesCli(unittest.TestCase):
    """Tests d'intégration : le programme complet, comme la moulinette."""

    def test_subject_example_cipher(self):
        result = run_pgp(["aes", "-c", "-b", SUBJECT_KEY], b"All men must die\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, (SUBJECT_CIPHER + "\n").encode())

    def test_subject_example_decipher(self):
        result = run_pgp(["aes", "-d", "-b", SUBJECT_KEY], (SUBJECT_CIPHER + "\n").encode())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"All men must die\n")

    def test_stream_round_trip_multiline(self):
        """En stream, un message de plusieurs lignes est entièrement traité."""
        message = b"Winter is coming\nThe night is dark and full of terrors\n"
        ciphered = run_pgp(["aes", "-c", SUBJECT_KEY], message)
        self.assertEqual(ciphered.returncode, 0, ciphered.stderr)
        deciphered = run_pgp(["aes", "-d", SUBJECT_KEY], ciphered.stdout)
        self.assertEqual(deciphered.returncode, 0, deciphered.stderr)
        self.assertTrue(deciphered.stdout.startswith(message))

    def test_wrong_key_size_exits_84(self):
        result = run_pgp(["aes", "-c", "-b", "57696e74"], b"All men must die\n")
        self.assertEqual(result.returncode, 84)
        self.assertTrue(result.stderr.startswith(b"Error"))

    def test_wrong_block_size_exits_84(self):
        result = run_pgp(["aes", "-c", "-b", SUBJECT_KEY], b"Too short\n")
        self.assertEqual(result.returncode, 84)


if __name__ == "__main__":
    unittest.main()
