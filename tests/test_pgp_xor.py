import os
import subprocess
import sys
import unittest

MAIN = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "main.py"))


def run_pgp(args, stdin: bytes) -> subprocess.CompletedProcess:
    """Lance le programme comme la CLI (./my_pgp ...) et renvoie le résultat."""
    return subprocess.run(
        [sys.executable, MAIN, *args], input=stdin, capture_output=True
    )


class TestPgpXor(unittest.TestCase):
    """Tests d'intégration pour le système hybride pgp-xor (RSA + XOR)."""

    def setUp(self):
        # Clés 256 bits officielles
        self.pub = (
            "010001-c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de"
            "139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3"
        )
        self.priv = (
            "81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a"
            "11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209-"
            "c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de"
            "139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3"
        )
        # Clé symétrique de l'exemple pgp-aes du sujet (16 octets)
        self.sym_key = "57696e74657220697320636f6d696e67"
        # Clé symétrique chiffrée attendue (1re ligne de l'exemple pgp-aes du sujet)
        self.ciphered_sym_key = (
            "97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e6916afe5c5f"
            "9b9d6eaa0a870374b686f1a024f9bbb88c23c766654579339caf55afd149d41d"
        )

    def cipher(self, message: bytes, sym_key: str, block: bool) -> list[str]:
        """Chiffre avec pgp-xor et renvoie les deux lignes de sortie."""
        flags = ["-c", "-b"] if block else ["-c"]
        result = run_pgp(["pgp-xor", *flags, f"{sym_key}:{self.pub}"], message)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode().splitlines()

    def decipher(self, lines: list[str], block: bool) -> bytes:
        """Déchiffre la sortie de cipher() et renvoie le message clair."""
        flags = ["-d", "-b"] if block else ["-d"]
        result = run_pgp(
            ["pgp-xor", *flags, f"{lines[0]}:{self.priv}"], (lines[1] + "\n").encode()
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_cipher_output_has_two_lines(self):
        """La sortie contient la clé chiffrée puis le message chiffré."""
        lines = self.cipher(b"All men must die\n", self.sym_key, block=True)
        self.assertEqual(len(lines), 2)

    def test_first_line_matches_subject_ciphered_key(self):
        """La 1re ligne est la clé symétrique chiffrée par RSA, comme dans le sujet."""
        lines = self.cipher(b"All men must die\n", self.sym_key, block=True)
        self.assertEqual(lines[0], self.ciphered_sym_key)

    def test_second_line_matches_plain_xor(self):
        """La 2e ligne est identique au chiffrement XOR seul avec la même clé."""
        lines = self.cipher(b"All men must die\n", self.sym_key, block=True)
        xor = run_pgp(["xor", "-c", "-b", self.sym_key], b"All men must die\n")
        self.assertEqual(lines[1], xor.stdout.decode().strip())

    def test_block_round_trip(self):
        """Chiffrer puis déchiffrer en mode bloc redonne le message."""
        lines = self.cipher(b"All men must die\n", self.sym_key, block=True)
        self.assertEqual(self.decipher(lines, block=True), b"All men must die\n")

    def test_decipher_from_subject_values(self):
        """Le déchiffrement fonctionne à partir de la clé chiffrée du sujet."""
        xor = run_pgp(["xor", "-c", "-b", self.sym_key], b"All men must die\n")
        lines = [self.ciphered_sym_key, xor.stdout.decode().strip()]
        self.assertEqual(self.decipher(lines, block=True), b"All men must die\n")

    def test_stream_round_trip_multiline(self):
        """En stream, un message de plusieurs lignes est entièrement chiffré."""
        message = b"Winter is coming\nThe night is dark and full of terrors\n"
        lines = self.cipher(message, self.sym_key, block=False)
        deciphered = self.decipher(lines, block=False)
        self.assertTrue(deciphered.startswith(message))

    def test_block_key_ending_with_zero_bytes(self):
        """Une clé finissant par 00 survit à l'aller-retour RSA (complément par zéros)."""
        sym_key = "414243444546470000"  # 9 octets, dont deux 00 de poids fort
        lines = self.cipher(b"abcdefghi\n", sym_key, block=True)
        self.assertEqual(self.decipher(lines, block=True), b"abcdefghi\n")

    def test_key_without_separator(self):
        """Une clé sans ':' doit faire échouer le programme avec le code 84."""
        result = run_pgp(["pgp-xor", "-c", "-b", self.sym_key], b"All men must die\n")
        self.assertEqual(result.returncode, 84)
        self.assertTrue(result.stderr.startswith(b"Error"))

    def test_key_with_too_many_separators(self):
        """Une clé avec plusieurs ':' doit faire échouer le programme avec le code 84."""
        key = f"{self.sym_key}:{self.pub}:{self.pub}"
        result = run_pgp(["pgp-xor", "-c", "-b", key], b"All men must die\n")
        self.assertEqual(result.returncode, 84)

    def test_block_size_mismatch(self):
        """En mode bloc, un message de taille différente de la clé est refusé."""
        result = run_pgp(
            ["pgp-xor", "-c", "-b", f"{self.sym_key}:{self.pub}"], b"Too short\n"
        )
        self.assertEqual(result.returncode, 84)


if __name__ == "__main__":
    unittest.main()
