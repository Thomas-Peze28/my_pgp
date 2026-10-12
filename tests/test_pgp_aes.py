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


class TestPgpAes(unittest.TestCase):
    """Tests d'intégration pour le système hybride pgp-aes (RSA + AES)."""

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
        # Clé AES de l'exemple pgp-aes du sujet (16 octets)
        self.sym_key = "57696e74657220697320636f6d696e67"
        # Sortie attendue de l'exemple pgp-aes du sujet (page 10)
        self.ciphered_sym_key = (
            "97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e6916afe5c5f"
            "9b9d6eaa0a870374b686f1a024f9bbb88c23c766654579339caf55afd149d41d"
        )
        self.ciphered_message = "744ce22c385958348f0df26eceb62eef"

    def cipher(self, message: bytes, sym_key: str, block: bool) -> list[str]:
        """Chiffre avec pgp-aes et renvoie les deux lignes de sortie."""
        flags = ["-c", "-b"] if block else ["-c"]
        result = run_pgp(["pgp-aes", *flags, f"{sym_key}:{self.pub}"], message)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode().splitlines()

    def decipher(self, lines: list[str], block: bool) -> bytes:
        """Déchiffre la sortie de cipher() et renvoie le message clair."""
        flags = ["-d", "-b"] if block else ["-d"]
        result = run_pgp(
            ["pgp-aes", *flags, f"{lines[0]}:{self.priv}"], (lines[1] + "\n").encode()
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_subject_example_cipher(self):
        """Reproduit exactement les deux lignes de l'exemple du sujet."""
        lines = self.cipher(b"All men must die\n", self.sym_key, block=True)
        self.assertEqual(lines, [self.ciphered_sym_key, self.ciphered_message])

    def test_subject_example_decipher(self):
        """Déchiffre l'exemple du sujet à partir de ses valeurs."""
        lines = [self.ciphered_sym_key, self.ciphered_message]
        self.assertEqual(self.decipher(lines, block=True), b"All men must die\n")

    def test_second_line_matches_plain_aes(self):
        """La 2e ligne est identique au chiffrement AES seul avec la même clé."""
        lines = self.cipher(b"All men must die\n", self.sym_key, block=True)
        aes = run_pgp(["aes", "-c", "-b", self.sym_key], b"All men must die\n")
        self.assertEqual(lines[1], aes.stdout.decode().strip())

    def test_stream_round_trip_multiline(self):
        """En stream, un message de plusieurs lignes est entièrement chiffré."""
        message = b"Winter is coming\nThe night is dark and full of terrors\n"
        lines = self.cipher(message, self.sym_key, block=False)
        self.assertTrue(self.decipher(lines, block=False).startswith(message))

    def test_key_ending_with_zero_bytes_block(self):
        """Une clé finissant par 00 survit à l'aller-retour RSA en mode bloc."""
        sym_key = "41424344454647484950515253540000"
        lines = self.cipher(b"All men must die\n", sym_key, block=True)
        self.assertEqual(self.decipher(lines, block=True), b"All men must die\n")

    def test_key_ending_with_zero_bytes_stream(self):
        """Une clé finissant par 00 survit aussi en stream (complément à 16 octets)."""
        sym_key = "41424344454647484950515253540000"
        lines = self.cipher(b"hello\n", sym_key, block=False)
        self.assertTrue(self.decipher(lines, block=False).startswith(b"hello\n"))

    def test_key_without_separator(self):
        """Une clé sans ':' doit faire échouer le programme avec le code 84."""
        result = run_pgp(["pgp-aes", "-c", "-b", self.sym_key], b"All men must die\n")
        self.assertEqual(result.returncode, 84)
        self.assertTrue(result.stderr.startswith(b"Error"))

    def test_wrong_aes_key_size(self):
        """Une clé symétrique qui n'a pas 16 octets est refusée."""
        result = run_pgp(
            ["pgp-aes", "-c", "-b", f"57696e74:{self.pub}"], b"All men must die\n"
        )
        self.assertEqual(result.returncode, 84)

    def test_block_size_mismatch(self):
        """En mode bloc, un message qui ne fait pas 16 octets est refusé."""
        result = run_pgp(
            ["pgp-aes", "-c", "-b", f"{self.sym_key}:{self.pub}"], b"Too short\n"
        )
        self.assertEqual(result.returncode, 84)


if __name__ == "__main__":
    unittest.main()
