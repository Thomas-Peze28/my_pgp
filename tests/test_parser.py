import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from cli.parser import parse_arguments


class TestCLIParser(unittest.TestCase):
    def test_valid_xor_block_mode(self):
        args = parse_arguments(["./my_pgp", "xor", "-c", "-b", "57686174"])
        self.assertEqual(args.crypto_system, "xor")
        self.assertEqual(args.mode, "-c")
        self.assertTrue(args.block_mode)
        self.assertEqual(args.key, "57686174")

    def test_valid_decipher_mode(self):
        args = parse_arguments(["./my_pgp", "aes", "-d", "1234567890abcdef"])
        self.assertEqual(args.mode, "-d")
        self.assertFalse(args.block_mode)

    def test_inverted_flags_order(self):
        args = parse_arguments(["./my_pgp", "xor", "-b", "-c", "57686174"])
        self.assertTrue(args.block_mode)
        self.assertEqual(args.mode, "-c")

    def test_combined_flags(self):
        args = parse_arguments(["./my_pgp", "aes", "-cb", "57686174"])
        self.assertEqual(args.crypto_system, "aes")
        self.assertEqual(args.mode, "-c")
        self.assertTrue(args.block_mode)

    def test_rsa_keygen_flags(self):
        args = parse_arguments(["./my_pgp", "rsa", "-g", "d3", "e3"])
        self.assertEqual(args.crypto_system, "rsa")
        self.assertEqual(args.mode, "-g")
        self.assertEqual(args.p, "d3")
        self.assertEqual(args.q, "e3")

    def test_invalid_system(self):
        with self.assertRaises(ValueError):
            parse_arguments(["./my_pgp", "unknown", "-c", "1234"])

    def test_missing_key(self):
        with self.assertRaises(ValueError):
            parse_arguments(["./my_pgp", "xor", "-c"])

    def test_conflicting_modes(self):
        with self.assertRaises(ValueError):
            parse_arguments(["./my_pgp", "xor", "-c", "-d", "1234"])

    def test_rsa_keygen_on_other_system(self):
        with self.assertRaises(ValueError):
            parse_arguments(["./my_pgp", "xor", "-g", "d3", "e3"])

    def test_multiple_keys(self):
        with self.assertRaises(ValueError):
            parse_arguments(["./my_pgp", "xor", "-c", "key1", "key2"])


if __name__ == "__main__":
    unittest.main()