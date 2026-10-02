import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)

from utils.endian import EndianUtils


class TestEndianUtils(unittest.TestCase):

    def test_subject_example_int_to_hex(self):
        # Exemple page 3 du sujet : 0x01234567 -> "67452301" en little-endian
        self.assertEqual(EndianUtils.int_to_hex(0x01234567, length=4), "67452301")
        self.assertEqual(EndianUtils.hex_to_int("67452301"), 0x01234567)

    def test_subject_example_rsa_bytes(self):
        # Exemple page 7 du sujet : b"WF" (0x57, 0x46) -> 18007 en little-endian
        self.assertEqual(EndianUtils.bytes_to_int(b"WF", byteorder="little"), 18007)
        self.assertEqual(
            EndianUtils.int_to_bytes(18007, length=2, byteorder="little"), b"WF"
        )

    def test_bytes_to_int_big_endian_default(self):
        # Séquence de texte standard : lecture séquentielle de gauche à droite
        self.assertEqual(EndianUtils.bytes_to_int(b"WF"), 0x5746)
        self.assertEqual(EndianUtils.int_to_bytes(0x5746, length=2), b"WF")

    def test_zero_handling(self):
        self.assertEqual(EndianUtils.int_to_hex(0, length=2), "0000")
        self.assertEqual(EndianUtils.hex_to_int("0000"), 0)
        self.assertEqual(EndianUtils.int_to_bytes(0, length=2), b"\x00\x00")

    def test_odd_hex_string_padding(self):
        self.assertEqual(EndianUtils.hex_to_bytes("1"), b"\x10")
        self.assertEqual(EndianUtils.hex_to_int("1"), 0x10)

    def test_invalid_byteorder(self):
        with self.assertRaises(ValueError):
            EndianUtils.hex_to_int("12", byteorder="invalid")
        with self.assertRaises(ValueError):
            EndianUtils.bytes_to_int(b"\x12", byteorder="invalid")


if __name__ == "__main__":
    unittest.main()
