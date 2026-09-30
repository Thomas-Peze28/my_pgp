import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from utils.endian import EndianUtils


class TestEndianUtils(unittest.TestCase):
    def test_subject_example_int_to_hex(self):
        self.assertEqual(EndianUtils.int_to_hex_le(0x01234567), "67452301")
        self.assertEqual(EndianUtils.hex_le_to_int("67452301"), 0x01234567)

    def test_subject_example_rsa_bytes(self):
        self.assertEqual(EndianUtils.bytes_to_int_le(b"WF"), 18007)
        self.assertEqual(EndianUtils.int_le_to_bytes(18007), b"WF")

    def test_zero_handling(self):
        self.assertEqual(EndianUtils.int_to_hex_le(0, length=2), "0000")
        self.assertEqual(EndianUtils.hex_le_to_int("0000"), 0)
        self.assertEqual(EndianUtils.int_le_to_bytes(0, length=2), b"\x00\x00")

    def test_odd_hex_string_padding(self):
        # Une chaîne impaire "1" doit être traitée proprement en "10"
        self.assertEqual(EndianUtils.hex_le_to_bytes("1"), b"\x10")


if __name__ == "__main__":
    unittest.main()