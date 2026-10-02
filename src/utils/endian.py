from typing import Literal


class EndianUtils:
    """Utility class for handling conversions between hexadecimal strings, raw bytes, and integers."""

    # =========================================================================
    # 1. Numbers (Hexadecimal <-> Integer)
    # =========================================================================

    @staticmethod
    def hex_to_int(
        hex_str: str,
        byteorder: str = "little"
        ) -> int:
        """Convert a hexadecimal string to an integer with specified endianness.

        @param hex_str: A hexadecimal string.
        @param byteorder: Byte order convention ('little' by default, or 'big').
        @return: The integer value corresponding to the hexadecimal string.
        """
        if byteorder not in ("little", "big"):
            raise ValueError("byteorder must be either 'little' or 'big'")
        clean_hex = hex_str.strip()
        if len(clean_hex) % 2 != 0:
            clean_hex += "0"
        raw_bytes = bytes.fromhex(clean_hex)
        return int.from_bytes(raw_bytes, byteorder=byteorder)

    @staticmethod
    def int_to_hex(
        value: int, length: int | None = None, byteorder: str = "little"
    ) -> str:
        """Convert an integer to a hexadecimal string with specified endianness.

        @param value: The integer to convert.
        @param length: The target length in bytes (optional).
        @param byteorder: Byte order convention ('little' by default, or 'big').
        @return: A hexadecimal string formatted in the given endianness.
        """
        if byteorder not in ("little", "big"):
            raise ValueError("byteorder must be either 'little' or 'big'")
        if value == 0:
            return "00" * (length if length else 1)
        if length is None:
            length = (value.bit_length() + 7) // 8
        raw_bytes = value.to_bytes(length, byteorder=byteorder)
        return raw_bytes.hex()

    # =========================================================================
    # 2. Byte Sequences (Bytes <-> Integer)
    # =========================================================================

    @staticmethod
    def bytes_to_int(data: bytes, byteorder: str = "big") -> int:
        """Convert a byte sequence to an integer with specified endianness.

        @param data: The sequence of bytes to convert.
        @param byteorder: Byte order convention ('big' for standard text, 'little' for RSA).
        @return: The arithmetic integer value.
        """
        if byteorder not in ("little", "big"):
            raise ValueError("byteorder must be either 'little' or 'big'")
        return int.from_bytes(data, byteorder=byteorder)

    @staticmethod
    def int_to_bytes(
        value: int, length: int | None = None, byteorder: str = "big"
    ) -> bytes:
        """Convert an integer to a byte sequence with specified endianness.

        @param value: The integer value to convert.
        @param length: The desired output length in bytes (optional).
        @param byteorder: Byte order convention ('big' for standard text, 'little' for RSA).
        @return: A bytes object in the given endianness.
        """
        if byteorder not in ("little", "big"):
            raise ValueError("byteorder must be either 'little' or 'big'")
        if value == 0 and length is not None:
            return b"\x00" * length
        if length is None:
            length = (value.bit_length() + 7) // 8
        return value.to_bytes(length, byteorder=byteorder)

    # =========================================================================
    # 3. Raw Memory Buffer (Hex <-> Bytes)
    # =========================================================================

    @staticmethod
    def hex_to_bytes(hex_str: str) -> bytes:
        """Convert a hexadecimal string directly to raw bytes in memory order.

        @param hex_str: A hexadecimal string.
        @return: A bytes object containing the parsed bytes.
        """
        clean_hex = hex_str.strip()
        if len(clean_hex) % 2 != 0:
            clean_hex += "0"
        return bytes.fromhex(clean_hex)

    @staticmethod
    def bytes_to_hex(data: bytes) -> str:
        """Convert raw bytes directly to a hexadecimal string.

        @param data: A bytes object.
        @return: A hexadecimal string representing the raw bytes.
        """
        return data.hex()

    @staticmethod
    def bytes_to_int_le(data: bytes) -> int:
        return EndianUtils.bytes_to_int(data, byteorder="little")

    @staticmethod
    def int_le_to_bytes(value: int, length: int | None = None) -> bytes:
        return EndianUtils.int_to_bytes(value, length=length, byteorder="little")
