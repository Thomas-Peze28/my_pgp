class EndianUtils:
    """Utility class for handling little-endian conversions between hexadecimal strings, raw bytes, and integers."""

    @staticmethod
    def hex_le_to_bytes(hex_str: str) -> bytes:
        """Convert a little-endian hexadecimal string to raw bytes.
    
        @param hex_str: A string representing a little-endian hexadecimal number.
        @return: A bytes object containing the raw bytes corresponding to the hexadecimal string.
        """

        clean_hex = hex_str.strip()
        if len(clean_hex) % 2 != 0:
            clean_hex = clean_hex + "0"
        return bytes.fromhex(clean_hex)

    @staticmethod
    def bytes_to_hex_le(data: bytes) -> str:
        """Convert raw bytes to a little-endian hexadecimal string.
    
        @param data: A bytes object containing the raw bytes.
        @return: A string representing the little-endian hexadecimal number corresponding to the raw bytes.
        """
        return data.hex()

    @staticmethod
    def hex_le_to_int(hex_str: str) -> int:
        """
        Convert a little-endian hexadecimal string to an integer.

        @param hex_str: A string representing a little-endian hexadecimal number.
        @return: An integer corresponding to the little-endian hexadecimal string.
        """
        raw_bytes = EndianUtils.hex_le_to_bytes(hex_str)
        return int.from_bytes(raw_bytes, byteorder="little")

    @staticmethod
    def int_to_hex_le(value: int, length: int = None) -> str:
        """
        Convert an integer to a little-endian hexadecimal string.
        If length is not specified, the minimum required size in bytes is calculated.
    
        @param value: An integer to convert.
        @param length: The desired length of the resulting hexadecimal string in bytes.
        @return: A string representing the little-endian hexadecimal number corresponding to the integer.
        """
        if value == 0:
            return "00" * (length if length else 1)
        if length is None:
            length = (value.bit_length() + 7) // 8
        raw_bytes = value.to_bytes(length, byteorder="little")
        return raw_bytes.hex()

    @staticmethod
    def bytes_to_int_le(data: bytes) -> int:
        """
        Convert raw bytes in little-endian format to an integer.
    
        @param data: A bytes object containing the raw bytes in little-endian format.
        @return: An integer corresponding to the little-endian bytes.
        """
        return int.from_bytes(data, byteorder="little")

    @staticmethod
    def int_le_to_bytes(value: int, length: int = None) -> bytes:
        """
        Convert a little-endian integer to a sequence of bytes.
    
        @param value: An integer to convert.
        @param length: The desired length of the resulting bytes object in bytes.
        @return: A bytes object containing the raw bytes in little-endian format.
        """
        if value == 0:
            return b"\x00" * (length if length else 1)
        if length is None:
            length = (value.bit_length() + 7) // 8
        return value.to_bytes(length, byteorder="little")
