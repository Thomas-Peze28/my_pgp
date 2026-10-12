from utils.endian import EndianUtils

# fmt: off
# Substitution table used by SubBytes (FIPS-197)
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

# Inverse substitution table used by InvSubBytes (FIPS-197)
INV_SBOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]

# Coefficients used by MixColumns (FIPS-197)
MIX_MATRIX = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
]

# Coefficients used by InvMixColumns (FIPS-197)
INV_MIX_MATRIX = [
    [14, 11, 13, 9],
    [9, 14, 11, 13],
    [13, 9, 14, 11],
    [11, 13, 9, 14],
]

# Round constants used by KeyExpansion (FIPS-197)
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


# fmt: on


class AesCipher:
    """A class for performing AES encryption and decryption."""

    @staticmethod
    def bytes_to_state(byte_array: bytes) -> list[list[int]]:
        """Converts a byte array to a 4x4 state matrix.

        @param byte_array: The input byte array.
        @return: The corresponding 4x4 state matrix.
        """
        state = [[0] * 4 for _ in range(4)]
        for row in range(4):
            for col in range(4):
                state[row][col] = byte_array[row + 4 * col]
        return state

    @staticmethod
    def state_to_bytes(state: list[list[int]]) -> bytes:
        """Converts a 4x4 state matrix back to a byte array.
        @param state: The input 4x4 state matrix.
        @return: The corresponding byte array.
        """
        byte_array = bytearray(16)
        for row in range(4):
            for col in range(4):
                byte_array[row + 4 * col] = state[row][col]
        return bytes(byte_array)

    @staticmethod
    def add_round_key(
        state: list[list[int]], round_key: list[list[int]]
    ) -> list[list[int]]:
        """Adds (XORs) the round key to the state.

        @param state: The current state of the AES algorithm as a 4x4 matrix.
        @param round_key: The round key to be added to the state as a 4x4 matrix.
        @return: The updated state after adding the round key.
        """

        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]
        return state

    @staticmethod
    def sub_bytes(state: list[list[int]]) -> list[list[int]]:
        """Substitutes bytes in the state using the AES S-box.

        @param state: The current state of the AES algorithm as a 4x4 matrix.
        @return: The updated state after substituting bytes.
        """
        for i in range(4):
            for j in range(4):
                state[i][j] = SBOX[state[i][j]]
        return state
    
    @staticmethod
    def inv_sub_bytes(state: list[list[int]]) -> list[list[int]]:
        """Substitutes bytes in the state using the AES inverse S-box.

        @param state: The current state of the AES algorithm as a 4x4 matrix.
        @return: The updated state after substituting bytes.
        """
        for i in range(4):
            for j in range(4):
                state[i][j] = INV_SBOX[state[i][j]]
        return state

    @staticmethod
    def shift_rows(state: list[list[int]]) -> list[list[int]]:
        """Shifts the rows of the state to the left.

        @param state: The current state of the AES algorithm as a 4x4 matrix.
        @return: The updated state after shifting rows.
        """
        for i in range(4):
            state[i] = state[i][i:] + state[i][:i]
        return state
    
    @staticmethod
    def inv_shift_rows(state: list[list[int]]) -> list[list[int]]:
        """Shifts the rows of the state to the right (inverse operation).

        @param state: The current state of the AES algorithm as a 4x4 matrix.
        @return: The updated state after inverse shifting rows.
        """
        for i in range(4):
            state[i] = state[i][-i:] + state[i][:-i]
        return state

    @staticmethod
    def gmul(a: int, b: int) -> int:
        """Multiplies two bytes in AES arithmetic (Galois Field GF(2^8)).

        @param a: The first byte (0-255).
        @param b: The second byte (0-255).
        @return: The product of a and b as a byte.
        """
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            if a & 0x100:
                a ^= 0x11B
            b >>= 1
        return result

    @staticmethod
    def _mix(state: list[list[int]], matrix: list[list[int]]) -> list[list[int]]:
        """Multiplies each column of the state by the given coefficient matrix.

        @param state: The current state of the AES algorithm as a 4x4 matrix.
        @param matrix: The coefficient matrix to multiply.
        @return: The updated state after mixing columns.
        """

        for col in range(4):
            column = [state[row][col] for row in range(4)]
            for row in range(4):
                value = 0
                for coef in range(4):
                    value ^= AesCipher.gmul(matrix[row][coef], column[coef])
                state[row][col] = value
        return state

    @staticmethod
    def mix_columns(state):
        """Mixes the columns of the state using the AES MixColumns transformation."""
        return AesCipher._mix(state, MIX_MATRIX)

    @staticmethod
    def inv_mix_columns(state):
        """Mixes the columns of the state using the AES InvMixColumns transformation."""
        return AesCipher._mix(state, INV_MIX_MATRIX)
    
    @staticmethod
    def key_expansion(key: bytes) -> list[list[list[int]]]:
        """Expands a 16-byte key into 11 round keys.

        @param key: The original cipher key as a byte array.
        @return: A list of round keys, each represented as a 4x4 matrix.
        """
        
        words = []
        for i in range(4):
            words.append(list(key[4 * i : 4 * i + 4]))
            
        for i in range(4, 44):
            temp = words[i - 1][:]
            if i % 4 == 0:
                temp = temp[1:] + temp[:1]
                temp = [SBOX[b] for b in temp]
                temp[0] ^= RCON[i // 4 - 1]
            new_word = []
            for j in range(4):
                new_word.append(words[i - 4][j] ^ temp[j])
            words.append(new_word)

        round_keys = []
        for k in range(11):
            key_bytes = bytes(words[4 * k] + words[4 * k + 1] + words[4 * k + 2] + words[4 * k + 3])
            round_keys.append(AesCipher.bytes_to_state(key_bytes))
        return round_keys
    
    @staticmethod
    def encrypt_block(block: bytes, key: bytes) -> bytes:
        """Encrypts a single 16-byte block with AES-128.

        @param block: The 16-byte clear block.
        @param key: The 16-byte cipher key.
        @return: The 16-byte encrypted block.
        """
        
        round_keys = AesCipher.key_expansion(key)
        state = AesCipher.bytes_to_state(block)
        
        state = AesCipher.add_round_key(state, round_keys[0])
        
        for round in range(1, 10):
            state = AesCipher.sub_bytes(state)
            state = AesCipher.shift_rows(state)
            state = AesCipher.mix_columns(state)
            state = AesCipher.add_round_key(state, round_keys[round])
            
        state = AesCipher.sub_bytes(state)
        state = AesCipher.shift_rows(state)
        state = AesCipher.add_round_key(state, round_keys[10])
    
        return AesCipher.state_to_bytes(state)
    
    @staticmethod
    def decrypt_block(block: bytes, key: bytes) -> bytes:
        """Decrypts a single 16-byte block with AES-128.

        @param block: The 16-byte encrypted block.
        @param key: The 16-byte cipher key.
        @return: The 16-byte decrypted block.
        """
        
        round_keys = AesCipher.key_expansion(key)
        state = AesCipher.bytes_to_state(block)
        
        state = AesCipher.add_round_key(state, round_keys[10])
        
        for round in range(9, 0, -1):
            state = AesCipher.inv_shift_rows(state)
            state = AesCipher.inv_sub_bytes(state)
            state = AesCipher.add_round_key(state, round_keys[round])
            state = AesCipher.inv_mix_columns(state)
            
        state = AesCipher.inv_shift_rows(state)
        state = AesCipher.inv_sub_bytes(state)
        state = AesCipher.add_round_key(state, round_keys[0])
    
        return AesCipher.state_to_bytes(state)