import sys


class IOHandler:
    """Class to handle input and output operations for the CLI application."""

    @staticmethod
    def read_input(
        block_mode: bool, is_rsa: bool = False, is_decipher: bool = False
    ) -> bytes:
        """
        Reads data from STDIN according to the execution mode:
        - In block mode (-b), for RSA, or during decryption: reads a single line and ignores the final newline.
        - In stream mode (symmetric encryption without -b): reads the entire binary stream.
        """

        stdin_buffer = sys.stdin.buffer

        if block_mode or is_rsa or is_decipher:
            line = stdin_buffer.readline()
            if not line and line != b"":
                raise ValueError("Standard input is empty.")
            if line.endswith(b"\r\n"):
                line = line[:-2]
            elif line.endswith(b"\n"):
                line = line[:-1]
            return line

        data = stdin_buffer.read()
        if not data:
            raise ValueError("Standard input is empty.")
        return data

    @staticmethod
    def write_output(output: str) -> None:
        """
        Writes the output string to STDOUT, followed by a newline.
        """
        sys.stdout.write(f"{output}\n")
        sys.stdout.flush()

    @staticmethod
    def write_raw_bytes(data: bytes) -> None:
        """
        Writes raw bytes to STDOUT without any additional formatting or newline.
        """
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
