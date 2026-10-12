import sys
from cli.io_handler import IOHandler
from cipher.xor import XorCipher
from cipher.rsa import RsaCipher
from cipher.aes import AesCipher


class Controller:
    """Controller class responsible for dispatching the appropriate cryptographic operation based on user input."""

    @staticmethod
    def _xor_process(args, key_hex: str, raw_data: bytes) -> None:
        """Ciphers or deciphers raw_data with XOR using key_hex, then writes the result."""

        if args.block_mode:
            if args.mode == "-c":
                ciphered = XorCipher.cipher_block(raw_data, key_hex)
                IOHandler.write_output(ciphered)
            elif args.mode == "-d":
                cipher_hex = raw_data.decode("ascii").strip()
                deciphered = XorCipher.decipher_block(cipher_hex, key_hex)
                IOHandler.write_raw_bytes(deciphered)
                sys.stdout.write("\n")
                sys.stdout.flush()
        else:
            if args.mode == "-c":
                ciphered = XorCipher.cipher_stream(raw_data, key_hex)
                IOHandler.write_output(ciphered)
            elif args.mode == "-d":
                cipher_hex = raw_data.decode("ascii").strip()
                deciphered = XorCipher.decipher_stream(cipher_hex, key_hex)
                IOHandler.write_raw_bytes(deciphered)
                sys.stdout.flush()

    @staticmethod
    def run_xor(args) -> None:
        """Handles the XOR cipher operations based on the provided arguments."""

        raw_data = IOHandler.read_input(
            block_mode=args.block_mode,
            is_rsa=False,
            is_decipher=(args.mode == "-d")
        )
        Controller._xor_process(args, args.key, raw_data)

    @staticmethod
    def _aes_process(args, key_hex: str, raw_data: bytes) -> None:
        """Ciphers or deciphers raw_data with AES using key_hex, then writes the result."""

        if args.block_mode:
            if args.mode == "-c":
                ciphered = AesCipher.cipher_block(raw_data, key_hex)
                IOHandler.write_output(ciphered)
            elif args.mode == "-d":
                cipher_hex = raw_data.decode("ascii").strip()
                deciphered = AesCipher.decipher_block(cipher_hex, key_hex)
                IOHandler.write_raw_bytes(deciphered)
                sys.stdout.write("\n")
                sys.stdout.flush()
        else:
            if args.mode == "-c":
                ciphered = AesCipher.cipher_stream(raw_data, key_hex)
                IOHandler.write_output(ciphered)
            elif args.mode == "-d":
                cipher_hex = raw_data.decode("ascii").strip()
                deciphered = AesCipher.decipher_stream(cipher_hex, key_hex)
                IOHandler.write_raw_bytes(deciphered)
                sys.stdout.flush()


    @staticmethod
    def run_aes(args) -> None:
        """Handles the AES cipher operations based on the provided arguments."""

        raw_data = IOHandler.read_input(
            block_mode=args.block_mode,
            is_rsa=False,
            is_decipher=(args.mode == "-d")
        )
        Controller._aes_process(args, args.key, raw_data)


    @staticmethod
    def run_rsa(args) -> None:
        """Handles the RSA cipher operations based on the provided arguments."""

        if args.mode == "-g":
            e_hex, d_hex, n_hex = RsaCipher.generate_keys(args.p, args.q)
            IOHandler.write_output(f"public key: {e_hex}-{n_hex}")
            IOHandler.write_output(f"private key: {d_hex}-{n_hex}")
            return
        
        if args.mode == "-c":
            raw_data = IOHandler.read_input(
                block_mode=args.block_mode,
                is_rsa=True,
                is_decipher=False
            )
            ciphered = RsaCipher.cipher(raw_data, args.key)
            IOHandler.write_output(ciphered)
        elif args.mode == "-d":
            raw_data = IOHandler.read_input(
                block_mode=args.block_mode,
                is_rsa=True,
                is_decipher=True
            )
            deciphered = RsaCipher.decipher(raw_data.decode("ascii").strip(), args.key)
            IOHandler.write_raw_bytes(deciphered)
            sys.stdout.write("\n")
            sys.stdout.flush()

    @staticmethod
    def run_pgp_xor(args) -> None:
        """Handles the PGP-XOR cipher operations based on the provided arguments."""

        parts = args.key.strip().split(":")
        if len(parts) != 2:
            raise ValueError("PGP-XOR key must follow the 'SYMMETRIC_KEY:RSA_KEY' format.")
        sym_key, rsa_key = parts
        
        if args.mode == "-c":
            raw_data = IOHandler.read_input(
                block_mode=args.block_mode,
                is_rsa=False,
                is_decipher=False
            )
            ciphered_key = RsaCipher.cipher(bytes.fromhex(sym_key), rsa_key)
            IOHandler.write_output(ciphered_key)
            Controller._xor_process(args, sym_key, raw_data)
        elif args.mode == "-d":
            sym_bytes = RsaCipher.decipher(sym_key, rsa_key)
            raw_data = IOHandler.read_input(
                block_mode=args.block_mode,
                is_rsa=False,
                is_decipher=True
            )
            if args.block_mode:
                message_len = len(raw_data.strip()) // 2
                sym_bytes = sym_bytes.ljust(message_len, b"\x00")
            Controller._xor_process(args, sym_bytes.hex(), raw_data)

    @staticmethod
    def run_pgp_aes(args) -> None:
        """Handles the PGP-AES cipher operations based on the provided arguments."""

        parts = args.key.strip().split(":")
        if len(parts) != 2:
            raise ValueError("PGP-AES key must follow the 'SYMMETRIC_KEY:RSA_KEY' format.")
        sym_key, rsa_key = parts

        if args.mode == "-c":
            raw_data = IOHandler.read_input(
                block_mode=args.block_mode,
                is_rsa=False,
                is_decipher=False
            )
            ciphered_key = RsaCipher.cipher(bytes.fromhex(sym_key), rsa_key)
            IOHandler.write_output(ciphered_key)
            Controller._aes_process(args, sym_key, raw_data)
        elif args.mode == "-d":
            sym_bytes = RsaCipher.decipher(sym_key, rsa_key)
            raw_data = IOHandler.read_input(
                block_mode=args.block_mode,
                is_rsa=False,
                is_decipher=True
            )
            sym_bytes = sym_bytes.ljust(16, b"\x00")
            Controller._aes_process(args, sym_bytes.hex(), raw_data)

    @classmethod
    def dispatch(cls, args) -> None:
        handlers = {
            "xor": cls.run_xor,
            "aes": cls.run_aes,
            "rsa": cls.run_rsa,
            "pgp-xor": cls.run_pgp_xor,
            "pgp-aes": cls.run_pgp_aes,
        }
        handler = handlers.get(args.crypto_system)
        if not handler:
            raise ValueError(f"System not supported : {args.crypto_system}")
        handler(args)