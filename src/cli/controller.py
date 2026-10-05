import sys
from cli.io_handler import IOHandler
from cipher.xor import XorCipher
from cipher.rsa import RsaCipher


class Controller:
    """Controller class responsible for dispatching the appropriate cryptographic operation based on user input."""

    @staticmethod
    def run_xor(args) -> None:
        """Handles the XOR cipher operations based on the provided arguments."""
    
        is_decipher = (args.mode == "-d")
    
        raw_data = IOHandler.read_input(
            block_mode=args.block_mode,
            is_rsa=False,
            is_decipher=is_decipher
        )

        if args.block_mode:
            if args.mode == "-c":
                ciphered = XorCipher.cipher_block(raw_data, args.key)
                IOHandler.write_output(ciphered)
            else:
                cipher_hex = raw_data.decode("ascii").strip()
                deciphered = XorCipher.decipher_block(cipher_hex, args.key)
                IOHandler.write_raw_bytes(deciphered)
                sys.stdout.write("\n")
                sys.stdout.flush()
        else:
            if args.mode == "-c":
                ciphered = XorCipher.cipher_stream(raw_data, args.key)
                IOHandler.write_output(ciphered)
            else:
                cipher_hex = raw_data.decode("ascii").strip()
                deciphered = XorCipher.decipher_stream(cipher_hex, args.key)
                IOHandler.write_raw_bytes(deciphered)
                sys.stdout.flush()

    @staticmethod
    def run_aes(args) -> None:
        # TODO: AES-128
        raise NotImplementedError("AES is not yet implemented.")

    @staticmethod
    def run_rsa(args) -> None:
        """Handles the RSA cipher operations based on the provided arguments."""

        if args.mode == "-g":
            e_hex, d_hex, n_hex = RsaCipher.generate_keys(args.p, args.q)
            IOHandler.write_output(f"public key: {e_hex}-{n_hex}")
            IOHandler.write_output(f"private key: {d_hex}-{n_hex}")
            return

    @staticmethod
    def run_pgp_xor(args) -> None:
        # TODO: PGP-XOR
        raise NotImplementedError("PGP-XOR is not yet implemented.")

    @staticmethod
    def run_pgp_aes(args) -> None:
        # TODO: PGP-AES
        raise NotImplementedError("PGP-AES is not yet implemented.")

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