import sys

VALID_SYSTEMS = {"xor", "aes", "rsa", "pgp-xor", "pgp-aes"}

USAGE_TEXT = """USAGE

    ./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]

DESCRIPTION

    Cipher or decipher MESSAGE using a given CRYPTO_SYSTEM. The MESSAGE is read from the standard input.

CRYPTO_SYSTEM

    "xor"          computation using XOR algorithm
    "aes"          computation using AES algorithm
    "rsa"          computation using RSA algorithm
    "pgp-xor"      computation using both RSA and XOR algorithm
    "pgp-aes"      computation using both RSA and AES algorithm

MODE

    -c             MESSAGE is clear and we want to cipher it
    -d             MESSAGE is ciphered and we want to decipher it
    -g P Q         RSA only: don't read a MESSAGE, but instead generate a public and private key pair from the prime number P and Q

OPTIONS

    -b             for XOR, AES and PGP, only works on one block. The MESSAGE and the symmetric key must be the same size

    key            Key used to cipher/decipher MESSAGE (incompatible with -g MODE)
"""


class cliArgs:
    """Class to hold parsed CLI arguments.

    Attributes:
            crypto_system (str): The selected crypto system.
            mode (str): The selected mode ("-c", "-d", or "-g").
            block_mode (bool): True if the -b option is specified, False otherwise.
            key (str): The key used to cipher/decipher MESSAGE.
            p (str): The first prime number for RSA key generation (only used with -g).
            q (str): The second prime number for RSA key generation (only used with -g).
    """

    def __init__(self, crypto_system):
        self.crypto_system = crypto_system
        self.mode = None
        self.block_mode = False
        self.key = None
        self.p = None
        self.q = None


def print_help():
    """Print the usage information and exit the program."""
    sys.stdout.write(USAGE_TEXT)
    sys.exit(0)


def parse_arguments(argv):
    """Parse CLI arguments.

    Args:
        argv (list[str]): Command-line arguments received by the program,
            including the executable name as argv[0].

    Raises:
        ValueError: If the arguments are incomplete, the crypto system is
            invalid, a mode is missing or conflicting, a required key is
            missing, or an option is malformed.

    Returns:
        cliArgs: Parsed CLI arguments containing the selected crypto system,
        mode, block mode flag, key, and RSA generation values when needed.
    """

    if len(argv) == 2 and argv[1] == "-h" or len(argv) == 2 and argv[1] == "--help":
        print_help()

    if len(argv) < 3:
        raise ValueError("Insufficient arguments.")

    system = argv[1].lower()
    if system not in VALID_SYSTEMS:
        raise ValueError(f"Invalid crypto system : {system}")

    args = cliArgs(system)
    remaining = argv[2:]

    # RSA key generation (-g P Q)
    if "-g" in remaining:
        if system != "rsa":
            raise ValueError("Flag -g is only valid for RSA.")
        if len(remaining) != 3 or remaining[0] != "-g":
            raise ValueError("Mode -g requires exactly two prime parameters: P and Q.")
        args.mode = "-g"
        args.p = remaining[1]
        args.q = remaining[2]
        return args

    # Parse other flags and key
    for token in remaining:
        if token.startswith("-"):
            flags = token[1:]
            if not flags:
                raise ValueError("Empty option flag '-' encountered.")

            for char in flags:
                if char == "c":
                    if args.mode and args.mode != "-c":
                        raise ValueError("Conflicting modes specified (-c and -d).")
                    args.mode = "-c"
                elif char == "d":
                    if args.mode and args.mode != "-d":
                        raise ValueError("Conflicting modes specified (-c and -d).")
                    args.mode = "-d"
                elif char == "b":
                    args.block_mode = True
                else:
                    raise ValueError(f"Invalid option: -{char}")
        else:
            if args.key is not None:
                raise ValueError("Multiple keys provided.")
            args.key = token

    if not args.mode:
        raise ValueError("A valid mode (-c or -d) is required.")

    if args.key is None:
        raise ValueError("A key is required for ciphering or deciphering.")
    return args
