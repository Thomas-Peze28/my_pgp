#!/usr/bin/env python3
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = current_dir if os.path.basename(current_dir) == "src" else os.path.join(current_dir, "src")

if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from cli.parser import parse_arguments


def main() -> int:
    try:
        args = parse_arguments(sys.argv)
        print(f"Parsed arguments: {args}")
        return 0
    except Exception as err:
        sys.stderr.write(f"Error: {err}\n")
        return 84


if __name__ == "__main__":
    sys.exit(main())
