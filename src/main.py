#!/usr/bin/env python3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    try:
        if len(sys.argv) < 2:
            raise ValueError(
                "No command provided. Please specify a command to execute."
            )
        return 0
    except Exception as err:
        sys.stderr.write(f"Error: {err}\n")
        return 84


if __name__ == "__main__":
    sys.exit(main())
