"""Generate an scrypt hash for ADMIN_PASSWORD_HASH.

Usage:
    python -m app.hashpw            # prompts (no echo)
    python -m app.hashpw 'secret'   # from argv (shell history — prefer the prompt)
"""
import getpass
import sys

from .security import hash_password


def main() -> None:
    if len(sys.argv) > 1:
        pw = sys.argv[1]
    else:
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Confirm : "):
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    if not pw:
        print("Empty password.", file=sys.stderr)
        sys.exit(1)
    print(hash_password(pw))


if __name__ == "__main__":
    main()
