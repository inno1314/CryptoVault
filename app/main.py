import argparse
import getpass
from base64 import b64encode, b64decode

from .crypto import derive_key, encrypt, decrypt, generate_salt
from .storage import load_vault, save_vault


def prompt_passphrase():
    return getpass.getpass("Enter passphrase: ")


def main():
    parser = argparse.ArgumentParser(description="CLI tool for password management.")
    parser.add_argument(
        "-a", "--add", help="Add a new password entry", metavar="ENTRY_NAME"
    )
    parser.add_argument(
        "-g", "--get", help="Get a password entry", metavar="ENTRY_NAME"
    )
    parser.add_argument("-l", "--list", help="List all entries", action="store_true")
    parser.add_argument("-d", "--delete", help="Delete entry", metavar="ENTRY_NAME")
    parser.add_argument(
        "-cp", "--change-passphrase", help="Change passphrase", action="store_true"
    )
    args = parser.parse_args()

    vault = load_vault()
    if vault:
        salt = b64decode(vault["salt"])
        key = derive_key(prompt_passphrase(), salt)
        entries = {}
        for name, blob in vault["entries"].items():
            entries[name] = blob
    else:
        # Новый файл
        print("Creating a new vault...")
        salt = generate_salt()
        key = derive_key(prompt_passphrase(), salt)
        entries = {}

    if args.add:
        name = args.add
        password = getpass.getpass("Enter password to store: ").encode()
        nonce, ct, tag, hmac_tag = encrypt(password, key)
        entries[name] = {
            "nonce": b64encode(nonce).decode(),
            "ct": b64encode(ct).decode(),
            "tag": b64encode(tag).decode(),
            "hmac": b64encode(hmac_tag).decode(),
        }
        print(f"Entry '{name}' added.")

    elif args.get:
        name = args.get
        if name not in entries:
            print(f"Entry '{name}' not found.")
            return
        blob = entries[name]
        try:
            password = decrypt(
                b64decode(blob["nonce"]),
                b64decode(blob["ct"]),
                b64decode(blob["tag"]),
                key,
                b64decode(blob["hmac"]),
            )
            print(f"{name}: {password.decode()}")
        except ValueError as e:
            print("Ошибка дешифровки:", e)

    elif args.list:
        print("Stored entries:")
        for name in entries.keys():
            print(f"- {name}")

    elif args.delete:
        name = args.delete
        if name in entries:
            del entries[name]
            print(f"Entry '{name}' deleted.")
        else:
            print(f"No such entry: {name}")

    elif args.change_passphrase:
        new_passphrase = getpass.getpass("New passphrase: ")
        new_salt = generate_salt()
        new_key = derive_key(new_passphrase, new_salt)
        new_entries = {}
        for name, blob in entries.items():
            # Расшифровать старыми ключами
            plaintext = decrypt(
                b64decode(blob["nonce"]),
                b64decode(blob["ct"]),
                b64decode(blob["tag"]),
                key,
                b64decode(blob["hmac"]),
            )
            # Зашифровать с новым ключом
            nonce, ct, tag, hmac_tag = encrypt(plaintext, new_key)
            new_entries[name] = {
                "nonce": b64encode(nonce).decode(),
                "ct": b64encode(ct).decode(),
                "tag": b64encode(tag).decode(),
                "hmac": b64encode(hmac_tag).decode(),
            }
        salt = new_salt
        entries = new_entries
        print("Пароль для хранилища успешно обновлён.")

    else:
        parser.print_help()
        return

    # Сохраняем изменения
    save_vault({"salt": b64encode(salt).decode(), "entries": entries})


if __name__ == "__main__":
    main()
