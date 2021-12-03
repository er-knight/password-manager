import json
import os
import pathlib
import pyperclip
import random
import string

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def clear_screen():

    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

def random_id():

    return "".join(
        random.sample(
            string.ascii_letters + string.digits, k=5
        )
    )

def show(entry):

    for field in entry:
        if entry[field]: print(f"{field.rjust(8)}: {entry[field]}")

def copy_to_clipboard(password):

    pyperclip.copy(password)
    print("password copied to clipboard")

def encrypt_and_dump(file, password, data):

    AES_256_CBC = AES.new(
        SHA256.new(password.encode("utf-8")).digest(),
        AES.MODE_CBC
    )

    with open(file, "wb") as f:
        padded_data = pad(
            bytes(json.dumps(data), encoding="utf-8"), 16
        )
        encrypted_data = AES_256_CBC.encrypt(padded_data)
        f.write(AES_256_CBC.iv + encrypted_data)

def decrypt_and_load(file, password):

    file_path = pathlib.Path(file)
    if not file_path.exists() or file_path.stat().st_size == 0:
        return {}

    with open(file, "rb") as f:
        iv = f.read(16)
        AES_256_CBC = AES.new(
            SHA256.new(password.encode("utf-8")).digest(),
            AES.MODE_CBC, iv
        )
        decrypted_data = AES_256_CBC.decrypt(f.read())
        unpadded_data  = unpad(decrypted_data, 16)
        data = json.loads(unpadded_data)

    return data

def insert(data, website):

    username = input(
        "insert username? [y]es/[n]o: "
    ).strip().lower()[0] == "y"
    username = input("username: ").strip() if username else None

    email = input(
        "insert email? [y]es/[n]o: "
    ).strip().lower()[0] == "y"
    email = input("email: ").strip() if email else None

    mobile = input(
        "insert mobile? [y]es/[n]o: "
    ).strip().lower()[0] == "y"
    mobile = input("mobile: ").strip() if mobile else None

    password = input(
        "insert password? [y]es/[n]o: "
    ).strip().lower()[0] == "y"
    password = input("password: ").strip() if password else None

    entry = {
        "username" : username,
        "email"    : email,
        "mobile"   : mobile,
        "password" : password
    }

    if website in data:
        for _entry in data[website].values():
            if _entry == entry:
                print("similar entry already exists, try update")
                return data

    existing_ids = data.get(website, {}).keys()

    _id = random_id()
    while _id in existing_ids:
        _id = random_id()

    data[website] = data.get(website, {})
    data[website][_id] = entry

    return data

def search(data, website):

    if not data or website not in data:
        print("data not found for website: {website}"); return

    for _id, entry in data[website].items():
        show(entry)

        copy_password = input(
            "copy password? [y]es/[n]o: "
        ).strip().lower()[0]

        if copy_password == "y":
            copy_to_clipboard(entry["password"])

def update(data, website):

    if not data or website not in data:
        print("data not found for website: {website}, try insert")
        return data

    for _id, entry in data[website].items():
        show(entry)

        to_update = input(
            "which to update?\n[u]sername, [e]mail, [m]obile or [p]assword: "
        ).strip().lower()[0]

        if to_update == "u":
            username = input("username: ").strip()
            data[website][_id]["username"] = username
        if to_update == "e":
            email = input("email: ").strip()
            data[website][_id]["email"] = email
        if to_update == "m":
            mobile = input("mobile: ").strip()
            data[website][_id]["mobile"] = mobile
        if to_update == "p":
            password = input("password: ").strip()
            data[website][_id]["password"] = password

    return data
            
def main():

    FILE = "data.enc"

    clear_screen()

    password = input("enter password: ")

    _exit = False
    while not _exit:

        decrypted_data = decrypt_and_load(FILE, password)

        website = input("website: ").strip()

        option = input(
            "options? [i]nsert/[s]earch/[u]pdate: "
        ).strip().lower()[0]

        if option == "i":
            updated_data = insert(decrypted_data, website)
            encrypt_and_dump(FILE, password, updated_data)

        if option == "s":
            search(decrypted_data, website)

        if option == "u":
            updated_data = update(decrypted_data, website)
            encrypt_and_dump(FILE, password, updated_data)

        _exit = input("exit? [y]es/[n]o: ").strip().lower()[0] == "y"

if __name__ == "__main__":

    main()
