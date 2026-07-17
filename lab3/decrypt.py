import sqlite3
from pathlib import Path

from Crypto.Cipher import AES

KEY = bytes(
    b"\x93n\x12\xcbC\xe0|\xd0\xa6%7(?KW\xa9\xc2\x02\x97\xc6\\\xd6\xd9c\xf4x\xb9\xe2\x89\x88<\x9d"
)

DB_PATH = Path(__file__).resolve().parent / "database.db"


def decrypt_password(db_path: Path = DB_PATH) -> str:
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    row = cur.execute("SELECT * FROM users").fetchone()
    conn.close()

    if row is None:
        raise ValueError("No users found in database")

    encrypted_password = row[1]
    if isinstance(encrypted_password, str):
        encrypted_password = encrypted_password.encode("latin-1")

    nonce = encrypted_password[:16]
    tag = encrypted_password[16:32]
    ciphertext = encrypted_password[32:]

    cipher = AES.new(KEY, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


if __name__ == "__main__":
    print("Database:", DB_PATH)
    print("Plaintext password:", decrypt_password(DB_PATH))
