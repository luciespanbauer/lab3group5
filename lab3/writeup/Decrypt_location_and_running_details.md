## Location of `decrypt.py`

The decryption script is included in the project submission as `decrypt.py`. It is located in the same directory as the application's `database.db` file so that it can automatically locate and open the database.

## How to Run `decrypt.py`

### Prerequisites

* Python 3 installed
* PyCryptodome installed

If PyCryptodome is not already installed, install it with:

```bash
pip install pycryptodome
```

### Running the Script

1. Open a terminal or command prompt.
2. Navigate to the directory containing `decrypt.py` and `database.db`.
3. Run the following command:

```bash
python decrypt.py
```

(or `python3 decrypt.py` on systems where Python 3 is invoked with `python3`).

The script will connect to `database.db`, retrieve the encrypted password from the `users` table, decrypt it using the AES key defined in the script, and print the recovered plaintext password to the terminal.
