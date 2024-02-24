# Toy Password Cracker

![Python](https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue)
[![LICENSE](https://img.shields.io/badge/LICENSE-BSD--3--CLAUSE-GREEN?style=for-the-badge)](LICENSE)

Toy demonstration of common password cracking methods, namely, brute force, dictionary attacks, and rainbow tables. Hashing algorithms used are MD5, PBKDF2, Scrypt, Balloon, and Argon2id.

## Requirements

- Python 3.11

## Usage

Run the following

```bash
git clone --depth 1 --recurse-submodules --shallow-submodules https://github.com/elliotwutingfeng/toy_password_cracker.git
cd toy_password_cracker

# If you do not have wget you can either install it first, or download the file via your web browser
wget -O 'crackstation-human-only.txt.gz' 'https://crackstation.net/files/crackstation-human-only.txt.gz'

python3 -m venv venv
venv/bin/python3 -m pip install --upgrade pip
venv/bin/python3 -m pip install -r requirements.txt
venv/bin/python3 toy_password_cracker.py
```

You can also generate your own pre-computed rainbow tables (multi-core CPU recommended).

```bash
venv/bin/python3 rainbow.py
```

## Sample output

```text
Cracking MD5
Method: Brute Force | Hash algorithm: md5_hexdigest | Elapsed time: 3.519825 seconds | Plaintext password: PASS
Method: Dictionary Attack | Hash algorithm: md5_hexdigest | Elapsed time: 31.884403 seconds | Plaintext password: PASSW0RD!
Method: Rainbow Table | Hash algorithm: md5_hexdigest | Elapsed time: 0.060471 seconds | Plaintext password: panda

Comparing different cracking methods for the MD5 hash of 'hoofs'
Method: Brute Force | Hash algorithm: md5_hexdigest | Elapsed time: 2.344848 seconds | Plaintext password: hoofs
Method: Dictionary Attack | Hash algorithm: md5_hexdigest | Elapsed time: 0.319403 seconds | Plaintext password: hoofs
Method: Rainbow Table | Hash algorithm: md5_hexdigest | Elapsed time: 0.057783 seconds | Plaintext password: hoofs

Comparing different KDFs (dictionary attack)
Method: Dictionary Attack | Hash algorithm: md5_hexdigest | Elapsed time: 0.000144 seconds | Plaintext password: cookie
Method: Dictionary Attack | Hash algorithm: pbkdf2_hexdigest | Elapsed time: 12.774528 seconds | Plaintext password: cookie
Method: Dictionary Attack | Hash algorithm: scrypt_hexdigest | Elapsed time: 26.034614 seconds | Plaintext password: cookie
Method: Dictionary Attack | Hash algorithm: balloon_hexdigest | Elapsed time: 1.467182 seconds | Plaintext password: cookie
Method: Dictionary Attack | Hash algorithm: argon2_digest | Elapsed time: 1.741409 seconds | Plaintext password: cookie
```

## Further reading

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Password Hashing Competition](https://www.password-hashing.net)
- [Cryptography Guidelines by Samuel Lucas (read the password hashing section)](https://github.com/samuel-lucas6/Cryptography-Guidelines)
