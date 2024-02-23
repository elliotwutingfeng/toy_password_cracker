from hashlib import md5
from importlib import import_module
from typing import Optional

import argon2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

balloon = import_module("balloon-hashing.balloon")


def md5_hexdigest(password: str, salt: Optional[str] = None) -> str:
    return md5(
        (password + (salt if salt else "")).encode("utf-8"), usedforsecurity=False
    ).hexdigest()


def pbkdf2_hexdigest(password: str, salt: Optional[str] = None) -> str:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8") if isinstance(salt, str) else b"",
        iterations=600_000,
    )
    return kdf.derive(password.encode("utf-8")).hex()


def scrypt_hexdigest(password: str, salt: Optional[str] = None) -> str:
    kdf = Scrypt(
        salt.encode("utf-8") if isinstance(salt, str) else b"",
        length=32,
        n=2**17,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8")).hex()


def balloon_hexdigest(password: str, salt: Optional[str] = None) -> str:
    return balloon.balloon_m(
        password,
        (salt if salt else ""),
        space_cost=16,
        time_cost=20,
        parallel_cost=4,
        delta=4,
    ).hex()


def argon2_digest(password: str, salt: Optional[str] = None) -> str:
    if salt:
        raise ValueError(
            "Argon2 does not accept a salt; remove salt argument from function call"
        )
    return argon2.PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1).hash(
        password
    )
