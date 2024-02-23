import gzip
import random
from abc import ABC, abstractmethod
from hmac import compare_digest
from itertools import product
from string import ascii_letters, ascii_lowercase
from time import perf_counter
from typing import Callable, Generator, Optional, Union

import argon2
from rainbow import RainbowTable

from hashing import (
    argon2_digest,
    balloon_hexdigest,
    md5_hexdigest,
    pbkdf2_hexdigest,
    scrypt_hexdigest,
)
from logging_utils import logger

random.seed(42)  # For predictable output.

TXT_LIST = "10-million-password-list-top-1000000.txt"  # From https://github.com/danielmiessler/SecLists


class BruteForceParams:
    def __init__(self, allowed_characters: str, maximum_password_length: int) -> None:
        self.allowed_characters = allowed_characters
        self.maximum_password_length = maximum_password_length


class Source(ABC):
    @abstractmethod
    def stream(self) -> Generator[str, None, None]:
        pass


class BruteForce(Source):
    def __init__(self, brute_force_params: BruteForceParams) -> None:
        super().__init__()
        self.allowed_characters = brute_force_params.allowed_characters
        self.maximum_password_length = brute_force_params.maximum_password_length

    def stream(self) -> Generator[str, None, None]:
        for length in range(1, self.maximum_password_length + 1):
            for password_chars in product(
                tuple(self.allowed_characters),
                repeat=length,
            ):
                yield "".join(password_chars)


class Dictionary(Source):
    def __init__(self, filename: str, filetype: str) -> None:
        super().__init__()
        self.filename = filename
        self.filetype = filetype

    def stream(self) -> Generator[str, None, None]:
        fopen = gzip.open if self.filetype == "gzip" else open
        with fopen(self.filename, "rt", encoding="utf-8", errors="ignore") as f:
            for line in f:
                yield line.removesuffix("\n")


class PasswordHash:
    def __init__(self, password: str, salt: str, hash_algo: Callable) -> None:
        self.hash_text = hash_algo(password + (salt if isinstance(salt, str) else ""))
        self.hash_algo = hash_algo


def verify_password(maybe_password: str, target_hash: str, hash_algo: Callable) -> bool:
    if hash_algo.__name__ == "argon2_digest":
        try:
            argon2.PasswordHasher().verify(target_hash, maybe_password)
        except argon2.exceptions.VerifyMismatchError:
            return False
        return True
    if compare_digest(hash_algo(maybe_password), target_hash):
        return True
    return False


def search(source: Source, password_hash: PasswordHash) -> Optional[str]:
    for maybe_password in source.stream():
        if verify_password(
            maybe_password, password_hash.hash_text, password_hash.hash_algo
        ):
            return maybe_password
    return None


def crack(
    password_hash: PasswordHash,
    brute_force_params: BruteForceParams,
    dictionary_source: Optional[str] = None,
    dictionary_filetype: Optional[str] = None,
    rainbow_table: Union[str, bool] = False,
) -> str:
    time_start = perf_counter()

    maybe_password = None

    method_used = "Rainbow Table"

    if rainbow_table:
        table = RainbowTable(
            hash_function=password_hash.hash_algo,
            allowed_characters=brute_force_params.allowed_characters,
            chain_length=100,
        )
        # The arguments `hash_function`, `allowed_characters`, `chain_length`
        # must be the same as those used to generate the `rainbow_table`
        # that we are about to load.
        if isinstance(rainbow_table, str):
            table.load(rainbow_table)  # rainbow_table may be a filename
        else:
            table.load()
        maybe_password = table.crack(password_hash.hash_text)

    if maybe_password is None and dictionary_source:
        method_used = "Dictionary Attack"
        maybe_password = search(
            Dictionary(dictionary_source, dictionary_filetype), password_hash
        )

    if maybe_password is None:
        method_used = "Brute Force"
        maybe_password = search(BruteForce(brute_force_params), password_hash)

    time_end = perf_counter()

    if maybe_password is None:
        raise ValueError(
            "Brute force failed. Either `maximum_password_length` is too short,"
            " or password contains characters not found in `allowed_characters`"
        )

    logger.info(
        "Method: %s | Hash algorithm: %s | Elapsed time: %lf seconds | Plaintext password: %s",
        method_used,
        password_hash.hash_algo.__name__,
        time_end - time_start,
        maybe_password,
    )
    return maybe_password


if __name__ == "__main__":
    logger.info("Cracking MD5")
    crack(PasswordHash("PASS", "", md5_hexdigest), BruteForceParams(ascii_letters, 4))
    crack(
        PasswordHash("PASSW0RD!", "", md5_hexdigest),
        BruteForceParams(ascii_letters, 9),
        dictionary_source="crackstation-human-only.txt.gz",
        dictionary_filetype="gzip",
    )
    crack(
        PasswordHash("panda", "", md5_hexdigest),
        BruteForceParams(ascii_lowercase, 5),
        rainbow_table=True,
    )

    logger.info("")

    word = "hoofs"
    logger.info("Comparing different cracking methods for the MD5 hash of '%s'", word)
    crack(
        PasswordHash(word, "", md5_hexdigest),
        BruteForceParams(ascii_lowercase, len(word)),
    )  # Slower if most letters are at the end of alphabet.
    crack(
        PasswordHash(word, "", md5_hexdigest),
        BruteForceParams(ascii_lowercase, len(word)),
        dictionary_source=TXT_LIST,
    )  # Slower if password is near the end of the word list.
    crack(
        PasswordHash(word, "", md5_hexdigest),
        BruteForceParams(ascii_lowercase, len(word)),
        rainbow_table=True,
    )  # Slower if chain length is long.

    logger.info("")

    # A naive comparison of dictionary attack performance across popular Key Derivation Functions (KDFs).
    # There are many factors to consider when determining if a KDF is good or bad, which are beyond the
    # scope of this repository (i.e. do not look at the benchmark results and conclude that `scrypt` is the best
    # just because it is the slowest.)

    logger.info("Comparing different KDFs (dictionary attack)")
    for hash_algo in (
        md5_hexdigest,
        pbkdf2_hexdigest,
        scrypt_hexdigest,
        balloon_hexdigest,
        argon2_digest,
    ):
        crack(
            PasswordHash("cookie", "", hash_algo),
            BruteForceParams(ascii_letters, 2),
            dictionary_source=TXT_LIST,
        )
