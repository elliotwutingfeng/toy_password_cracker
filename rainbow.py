import json
import random
from itertools import repeat
from multiprocessing import Pool
from string import ascii_lowercase
from typing import Callable, Optional

import dill
from tqdm import tqdm

from hashing import md5_hexdigest
from logging_utils import logger

DEFAULT_RAINBOW_TABLE_FILENAME = "RainbowTable.json"
DEFAULT_RAINBOW_TABLE_PASSWORD_LENGTH = 5


def make_chain(args) -> tuple[str, str]:
    allowed_characters = args["allowed_characters"]
    password_length = args["password_length"]
    chain_length = args["chain_length"]
    hash_function_dump = args["hash_function_dump"]
    reduction_function_dump = args["reduction_function_dump"]

    start = "".join(random.choice(allowed_characters) for _ in range(password_length))
    plaintext = start

    hash_function = dill.loads(hash_function_dump)
    reduction_function = dill.loads(reduction_function_dump)

    for col in range(chain_length):
        hashcode = hash_function(plaintext)
        plaintext = reduction_function(hashcode, col)

    return hashcode, start


def make_table(
    allowed_characters: str,
    password_length: int,
    chain_length: int,
    hash_function: Callable,
    reduction_function: Callable,
    rows: int,
) -> dict[str, str]:
    table: dict[str, str] = {}
    with Pool() as p:
        hash_function_dump = dill.dumps(hash_function)
        reduction_function_dump = dill.dumps(reduction_function)
        logger.info("Generating rainbow table...")
        for hashcode, start in p.imap_unordered(
            make_chain,
            tqdm(
                repeat(
                    {
                        "allowed_characters": allowed_characters,
                        "password_length": password_length,
                        "chain_length": chain_length,
                        "hash_function_dump": hash_function_dump,
                        "reduction_function_dump": reduction_function_dump,
                    },
                    rows,
                ),
                total=rows,
            ),
            chunksize=2**8,
        ):
            table[hashcode] = start
    return table


class RainbowTable:
    def __init__(
        self,
        hash_function: Callable,
        allowed_characters: str,
        chain_length: int,
        password_length: int = DEFAULT_RAINBOW_TABLE_PASSWORD_LENGTH,
    ) -> None:
        self.table = {}
        self.hash_function = hash_function
        self.reduction_function = self.gen_reduction_function(
            password_length, allowed_characters
        )
        self.password_length = password_length
        self.allowed_characters = allowed_characters
        self.chain_length = chain_length

    def gen_reduction_function(
        self, password_length: int, allowed_characters: str
    ) -> Callable:
        def result(hash_text: str, col: int) -> str:
            plaintext = ""
            plaintext_key: int = (int(hash_text[:9], 16) ^ col) % (
                len(allowed_characters) ** password_length
            )
            for _ in range(password_length):
                plaintext += allowed_characters[plaintext_key % len(allowed_characters)]
                plaintext_key //= len(allowed_characters)
            return plaintext

        return result

    def generate(
        self,
        filename: str = DEFAULT_RAINBOW_TABLE_FILENAME,
        rows: int = 3 * 10**6,
        save_to_file: bool = False,
        extend: bool = False,
    ) -> None:
        if not extend:
            self.table = {}
        self.table.update(
            make_table(
                self.allowed_characters,
                self.password_length,
                self.chain_length,
                self.hash_function,
                self.reduction_function,
                rows,
            )
        )
        if save_to_file:
            with open(filename, "w") as f:
                json.dump(self.table, f)

    def load(self, filename: str = DEFAULT_RAINBOW_TABLE_FILENAME) -> None:
        with open(filename, "r") as f:
            self.table = json.load(f)

    def crack(self, hashed_password: str) -> Optional[str]:
        for start_col in range(self.chain_length - 1, -1, -1):
            candidate = hashed_password
            for col in range(start_col, self.chain_length):
                candidate = self.hash_function(
                    self.reduction_function(candidate, col - 1)
                )
            if candidate in self.table:
                traversal_result = self.traverse_chain(
                    hashed_password, self.table[candidate]
                )
                if traversal_result:
                    return traversal_result
        return None

    def traverse_chain(self, hashed_password: str, start: str) -> Optional[str]:
        for col in range(self.chain_length):
            hash = self.hash_function(start)
            if hash == hashed_password:
                return start
            start = self.reduction_function(hash, col)
        return None


if __name__ == "__main__":
    # Here, you can generate your own precomputed rainbow table.
    table = RainbowTable(
        hash_function=md5_hexdigest,
        allowed_characters=ascii_lowercase,
        chain_length=100,  # Can be increased to reduce memory usage
    )
    table.generate(
        rows=3 * 10**6,
        filename=f"Another{DEFAULT_RAINBOW_TABLE_FILENAME}",  # WARNING: Content of file at `filename` will be replaced!
        save_to_file=True,
    )
