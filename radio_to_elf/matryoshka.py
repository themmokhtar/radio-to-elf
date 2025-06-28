import logging

from fastboot_unpacker import FastbootUnpacker
from tar_unpacker import TarUnpacker

UNPACKERS = [
    FastbootUnpacker(),
    TarUnpacker()
]


def matryoshka_unpack(data: bytes) -> bytes:

    unpackers_exhausted = False
    while not unpackers_exhausted:
        unpackers_exhausted = True

        for unpacker in UNPACKERS:
            if unpacker.check_can_unpack(data):
                logging.info(
                    f"Unpacking detected {unpacker.get_format_name()} package format")
                data = unpacker.unpack(data)

                unpackers_exhausted = False
                break

    return data
