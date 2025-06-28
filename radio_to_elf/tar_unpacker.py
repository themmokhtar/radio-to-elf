import os
import logging
import tarfile

from io import BytesIO

from unpacker import Unpacker

from exceptions import BadFileError, FileParsingError


class TarUnpacker(Unpacker):

    def get_format_name(self) -> str:
        return "TapeARchive"

    def check_can_unpack(self, data: bytes) -> bool:
        with BytesIO(data) as f:
            return tarfile.is_tarfile(f)

    def unpack(self, data: bytes) -> bytes:
        with BytesIO(data) as f:
            with tarfile.open(mode='r', fileobj=f) as tf:
                for member in tf.getmembers():
                    if (member.isfile() or member.islink()) and member.name.endswith(".ext4"):
                        reader = tf.extractfile(member)
                        return reader.read()
                    else:
                        logging.info(
                            f"Skipping unwanted tar entry \"{member.name}\"")
