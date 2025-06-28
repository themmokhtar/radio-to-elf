import os
import logging

from io import BytesIO

from fbpacktool import fbpack
from fbpacktool.fbpacktool import bytes_to_str
from unpacker import Unpacker

from exceptions import BadFileError, FileParsingError


class FastbootUnpacker(Unpacker):

    def get_format_name(self) -> str:
        return "FastBootPacK"

    def check_can_unpack(self, data: bytes) -> bool:
        return data[:4] == b"FBPK"

    def unpack(self, data: bytes) -> bytes:
        with BytesIO(data) as f:
            pack = fbpack.CommonPackHeader.from_bytes(
                f.read(len(fbpack.CommonPackHeader())))

            f.seek(0, os.SEEK_SET)

            if pack.version == fbpack.FBPACK_VERSION:
                pack = fbpack.PackHeader.from_bytes(
                    f.read(len(fbpack.PackHeader())))
            elif pack.version == fbpack.FBPACK_VERSION_V1:
                pack = fbpack.PackHeaderV1.from_bytes(
                    f.read(len(fbpack.PackHeaderV1())))
            else:
                raise FileParsingError(
                    f'Unsupported FastBootPacK version {pack.version}')

            next_offset = len(pack)

            # Find the entry we want to extract
            for _ in range(pack.total_entries):
                if pack.version == fbpack.FBPACK_VERSION:
                    entry = fbpack.PackEntry.from_bytes(
                        f.read(len(fbpack.PackEntry())))
                    offset = entry.offset
                else:
                    f.seek(next_offset, os.SEEK_SET)
                    entry = fbpack.PackEntryV1.from_bytes(
                        f.read(len(fbpack.PackEntryV1())))
                    offset = f.tell()
                    next_offset = (entry.next_offset_h <<
                                   32) | entry.next_offset

                if entry.type == 0:
                    # Ignore partition table entries, next_offset will tell us
                    # where to go next
                    continue

                name = bytes_to_str(entry.name)
                if name == "modem":
                    return data[offset:offset + entry.size]
                else:
                    logging.info(f"Skipping unwanted FastBootPacK entry \"{name}\"")

            raise BadFileError(
                "Failed to find modem entry in fastboot package")
