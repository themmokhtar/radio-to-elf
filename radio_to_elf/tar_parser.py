from __future__ import annotations

import struct
import zlib

from dataclasses import dataclass
from typing import ClassVar

@dataclass
class TarHeaderInfo:
    # SIZE: ClassVar[int] = 512
    SIZE: ClassVar[int] = 512

    file_path: str
    file_mode: str
    owner_uid: str
    owner_gid: str
    file_size: int
    file_mtime: int
    header_checksum: int
    # name: str
    # file_offset: int
    # load_address: int
    # size: int
    # crc: int
    # entry_id: int

    @staticmethod
    def from_bytes(data: bytes) -> TarHeaderInfo:
        header = struct.unpack("<100s8s4s4s8s12s8s368s", data)

        calculated_checksum = sum(struct.unpack("<148B", data[:148]) + (ord(' '),) * 8 + struct.unpack("<356B", data[156:]))
        # calculated_checksum = sum(struct.unpack("<74H", data[:148]) + (ord(' '),) * 8 + struct.unpack("<178H", data[156:]))
        # calculated_checksum = zlib.crc32(data)
        # calculated_checksum = sum(struct.unpack("<37I", data[:148]) + (ord(' '),) * 8 + struct.unpack("<89I", data[156:]))
        print(calculated_checksum)
        # header = struct.unpack("<100s8s4s4s8s12s8s", data)

        return TarHeaderInfo(header[0].rstrip(b'\x00').decode(), # file_path
                             header[1].rstrip(b' \x00').decode(), # file_mode
                             header[2], # owner_uid
                             header[3], # owner_gid
                             int(header[4].rstrip(b' \x00').decode(), 8), # file_size
                             int(header[5].rstrip(b' \x00').decode(), 8), # file_mtime
                             int(header[6].rstrip(b' \x00').decode(), 8), # header_checksum
                             )

    def verify_header_checksum(self) -> None:
        if self.crc == 0:
            logging.debug(f"Skipped CRC checksum check for {self.name} section due to unspecified checksum")
            return

        section_data = self.slice_section_data(data)
        section_crc = zlib.crc32(section_data)
        
        if section_crc != self.crc:
            raise FileParsingError(
                f"Failed to parse TOC header with invalid {self.name} section data CRC checksum (expected 0x{self.crc:08x}, got 0x{section_crc:08x})")

        logging.debug(f"CRC checksum for {self.name} section verified")

    # def __repr__(self):
    #     return f"{self.__class__.__name__}(name='{self.name}', file_offset=0x{self.file_offset:08x}, load_address=0x{self.load_address:08x}, size=0x{self.size:08x}, crc=0x{self.crc:08x}, entry_id={self.entry_id})"

    # def


class TarParser:
    @staticmethod
    def parse(data: bytes) -> dict:
        header = TarHeaderInfo.from_bytes(data[:TarHeaderInfo.SIZE])
        print(header)
