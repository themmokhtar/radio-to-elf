from __future__ import annotations

import re
import struct
import logging
import string
import zlib

from dataclasses import dataclass
from typing import ClassVar

from exceptions import BadFileError, FileParsingError


def hexdump(data: bytes, line_size: int = 16) -> None:
    chunks = [data[i:i+line_size] for i in range(0, len(data), line_size)]

    offset = 0
    for chunk in chunks:
        printables = set(bytes(
            "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", 'ascii'))

        padding_count = line_size - len(chunk)
        data_hex = " ".join(
            [f"{x:02x}" for x in chunk]) + " " * 3 * padding_count
        data_ascii = "".join(
            [(chr(x) if x in printables else ".") for x in chunk])

        logging.debug(f"{offset:06x}: {data_hex} {data_ascii}")
        offset += line_size


# All the patterns specified in this class are courtesy of Grant-H and his team
# Many many thanks to their amazing team for making their research public
# https://github.com/grant-h/ShannonBaseband.git
class RegexDB:
    SOC_VERSION = re.compile(
        # SoC identifier
        b"(?P<SoC>[S][0-9]{3,4}(AP)?)"
        # garbage or unknown (usually underscores)
        b".{0,10}"
        # Date as YYYYMMDD (for rough SoC revision)
        b"(?P<date>[0-9]{8})"
        # null terminator
        b"[^\\x00]*"
    )

    SHANNON_VERSION = re.compile(
        # Match until end of string
        b"(ShannonOS.*?)[\\x00]"
    )

    # This pattern needs explaining. An MPU entry is a table that Shannon
    # will process to populate the MPU table of the Cortex-R series CPU.
    # Each entry is 40 bytes (10 words little-endian) with this layout (each field is 4 bytes):
    #
    # [slot][base][size][access_control]{6}[enable]
    #
    # Slot - the architectural MPU slot number
    # Base - the base address the MPU entry should apply to
    # Size - a size code that indicates the memory range an entry should cover
    # Access Control - a series of 6 words that are OR'd together to form the MPU permissions
    # Enable - whether this MPU entry is enabled (usually 1)
    #
    # SO...now about this pattern. Well this pattern is matching the first MPU entry.
    #
    # This is a different pattern from the one provided by Grant and his team. The one they provided did not work on the newer images I tried.
    # I wrote one that searches with the least number of "known address values," and depends more on the things that won't change over time (structure size and offsets etc...)
    # See the comments inline.
    MPU_TABLE = re.compile(
        b"".join(
            [
                # the entry slot ID of x
                struct.pack("<I", x) +
                # a start address of zero for the first slot, and any address for the rest
                (b"[\\x00]{4}" if x == 0 else b".{4}") +
                # 7 arbitrary 4-byte values
                b".{28}"
                # the enable boolean of 1
                b"\\x01\\x00\\x00\\x00"
                # For 4 slots (this could be adjusted)
                for x in range(4)
            ]
        )
    )


@dataclass
class TocHeaderInfo:
    SIZE: ClassVar[int] = 32

    name: str
    file_offset: int
    load_address: int
    size: int
    crc: int
    entry_id: int

    @staticmethod
    def from_bytes(data: bytes) -> TocHeaderInfo:
        header = struct.unpack("<12s5I", data)
        return TocHeaderInfo(header[0].rstrip(b'\x00').decode(), header[1], header[2], header[3], header[4], header[5])

    def slice_section_data(self, data: bytes) -> bytes:
        return data[self.file_offset:self.file_offset + self.size]

    def verify_data_checksum(self, data: bytes) -> None:
        if self.crc == 0:
            logging.debug(
                f"Skipped CRC checksum check for {self.name} section due to unspecified checksum")
            return

        section_data = self.slice_section_data(data)
        section_crc = zlib.crc32(section_data)

        if section_crc != self.crc:
            raise FileParsingError(
                f"Failed to parse TOC header with invalid {self.name} section data CRC checksum (expected 0x{self.crc:08x}, got 0x{section_crc:08x})")

        logging.debug(f"CRC checksum for {self.name} section verified")

    def __repr__(self):
        return f"{self.__class__.__name__}(name='{self.name}', file_offset=0x{self.file_offset:08x}, load_address=0x{self.load_address:08x}, size=0x{self.size:08x}, crc=0x{self.crc:08x}, entry_id={self.entry_id})"


@dataclass
class MpuSlotInfo:
    SIZE: ClassVar[int] = 40

    slot_id: int
    base_address: int
    mpu_rasr: int
    enabled: bool

    @staticmethod
    def from_bytes(data: bytes) -> MpuSlotInfo:
        slot = struct.unpack("<3I4s4s4s4s4s4s1I", data)
        mpu_rasr = bytes([(a | b | c | d | e | f)
                          for (a, b, c, d, e, f) in zip(*slot[3:9])])
        mpu_rasr = (struct.unpack("<I", mpu_rasr)[0] << 16) | slot[2] | slot[9]

        return MpuSlotInfo(data[0], slot[1], mpu_rasr, slot[9] != 0)

    def get_is_enabled(self) -> bool:
        return ((self.mpu_rasr) & 0b1) == 1

    def get_actual_size(self) -> int:
        actual_size = (self.mpu_rasr >> 1) & 0b11111

        if actual_size < 0b00111:  # These are reserved according to the ARM Cortex documentation of the MPU_RASR size bit assignments
            raise FileParsingError(
                "Failed to parse MPU slot due to invalid MPU_RASR size bits")

        return 2 ** (actual_size - 1)

    def get_ap_bits(self) -> int:
        ap_bits = (self.mpu_rasr >> 24) & 0b111

        if ap_bits == 0b100:  # This value is reserved according to the ARM Cortex documentation of the MPU_RASR AP bit assignments
            raise FileParsingError(
                "Failed to parse MPU slot due to invalid MPU_RASR AP bits")

        return ap_bits

    def get_priv_readable(self) -> bool:
        return self.get_ap_bits() in [0b001, 0b010, 0b011, 0b101, 0b110, 0b111]

    def get_priv_writable(self) -> bool:
        return self.get_ap_bits() in [0b001, 0b010, 0b011]

    def get_unpriv_readable(self) -> bool:
        return self.get_ap_bits() in [0b010, 0b011, 0b110, 0b111]

    def get_unpriv_writable(self) -> bool:
        return self.get_ap_bits() in [0b011]

    def get_executable(self) -> bool:
        return ((self.mpu_rasr >> 28) & 0b1) == 0

    def __repr__(self):
        return f"{self.__class__.__name__}(slot_id={self.slot_id}, base_address=0x{self.base_address:08x}, mpu_rasr=0x{self.mpu_rasr:08x} [" + \
            f"priv_perms={'r' if self.get_priv_readable() else '-'}{'w' if self.get_priv_writable() else '-'}{'x' if self.get_executable() else '-'}, " + \
            f"unpriv_perms={'r' if self.get_unpriv_readable() else '-'}{'w' if self.get_unpriv_writable() else '-'}{'x' if self.get_executable() else '-'}, " + \
            f"size=0x{self.get_actual_size():08x}, enabled={self.get_is_enabled()}" + \
            f"])"


# Parsed MPU slot: MpuSlotInfo(slot_id=8, base_address=1276116992, size=38, flags=b'\x08\x13\x00\x00', enabled=True)
#
# def slice_section_data(self, data):
#     return data[self.file_offset:self.file_offset + self.size]

# Parsed MPU slot: MpuSlotInfo(slot_id=2, base_address=1077936128, size=40, flags=b'\x0b\x16\x00\x00', enabled=True)

class RadioParser:
    RADIO_MAGIC = b"TOC\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    @staticmethod
    def parse(data: bytes) -> dict:
        hexdump(data[:0x100])

        if data[:len(RadioParser.RADIO_MAGIC)] != RadioParser.RADIO_MAGIC:
            raise BadFileError("File is not a Shannon modem image")

        headers = RadioParser.parse_header(data[offset:])
        for header in headers.values():
            header.verify_data_checksum(data)
        logging.info("TOC header CRC checksums verified")

        if "BOOT" not in headers:
            raise BadFileError("File has no BOOT header section")
        if "MAIN" not in headers:
            raise BadFileError("File has no MAIN header section")

        boot_header = headers["BOOT"]
        main_header = headers["MAIN"]

        main_section = main_header.slice_section_data(data)
        logging.info(f"CRC {zlib.crc32(main_section):x}")

        RadioParser.detect_soc_version(main_section)
        RadioParser.detect_shannon_version(main_section)

        mpu_offset = RadioParser.find_mpu_table(main_section)

        if mpu_offset != None:
            mpu_table = RadioParser.parse_mpu_table(main_section[mpu_offset:])

            # Calculate actual permissions from here

        # Load sections from TOC

        # Type the MPU entries for reversing

    @staticmethod
    def parse_header(data: bytes) -> dict:
        count = TocHeaderInfo.from_bytes(data[:TocHeaderInfo.SIZE]).entry_id
        logging.info(f"Found TOC header with {count} sections")

        result = {}
        for i in range(count):
            header = TocHeaderInfo.from_bytes(
                data[i * TocHeaderInfo.SIZE: (i + 1) * TocHeaderInfo.SIZE])

            logging.debug(f"Parsed TOC header: {header}")

            result[header.name] = header

        return result

    def detect_soc_version(data: bytes) -> tuple[str, str] | None:
        # TODO check for multiple matches?
        match = RegexDB.SOC_VERSION.search(data)

        if not match:
            logging.warning("Unable to detect image SoC version")
            return None

        version = (match['SoC'].decode(), match["date"].decode())

        logging.info(
            f"Detected SoC version: SoC = {version[0]}, revision = {version[1]}")

        return version

    def detect_shannon_version(data: bytes) -> str | None:
        # TODO check for multiple matches?
        match = RegexDB.SHANNON_VERSION.search(data)

        if not match:
            logging.warning("Unable to detect image Shannon version")
            return None

        version = match[0].decode()

        logging.info(f"Detected Shannon OS version: SOC = {version}")

        return version

    def find_mpu_table(data: bytes) -> int | None:
        # TODO check for multiple matches?
        match = RegexDB.MPU_TABLE.search(data)

        if not match:
            logging.warning("Unable to find MPU table")
            return None

        offset = match.start()

        logging.info(f"Found MPU table: offset = 0x{offset:x}")

        return offset

    def parse_mpu_table(data: bytes) -> list[MpuSlotInfo]:
        slots = []

        for i in range(100):
            slot = MpuSlotInfo.from_bytes(
                data[i * MpuSlotInfo.SIZE: (i + 1) * MpuSlotInfo.SIZE])

            if slot.slot_id == 0xff:
                break

            logging.debug(f"Parsed MPU slot: {slot}")
            slots.append(slot)

        logging.info(f"Parsed {len(slots)} slots in MPU entry")

        return slots
        # TODO puts them in the addrentries?
