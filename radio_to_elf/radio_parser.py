from __future__ import annotations

import os
import io
import re
import struct
import logging
import string
import zlib

from itertools import islice
from dataclasses import dataclass
from typing import ClassVar

from binary import Binary, BinaryChunkInfo, BinarySymbolInfo, BinaryAddressRange, BinaryMappingRange, BinaryMappingInfo, BinaryPermissionsInfo, ZeroChunkHandle
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

    SCATTERLOAD = re.compile(
        # Here the first instruction is `adr r0, #0x28`
        b"(?P<THUMB>\\x0A\\xA0\\x90\\xE8\\x00\\x0C\\x82\\x44)"
        b"|"
        # Here the first instruction is `add r0, pc, #0x2c`
        b"(?P<ARM>\\x2C\\x00\\x8F\\xE2\\x00\\x0C\\x90\\xE8\\x00\\xA0\\x8A\\xE0\\x00\\xB0\\x8B\\xE0)"
    )

    SCATTERLOAD_COPY = re.compile(
        b"(?P<THUMB>"
        b"\\x10\\x3a"  # sub       sz,#0x10
        b"\\x24\\xbf"  # itt       cs
        b"\\x78\\xc8"  # ldmia.cs  src!,{ r3, r4, r5, r6 }
        b"\\x78\\xc1"  # stmia.cs  dst!,{ r3, r4, r5, r6 }
        b"\\xfa\\xd8"  # bhi       BOOT_MEMCPY
        b"\\x52\\x07"  # lsl       sz,sz,#0x1d
        b")"
        b"|"
        b"(?P<ARM>"
        b"\\x10\\x20\\x52\\xe2"  # subs      r2,r2,#0x10
        b"\\x78\\x00\\xb0\\x28"  # ldmiacs   r0!,{r3 r4 r5 r6}=>DAT_01245cc4
        b")"
    )

    SCATTERLOAD_ZEROINIT = re.compile(
        b"(?P<THUMB>"
        b"\\x00\\x23"  # mov       r3,#0x0
        b"\\x00\\x24"  # mov       r4,#0x0
        b"\\x00\\x25"  # mov       r5,#0x0
        b"\\x00\\x26"  # mov       r6,#0x0
        b"\\x10\\x3a"  # sub       sz,#0x10
        b"\\x28\\xbf"  # it        cs
        b"\\x78\\xc1"  # stmia.cs  dst!,{ r3, r4, r5, r6 }
        b"\\xfb\\xd8"  # bhi       LAB_415da584
        b")"
        b"|"
        b"(?P<ARM>"
        b"\\x00\\x30\\xb0\\xe3"  # movs      r3,#0x0
        b"\\x00\\x40\\xb0\\xe3"  # movs      r4,#0x0
        b"\\x00\\x50\\xb0\\xe3"  # movs      r5,#0x0
        b"\\x00\\x60\\xb0\\xe3"  # movs      r6,#0x0
        b")"
    )

    # How the ARM RVCT linker (armlink) chooses which scatter compressor to use
    # https://developer.arm.com/documentation/dui0474/f/using-linker-optimizations/overriding-the-compression-algorithm-used-by-the-linker?lang=en
    # These are using LZ77 compression or mixing it with Run Length Encoding (RLE)
    SCATTERLOAD_DECOMPRESS = re.compile(
        b"(?P<UNKNOWN1>"
        b"\\x0a\\x44\\x10\\xf8\\x01\\x4b\\x14\\xf0\\x0f\\x05\\x08\\xbf\\x10\\xf8\\x01\\x5b"
        b")"
        b"|"
        b"(?P<UNKNOWN2>"
        b"\\x0a\\x44"            # add       endptr,dst
        b"\\x4f\\xf0\\x00\\x0c"  # mov.w     r12,#0x0
        b"\\x10\\xf8\\x01\\x3b"  # ldrb.w    r3,src],#0x1
        b"\\x13\\xf0\\x07\\x04"  # ands      match_len,r3,#0x7
        b"\\x08\\xbf"            # it        eq
        b")"
        b"|"
        b"(?P<UNKNOWN3>"
        b"..\\x8f\\xe2"          # adr r12, REF (starts in ARM)
        b"\\x1c\\xff\\x2f\\xe1"  # bx r12 (switch to thumb)
        b"\\x8a\\x18"            # add  r2,r1,r2 (REF)"
        b"\\x03\\x78"            # ldrb r3,[r0,#0x0]
        b"\\x01\\x30"            # add  r0,#0x1
        b"\\x5c\\x07"            # lsl  r4,r3,#0x1d
        b"\\x64\\x0f"            # lsr  r4,r4,#0x1d
        b")"
        b"|"
        b"(?P<ARM>"
        b"\\x02\\x20\\x81\\xe0"  # add       r2,r1,r2
        b"\\x00\\xc0\\xa0\\xe3"  # mov       r12,#0x0
        b"\\x01\\x30\\xd0\\xe4"  # ldrb      r3,[r0],#0x1
        b")"
    )

    SCATTERLOAD_DECOMPRESS2 = re.compile(
        b"\\x10\\xf8\\x01\\x3b\\x0a\\x44\\x13\\xf0\\x03\\x04\\x08\\xbf\\x10\\xf8\\x01\\x4b"
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
            logging.warning(
                f"Failed to parse TOC header with invalid {self.name} section data CRC checksum (expected 0x{self.crc:08x}, got 0x{section_crc:08x})")

        logging.debug(
            f"CRC checksum for {self.name} section verified (0x{section_crc:08x})")

    def __repr__(self):
        return f"{self.__class__.__name__}(name='{self.name}', file_offset=0x{self.file_offset:08x}, load_address=0x{self.load_address:08x}, size=0x{self.size:08x}, crc=0x{self.crc:08x}, entry_id={self.entry_id})"


@dataclass
class MpuSlotInfo:
    SIZE: ClassVar[int] = 40

    slot_id: int
    base_address: int
    mpu_rasr: int

    @property
    def enabled(self) -> bool:
        return ((self.mpu_rasr) & 0b1) == 1

    @property
    def size(self) -> int:
        actual_size = (self.mpu_rasr >> 1) & 0b11111

        if actual_size < 0b00111:  # These are reserved according to the ARM Cortex documentation of the MPU_RASR size bit assignments
            raise FileParsingError(
                "Failed to parse MPU slot due to invalid MPU_RASR size bits")

        return 2 ** (actual_size - 1)

    @property
    def ap_bits(self) -> int:
        ap_bits = (self.mpu_rasr >> 24) & 0b111

        if ap_bits == 0b100:  # This value is reserved according to the ARM Cortex documentation of the MPU_RASR AP bit assignments
            raise FileParsingError(
                "Failed to parse MPU slot due to invalid MPU_RASR AP bits")

        return ap_bits

    @property
    def priv_readable(self) -> bool:
        return self.ap_bits in [0b001, 0b010, 0b011, 0b101, 0b110, 0b111]

    @property
    def priv_writable(self) -> bool:
        return self.ap_bits in [0b001, 0b010, 0b011]

    @property
    def unpriv_readable(self) -> bool:
        return self.ap_bits in [0b010, 0b011, 0b110, 0b111]

    @property
    def unpriv_writable(self) -> bool:
        return self.ap_bits in [0b011]

    @property
    def executable(self) -> bool:
        return ((self.mpu_rasr >> 28) & 0b1) == 0

    @staticmethod
    def from_bytes(data: bytes) -> MpuSlotInfo:
        slot = struct.unpack("<3I4s4s4s4s4s4s1I", data)
        mpu_rasr = bytes([(a | b | c | d | e | f)
                          for (a, b, c, d, e, f) in zip(*slot[3:9])])
        mpu_rasr = (struct.unpack("<I", mpu_rasr)[0] << 16) | slot[2] | slot[9]

        return MpuSlotInfo(data[0], slot[1], mpu_rasr)

    def __repr__(self):
        return f"{self.__class__.__name__}(slot_id={self.slot_id}, base_address=0x{self.base_address:08x}, mpu_rasr=0x{self.mpu_rasr:08x} [" + \
            f"priv_perms={'r' if self.priv_readable else '-'}{'w' if self.priv_writable else '-'}{'x' if self.executable else '-'}, " + \
            f"unpriv_perms={'r' if self.unpriv_readable else '-'}{'w' if self.unpriv_writable else '-'}{'x' if self.executable else '-'}, " + \
            f"size=0x{self.size:08x}, enabled={self.enabled}" + \
            f"])"


@dataclass
class ScatterloadEntryInfo:
    SIZE: ClassVar[int] = 16

    src: int
    dst: int
    size: int
    handler: int

    @staticmethod
    def from_bytes(data: bytes) -> TocHeaderInfo:
        header = struct.unpack("<4I", data)
        return ScatterloadEntryInfo(*header)

    def __repr__(self):
        return f"{self.__class__.__name__}(src={self.src:#08x}, dst={self.dst:#08x}, size={self.size:#08x}, handler={self.handler:#08x})"


# Parsed MPU slot: MpuSlotInfo(slot_id=8, base_address=1276116992, size=38, flags=b'\x08\x13\x00\x00', enabled=True)
#
# def slice_section_data(self, data):
#     return data[self.file_offset:self.file_offset + self.size]

# Parsed MPU slot: MpuSlotInfo(slot_id=2, base_address=1077936128, size=40, flags=b'\x0b\x16\x00\x00', enabled=True)

class RadioParser:
    RADIO_MAGIC = b"TOC\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    @staticmethod
    def parse(data: bytes) -> Binary:
        binary = Binary()

        if data[:len(RadioParser.RADIO_MAGIC)] != RadioParser.RADIO_MAGIC:
            raise BadFileError("File is not a Shannon modem image")

        # Parse header
        headers = RadioParser.parse_header(data)
        for header in headers.values():
            header.verify_data_checksum(data)
        logging.info("TOC header CRC checksums verified")

        if "BOOT" not in headers:
            raise BadFileError("File has no BOOT header section")
        if "MAIN" not in headers:
            raise BadFileError("File has no MAIN header section")

        chunk_handle = binary.add_chunk(BinaryChunkInfo("modem", data))
        for header in headers.values():
            binary.impose_mapping(BinaryAddressRange(
                header.load_address, header.size), BinaryMappingInfo(header.file_offset, chunk_handle))
            binary.add_symbol(
                BinarySymbolInfo(f"section_{header.name}", header.size, BinaryMappingInfo(header.file_offset, chunk_handle)))

        boot_header = headers["BOOT"]
        main_header = headers["MAIN"]

        main_section = main_header.slice_section_data(data)

        # Parse version strings
        soc_version = RadioParser.detect_soc_version(main_section)
        if soc_version:
            version_span = soc_version.span()
            binary.add_symbol(
                BinarySymbolInfo(f"soc_version", version_span[1] - version_span[0], BinaryMappingInfo(version_span[0] + main_header.file_offset, chunk_handle)))

        shannon_version = RadioParser.detect_shannon_version(main_section)
        if shannon_version:
            version_span = shannon_version.span()
            binary.add_symbol(
                BinarySymbolInfo(f"shannon_version", version_span[1] - version_span[0], BinaryMappingInfo(version_span[0] + main_header.file_offset, chunk_handle)))

        # Parse MPU Table
        mpu_offset = RadioParser.find_mpu_table(main_section)

        if mpu_offset:
            mpu_table = RadioParser.parse_mpu_table(main_section[mpu_offset:])

            binary.add_symbol(
                BinarySymbolInfo(f"mpu_table", (len(mpu_table) + 1) * MpuSlotInfo.SIZE, BinaryMappingInfo(mpu_offset + main_header.file_offset, chunk_handle)))

            for slot in mpu_table:
                if not slot.enabled:
                    continue

                binary.impose_permissions(BinaryAddressRange(slot.base_address, slot.size),
                                          BinaryPermissionsInfo(slot.priv_readable, slot.priv_writable, slot.executable))

        # Parse scatterload tables
        scatterload, scatterload_type = RadioParser.find_scatterload(
            main_section)
        if scatterload:
            # Scatterload itself
            scatterload_span = scatterload.span()

            binary.add_symbol(BinarySymbolInfo(f"__scatterload_{scatterload_type}", scatterload_span[1] - scatterload_span[0],
                                               BinaryMappingInfo(scatterload_span[0] + main_header.file_offset, chunk_handle)))

            # Scatterload table
            scatterload_table_start_offset, scatterload_table_end_offset, entries = RadioParser.parse_scatterload(
                main_section, scatterload_span[0], scatterload_type == "THUMB")
            binary.add_symbol(BinarySymbolInfo(f"scatterload_table", scatterload_table_end_offset - scatterload_table_start_offset,
                              BinaryMappingInfo(scatterload_table_start_offset + main_header.file_offset, chunk_handle)))

            # Scatterload handlers
            handlers = RadioParser.find_scatterload_handlers(main_section)

            handlers_addresses = {}
            for function, match in handlers.items():
                if not match:
                    continue

                function_span = match.span()
                binary.add_symbol(BinarySymbolInfo(function, function_span[1] - function_span[0],
                                                   BinaryMappingInfo(function_span[0] + main_header.file_offset, chunk_handle)))

                ranges = binary.translate_mapping_range(
                    BinaryMappingRange(BinaryMappingInfo(main_header.file_offset + function_span[0], chunk_handle), 1))

                for range_info in ranges:
                    address = range_info.address_range.start
                    logging.info(
                        f"Found {function} function at address {address:#x}")

                    handlers_addresses[address] = function

            # Perform for the scatterload operations now
            for index, entry in enumerate(entries):
                if entry.size == 0:
                    logging.warning(
                        f"Skipping scatterload entry {index} with zero size")
                    continue

                if entry.src == entry.dst:
                    logging.warning(
                        f"Skipping scatterload entry {index} with matching source and destination addresses {entry.src:#x}")
                    continue

                if entry.handler not in handlers_addresses:
                    logging.warning(
                        f"Skipping scatterload entry {index} with unknown handler function at address {entry.handler:#x}")
                    continue

                handler_name = handlers_addresses[entry.handler]

                # if handler_name != "__scatterload_zeroinit":
                #     # 2A77360
                #     # translated = binary.translate_address_range(BinaryAddressRange(entry.src + 0x100000, entry.size))
                #     # print(translated)

                destination_ranges = binary.translate_address_range(
                    BinaryAddressRange(entry.src, 4))
                if len(destination_ranges) > 0 and binary[destination_ranges[0]] == b"DBT:" or False:
                    logging.warning(
                        f"Skipping scatterload entry {index:02} to avoid overwriting debug tables")
                    continue

                logging.info(
                    f"Loading scatterload entry {index:02}: {handler_name}(dst={entry.dst:#x}, src={entry.src:#x}, size={entry.size:#x})")

                src_range = BinaryAddressRange(entry.src,
                                               entry.size)
                dst_range = BinaryAddressRange(entry.dst,
                                               entry.size)

                if handler_name == "__scatterload_zeroinit":
                    binary.impose_mapping(dst_range,
                                          BinaryMappingInfo(0, ZeroChunkHandle))
                    continue

                translated_ranges = binary.translate_address_range(
                    src_range)

                if len(translated_ranges) == 0:
                    raise NotImplementedError(
                        f"Implementing {handler_name} for empty ranges is not supported (yet, hopefully)")
                translated_range = translated_ranges[0] 
                # print(translated_range)

                if translated_range.address_range.start != entry.src:
                    raise NotImplementedError(
                        f"Implementing {handler_name} for incomplete ranges is not supported (yet, hopefully)")

                if handler_name == "__scatterload_copy":
                    if len(translated_ranges) > 1:
                        raise NotImplementedError(
                            f"Implementing {handler_name} for fragmented ranges is not supported (yet, hopefully)")

                    if translated_range.address_range.size != entry.size:
                        raise NotImplementedError(
                            f"Implementing {handler_name} for smaller ranges is not supported (yet, hopefully)")

                    binary.impose_mapping(dst_range,
                                          translated_range.mapping)
                    continue

                if len(translated_ranges) > 1:
                    # Since we don't know the size of the input beforehand, we're just gonna assume the first range will be enough
                    logging.warning(
                        f"Using only the first range out of {len(translated_ranges)} for {handler_name}")

                if handler_name == "__scatterload_decompress":
                    data_chunk = binary[translated_range.mapping.chunk]
                    data = data_chunk.data[translated_range.mapping.chunk_offset:]

                    decompressed = RadioParser.scatterload_decompress1(data,
                                                                       entry.size)

                    decompressed_chunk = binary.add_chunk(BinaryChunkInfo(
                        f"scatterload_entry_{index}_decompressed", decompressed))

                    binary.impose_mapping(dst_range,
                                          BinaryMappingInfo(0, ZeroChunkHandle))
                    continue

                # __scatterload_decompress2 is not implemented because I'm lazy and I'll only implement it if I need it
                # Plus, I'm not gonna implement something I don't know how to test because then it will be broken for sure
                # In case you need it for some reason, check out the original implementation of the Ghidra extension by Grant and his team
                raise NotImplementedError(
                    f"implementation for the {handler_name} handler is not supported (yet, hopefully)")

        return binary

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

    @staticmethod
    def detect_soc_version(data: bytes) -> tuple[str, str] | None:
        # TODO check for multiple matches?
        match = RegexDB.SOC_VERSION.search(data)

        if not match:
            logging.warning("Unable to detect image SoC version")
            return None

        version = (match['SoC'].decode(), match["date"].decode())

        logging.info(
            f"Detected SoC version: SoC = {version[0]}, revision = {version[1]}")

        return match

    @staticmethod
    def detect_shannon_version(data: bytes) -> str | None:
        # TODO check for multiple matches?
        match = RegexDB.SHANNON_VERSION.search(data)

        if not match:
            logging.warning("Unable to detect image Shannon version")
            return None

        version = match[0].decode()

        logging.info(f"Detected Shannon OS version: SOC = {version}")

        return match

    @staticmethod
    def find_mpu_table(data: bytes) -> int | None:
        # TODO check for multiple matches?
        match = RegexDB.MPU_TABLE.search(data)

        if not match:
            logging.warning("Unable to find MPU table")
            return None

        offset = match.start()

        logging.info(f"Found MPU table: offset = 0x{offset:x}")

        return offset

    @staticmethod
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

    @staticmethod
    def find_scatterload(data: bytes):
        match = RegexDB.SCATTERLOAD.search(data)

        if not match:
            logging.warning("Unable to find scatterload code")
            return None, None

        match_type = "THUMB" if match["THUMB"] else "ARM"

        logging.info(
            f"Found {match_type} version of scatterload function at offset 0x{match.start():x} in section")

        return match, match_type

    def find_scatterload_handlers(data: bytes):
        functions = {
            "__scatterload_copy": RegexDB.SCATTERLOAD_COPY,
            "__scatterload_zeroinit": RegexDB.SCATTERLOAD_ZEROINIT,
            "__scatterload_decompress": RegexDB.SCATTERLOAD_DECOMPRESS,
            "__scatterload_decompress2": RegexDB.SCATTERLOAD_DECOMPRESS2,
        }

        for function, regex in functions.items():
            match = regex.search(data)

            if match:
                logging.info(
                    f"Found {function} function at offset 0x{match.start():x} in section")

                # match = match.start()

            functions[function] = match

        return functions

    @staticmethod
    def parse_scatterload(data: bytes, scatterload_function_offset: int, is_thumb: bool):
        # PC is at the start of the scatterload function + two instructions
        pc_offset = scatterload_function_offset + (4 if is_thumb else 8)

        # Table is at an offset from PC ()`adr r0, #0x28` for THUMB and `add r0, pc, #0x2c` for ARM)
        table_reference_offset = pc_offset + (0x28 if is_thumb else 0x2c)
        logging.info(
            f"Found scatterload table reference at offset 0x{table_reference_offset:x}")
        # hexdump(main_section[table_reference_offset:][:0x100])

        # Offsets can be positive or negative
        start_offset, end_offset = struct.unpack(
            "<2i", data[table_reference_offset:table_reference_offset+8])
        logging.info(
            f"Scatterload offsets = ({start_offset:#x}, {end_offset:#x})")

        scatterload_table_start_offset = table_reference_offset + start_offset
        scatterload_table_end_offset = table_reference_offset + end_offset
        logging.info(
            f"Found scatterload table at range ({scatterload_table_start_offset:#x}, {scatterload_table_end_offset:#x})")

        scatterload_table = data[scatterload_table_start_offset:scatterload_table_end_offset]
        # hexdump(scatterload_table)

        entries = []
        for i in range(len(scatterload_table) // ScatterloadEntryInfo.SIZE):
            entry_bytes = scatterload_table[i * ScatterloadEntryInfo.SIZE:
                                            (i + 1) * ScatterloadEntryInfo.SIZE]

            entry = ScatterloadEntryInfo.from_bytes(entry_bytes)

            logging.debug(f"Parsed scatterload entry: {entry}")
            entries.append(entry)

        logging.info(f"Parsed {len(entries)} entries in scatterload table")

        return scatterload_table_start_offset, scatterload_table_end_offset, entries

    # @staticmethod
    # def scatterload_decompress1(data: bytes, decompressed_size: int):
    #     result = io.BytesIO()

    #     idata = iter(data)

    #     start = time.time()
    #     while len(result.getvalue()) < decompressed_size:
    #         percent = (len(result.getvalue()) / decompressed_size)  * 100
    #         print(f"t {percent}%")
    #         # if percent >= 5:
    #         #     exit(0)
    #         #     print(time.time()-start)
    #         #     break

    #         token = next(idata)

    #         match_len = token & 7
    #         if match_len == 0:
    #             match_len = next(idata)

    #         lit_len = (token >> 4) & 0xf
    #         if lit_len == 0:
    #             lit_len = next(idata)

    #         for _ in range(match_len - 1):
    #             if len(result.getvalue()) >= decompressed_size:
    #                 raise FileParsingError("Decompression overflow")
    #             result.write(bytes(next(idata)))

    #         # RLE for zeros
    #         if token & 8 == 0:
    #             for _ in range(lit_len):
    #                 if len(result.getvalue()) >= decompressed_size:
    #                     raise FileParsingError("Decompression overflow")
    #                 result.write(b"\x00")
    #         else:
    #             backref = next(idata)
    #             backref_offset = len(result.getvalue()) - backref

    #             for _ in range(lit_len + 2):
    #                 if len(result.getvalue()) >= decompressed_size:
    #                     raise FileParsingError("Decompression overflow")

    #                 # print(result)
    #                 if backref_offset < 0 or backref_offset >= len(result.getvalue()) or backref_offset >= decompressed_size:
    #                     print(f"backref_offset = {backref_offset}, len(result.getvalue()) = {len(result).getvalue()}")
    #                     raise FileParsingError("Decompression backreference out-of-range")

    #                 backref_offset = len(result) - backref
    #                 result.write(result.getbuffer()[backref_offset:backref_offset+1])

    #     return result

    @staticmethod
    def scatterload_decompress1(data: bytes, decompressed_size: int):
        result = io.BytesIO()
        idata = iter(data)

        while len(result.getvalue()) < decompressed_size:
            percent = (len(result.getvalue()) / decompressed_size) * 100
            print(f"\rDecompressed {percent:.02f}%", end='')

            token = next(idata)

            match_len = token & 7
            if match_len == 0:
                match_len = next(idata)

            lit_len = (token >> 4) & 0xf
            if lit_len == 0:
                lit_len = next(idata)

            result.write(bytes(islice(idata, match_len - 1)))
            if len(result.getvalue()) > decompressed_size:
                raise FileParsingError("Decompression overflow")

            # RLE for zeros
            if token & 8 == 0:
                result.write(b"\x00" * lit_len)
                if len(result.getvalue()) > decompressed_size:
                    raise FileParsingError("Decompression overflow")
            else:
                backref = next(idata)
                backref_size = lit_len + 2

                for _ in range(backref_size):
                    if len(result.getvalue()) >= decompressed_size:
                        # print(len(result.getvalue()), decompressed_size)
                        # print()
                        raise FileParsingError("Decompression overflow")

                    # backref_offset = len(result.getvalue()) - backref
                    # if backref_offset < 0 or backref_offset >= len(result.getvalue()) or backref_offset >= decompressed_size:
                    #     print(f"backref_offset = {backref_offset}, len(result) = {len(result)}")
                    #     raise FileParsingError("Decompression backreference out-of-range")

                    result.seek(-backref, os.SEEK_END)
                    one_byte = result.read(1)
                    if len(one_byte) == 0:
                        raise FileParsingError(
                            "Decompression backreference out-of-range")

                    result.seek(0, os.SEEK_END)
                    result.write(one_byte)

                # print(f"backref_offset = {backref_offset}, {backref_end_offset}, {len(result.getvalue())}")
                # if backref_offset < 0 \
                #         or backref_offset >= len(result.getvalue()) or backref_offset >= decompressed_size \
                #         or backref_end_offset >= len(result.getvalue()) or backref_end_offset >= decompressed_size:
                #     raise FileParsingError(
                #         "Decompression backreference out-of-range")

                # result.seek(backref_offset, os.SEEK_SET)
                # result.seek(backref, os.SEEK_CUR)
                # data = result.read(backref_size)

                # result.seek(0, os.SEEK_END)
                # result.write(data)

                if len(result.getvalue()) > decompressed_size:
                    raise FileParsingError("Decompression overflow")

        print('\r', end='')
        return result.getvalue()

    # @staticmethod
    # def scatterload_decompress1(data: bytes, decompressed_size: int):
    #     result = b""

    #     idata = iter(data)

    #     while len(result) < decompressed_size:
    #         token = next(idata)

    #         match_len = token & 7
    #         if match_len == 0:
    #             match_len = next(idata)

    #         lit_len = (token >> 4) & 0xf
    #         if lit_len == 0:
    #             lit_len = next(idata)

    #         for _ in range(match_len - 1):
    #             if len(result) >= decompressed_size:
    #                 raise FileParsingError("Decompression overflow")
    #             result += bytes(next(idata))

    #         # RLE for zeros
    #         if token & 8 == 0:
    #             for _ in range(lit_len):
    #                 if len(result) >= decompressed_size:
    #                     raise FileParsingError("Decompression overflow")
    #                 result += b"\x00"
    #         else:
    #             backref = next(idata)
    #             backref_offset = len(result) - backref

    #             for _ in range(lit_len + 2):
    #                 if len(result) >= decompressed_size:
    #                     raise FileParsingError("Decompression overflow")

    #                 # print(result)
    #                 if backref_offset < 0 or backref_offset >= len(result) or backref_offset >= decompressed_size:
    #                     print(f"backref_offset = {backref_offset}, len(result) = {len(result)}")
    #                     raise FileParsingError("Decompression backreference out-of-range")

    #                 backref_offset = len(result) - backref
    #                 result += result[backref_offset:backref_offset+1]

    #         print(f"{(len(result) / decompressed_size) * 100}%")

    #     return result
        # match = RegexDB.SCATTERLOAD.search(data)

        # if not match:
        #     logging.warning("Unable to find scatterload code")
        #     return None

        # match_type = "THUMB" if match["THUMB"] else "ARM"

        # logging.info(
        #     f"Found {match_type} version of scatterload function at offset 0x{match.start():x} in section")

        # return match, match_type
