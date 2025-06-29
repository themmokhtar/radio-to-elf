from __future__ import annotations

import os
import logging
import tarfile

from io import BytesIO
from collections import namedtuple
from dataclasses import dataclass
from typing import Iterator

from unpacker import Unpacker

from exceptions import BadFileError, FileParsingError

BinaryChunkHandle = int


@dataclass
class BinaryChunkInfo:
    name: str
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class BinarySymbolInfo:
    name: str

    chunk_offset: int
    chunk: ChunkHandle


@dataclass
class BinaryAddressRangeInfo:
    address_range: BinaryAddressRange
    mapping: BinaryMappingInfo
    permissions: BinaryPermissionsInfo

    def __repr__(self):
        return f"({self.address_range}, {self.mapping}, {self.permissions})"


@dataclass
class BinaryAddressRange:
    address: int
    size: int

    @property
    def start(self) -> int:
        return self.address

    @property
    def end(self) -> int:
        return self.address + self.size

    @staticmethod
    def from_start_end(start: int, end: int) -> BinaryAddressRange:
        return BinaryAddressRange(start, end - start)

    # Calculates the intersection of two address ranges
    def __and__(self, other: BinaryAddressRange) -> BinaryAddressRange | None:
        new_start = max(self.start, other.start)
        new_end = min(self.end, other.end)
        print(f"new_end {new_end:x}")
        print(f"new_start {new_start:x}")
        if new_start >= new_end:
            return None
        print("NOTNONE")
        return BinaryAddressRange.from_start_end(new_start, new_end)

    # Calculates the union of two address ranges (may return 1 or 2 ranges)
    def __or__(self, other: BinaryAddressRange) -> List[BinaryAddressRange]:
        if self.end >= other.start and other.end >= self.start:
            return [BinaryAddressRange.from_start_end(min(self.start, other.start), max(self.end, other.end))]
        elif other.start > self.start:
            return [self, other]
        else:
            return [other, self]

    # Calculates the union of two address ranges (may return 1 or 2 ranges)
    def __add__(self, other: BinaryAddressRange) -> List[BinaryAddressRange]:
        return self | other

    # Removes one address range from the other (may return 0, 1 or 2 ranges)
    def __sub__(self, other: BinaryAddressRange) -> List[BinaryAddressRange]:
        intersection = self & other
        if not intersection:
            return [self]  # no overlap

        result = []
        if self.start < intersection.start:
            result.append(BinaryAddressRange.from_start_end(
                self.start, intersection.start))
        if intersection.end < self.end:
            result.append(BinaryAddressRange.from_start_end(
                intersection.end, self.end))

        return result

    def __repr__(self):
        return f"0x{self.start:x}:0x{self.end:x}"


@dataclass
class BinaryMappingInfo:
    chunk_offset: int
    chunk: ChunkHandle

    def __add__(self, other: int) -> BinaryMappingInfo:
        return BinaryMappingInfo(self.chunk_offset + other, self.chunk)

    def __sub__(self, other: int) -> BinaryMappingInfo:
        return BinaryMappingInfo(self.chunk_offset - other, self.chunk)

    def __repr__(self):
        return f"#{self.chunk} @ 0x{self.chunk_offset:x}"


@dataclass
class BinaryPermissionsInfo:
    readable: bool
    writable: bool
    executable: bool

    def __repr__(self):
        return f"{'r' if self.readable else '-'}{'w' if self.writable else '-'}{'x' if self.executable else '-'}"


class Binary:

    @property
    def chunks(self) -> Iterator[Tuple[int, BinaryChunkInfo]]:
        for chunk in enumerate(self._chunks):
            yield chunk

    @property
    def symbols(self) -> Iterator[BinarySymbolInfo]:
        for symbol in self._symbols:
            yield symbol

    @property
    def address_space(self) -> Iterator[BinaryAddressRangeInfo]:
        for address_range_info in self._address_space:
            yield address_range_info

    def __init__(self):
        self._chunks = []
        self._symbols = []
        self._address_space = []

    def add_chunk(self, chunk: BinaryChunkInfo) -> ChunkHandle:
        if chunk.size <= 0:
            raise InvalidBinaryInfoError(
                "Cannot have an empty chunk in the binary")
        if not chunk.name:
            raise InvalidBinaryInfoError(
                "Cannot have a chunk with an empty name in the binary")

        self._chunks.append(chunk)

        return len(self._chunks) - 1

    def add_symbol(self, symbol: BinarySymbolInfo) -> None:
        if not symbol.name:
            raise InvalidBinaryInfoError(
                "Cannot have a symbol with an empty name in the binary")
        if symbol.chunk >= len(self._chunks) or symbol.chunk < 0:
            raise InvalidBinaryInfoError(
                "Symbol has an invalid chunk handle")
        if symbol.chunk_offset > self._chunks[symbol.chunk].size or symbol.chunk_offset < 0:
            raise InvalidBinaryInfoError(
                "Symbol chunk offset is out of bounds of chunk")

        self._symbols.append(symbol)

    def impose_mapping(self, address_range: BinaryAddressRange, mapping: BinaryMappingInfo) -> None:
        self._impose_address_range(
            BinaryAddressRangeInfo(address_range, mapping, None))

    def impose_permissions(self, address_range: BinaryAddressRange, permissions: BinaryPermissionsInfo) -> None:
        self._impose_address_range(
            BinaryAddressRangeInfo(address_range, None, permissions))

    def _impose_address_range(self, info: BinaryAddressRangeInfo) -> None:
        mapping_range = info.address_range

        if mapping_range.size <= 0:
            raise InvalidBinaryInfoError(
                "Cannot impose address range of zero or negative size")
        if mapping_range.address < 0:
            raise InvalidBinaryInfoError(
                "Cannot impose address range of negative address")

        i = 0

        print(info)
        print(self._address_space)
        prev_range = BinaryAddressRange(0, 0)
        while i <= len(self._address_space) and mapping_range.end > prev_range.end:
            is_last_range = i == len(self._address_space)

            if is_last_range:
                next_range = BinaryAddressRange.from_start_end(
                    max(prev_range.end, mapping_range.start), mapping_range.end)
                next_range_info = BinaryAddressRangeInfo(
                    next_range, None, None)
            else:
                next_range_info = self._address_space.pop(i)
                next_range = next_range_info.address_range

            # During this iteration, we need to fix all the area from prev_range.end to next_range.end
            imposed_range = mapping_range & BinaryAddressRange.from_start_end(
                prev_range.end, next_range.end)
            print("mapping_range", mapping_range)
            print("anded_range", BinaryAddressRange.from_start_end(
                prev_range.end, next_range.end))
            print("prev_range", prev_range)
            print("next_range", next_range)
            print("imposed_range", imposed_range)

            prev_range = next_range

            # If the imposed mapping does not interact with this area, skip it
            if not imposed_range:
                self._address_space.insert(i, next_range_info)
                i += 1
                continue

            # Calculate all possible three ranges
            low_range = imposed_range - next_range
            mid_range = imposed_range & next_range
            high_range1 = next_range - imposed_range
            high_range2 = None

            # The low and high ranges should never end up being two split ranges
            if len(low_range) > 1:
                raise RuntimeError("Address range logic mismatch")

            low_range = low_range[0] if len(low_range) == 1 else None

            # print(f"PREV {prev_range}")
            # print(f"NEXT {next_range_info}")
            # print(f"LOW {low_range}")
            # print(f"MID {mid_range}")
            # print(f"HIGH {high_range1}")

            if len(high_range1) == 0:
                high_range1 = None
            elif len(high_range1) == 1:
                high_range1 = high_range1[0] if not is_last_range else None
            elif len(high_range1) == 2 and not low_range and not is_last_range:
                high_range2 = high_range1[1]
                high_range1 = high_range1[0]
            else:
                raise RuntimeError("Address range logic mismatch")

            # Create the range info accordingly
            if low_range:
                low_range = BinaryAddressRangeInfo(
                    low_range, info.mapping, info.permissions)

            if mid_range:
                mid_range = BinaryAddressRangeInfo(
                    mid_range,
                    info.mapping + (mid_range.start - mapping_range.start)
                    if info.mapping else next_range_info.mapping,
                    info.permissions if info.permissions else next_range_info.permissions)

            if high_range1:
                high_range1 = BinaryAddressRangeInfo(
                    high_range1, next_range_info.mapping + (high_range1.start - next_range.start), next_range_info.permissions)

            if high_range2:
                high_range2 = BinaryAddressRangeInfo(
                    high_range2, next_range_info.mapping + (high_range2.start - next_range.start), next_range_info.permissions)

            # print(f"PREV {prev_range}")
            # print(f"NEXT {next_range_info}")
            # print(f"LOW {low_range}")
            # print(f"MID {mid_range}")
            # print(f"HIGH {high_range}")

            # Only use the ranges that actually exist from our boolean range calculation operations
            new_ranges = [low_range, mid_range, high_range1, high_range2]
            new_ranges = [x for x in new_ranges if x]

            # Insert them reversed at the same index to maintain order
            for new_range in reversed(new_ranges):
                self._address_space.insert(i, new_range)

            # Jump beyond the ranges we have handled to the next range
            i += len(new_ranges)

        # Now we will merge any similar adjacent ranges
        while i < len(self._address_space) - 1:
            prev_range_info = self._address_space.pop(i)
            next_range_info = self._address_space.pop(i)

            prev_range = prev_range_info.address_range
            next_range = next_range_info.address_range

            union = prev_range | next_range

            if len(union) == 1 and prev_range_info.mapping == next_range_info.mapping and prev_range_info.permissions == next_range_info.permissions:
                self._address_space.insert(i, BinaryAddressRangeInfo(
                    union[0], prev_range_info.mapping, prev_range_info.permissions))
            else:
                self._address_space.insert(i, next_range_info)
                self._address_space.insert(i, prev_range_info)
                i += 1

        # for
        # print(self._address_space)
    # def
    # # for other in self._sections:
    # #     if self._check_range_overlap(section.address_range, other.address_range):
    # #         raise SectionOverlapError(
    # #             f"Cannot have overlapping sections \"{section.name}\" and \"{other.name}\" at {section.address_range} and {other.address_range}")

    # # self._sections.append(section)

    # def add__sections(self, _sections: Iterator[BinarySection]) -> None:
    #     for section in _sections:
    #         self.add_section(section)

    # def add_symbol(self, symbol: BinarySymbol) -> None:
    #     for other in self._sections:
    #         if self._check_range_overlap(symbol.address_range, section.address_range):
    #             self._symbols.append(symbol)

    #     raise DanglingSymbolError(
    #         f"Cannot have a symbol \"{symbol.name}\" at {symbol.address} that belongs to no section")

    # def add_symbols(self, _symbols: Iterator[BinarySymbol]) -> None:
    #     for symbol in _symbols:
    #         self.add_symbol(symbol)
