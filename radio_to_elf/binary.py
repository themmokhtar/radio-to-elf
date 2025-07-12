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
ZeroChunkHandle = 0


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
    size: int

    mapping: BinaryMappingInfo


@dataclass
class BinaryAddressSymbolInfo:
    name: str
    offset: int

    address_range: BinaryAddressRange
    mapping: BinaryMappingInfo


@dataclass
class BinaryAddressRangeInfo:
    address_range: BinaryAddressRange
    mapping: BinaryMappingInfo
    permissions: BinaryPermissionsInfo

    def __rshift__(self, other: int) -> BinaryMappingInfo:
        return BinaryAddressRangeInfo(self.address_range >> other, self.mapping >> other, self.permissions)

    def __lshift__(self, other: int) -> BinaryMappingInfo:
        return self >> (-other)

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

    # Checks if an address lies in the address range
    def __contains__(self, address: int) -> bool:
        return address >= self.start and address < self.end

    # Calculates the intersection of two address ranges
    def __and__(self, other: BinaryAddressRange) -> BinaryAddressRange | None:
        new_start = max(self.start, other.start)
        new_end = min(self.end, other.end)
        # print(f"new_end {new_end:x}")
        # print(f"new_start {new_start:x}")
        if new_start >= new_end:
            return None

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

    def __rshift__(self, other: int) -> BinaryMappingInfo:
        # print(f"address {self.address}, other {other}")
        # if self.address + other < 0:
        #     raise RuntimeError("Cannot shift address below zero")
        return BinaryAddressRange(self.address + other, self.size)

    def __lshift__(self, other: int) -> BinaryMappingInfo:
        return self >> (-other)

    def __repr__(self):
        return f"0x{self.start:x}:0x{self.end:x} ({self.size:#x})"


@dataclass
class BinaryMappingRange:
    mapping: BinaryMappingInfo
    size: int

    @property
    def start(self) -> int:
        return self.mapping.chunk_offset

    @property
    def end(self) -> int:
        return self.mapping.chunk_offset + self.size

    def __rshift__(self, other: int) -> BinaryMappingInfo:
        # TODO check if this is going OOB of the chunk somehow
        # print(f"chunk_offset {self.chunk_offset}, other {other}")
        # if self.chunk_offset + other < 0:
        #     raise RuntimeError("Cannot shift chunk_offset below zero")
        return BinaryMappingInfo(self.chunk_offset + other, self.chunk)

    def __lshift__(self, other: int) -> BinaryMappingInfo:
        return self >> (-other)

    def __repr__(self):
        return f"{self.mapping}:{self.mapping.chunk_offset + self.size:x} ({self.size:#x})"


@dataclass
class BinaryMappingInfo:
    chunk_offset: int
    chunk: ChunkHandle

    def __rshift__(self, other: int) -> BinaryMappingInfo:
        # TODO check if this is going OOB of the chunk somehow
        # print(f"chunk_offset {self.chunk_offset}, other {other}")
        # if self.chunk_offset + other < 0:
        #     raise RuntimeError("Cannot shift chunk_offset below zero")
        return BinaryMappingInfo(self.chunk_offset + other, self.chunk)

    def __lshift__(self, other: int) -> BinaryMappingInfo:
        return self >> (-other)

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

    class ZeroBytes:
        def __init__(self, size):
            self._size = size
            self._view = None

        def __len__(self):
            return self._size

        def __getitem__(self, key):
            if isinstance(key, int):
                if key < 0:
                    key += self._size
                if not (0 <= key <= self._size):
                    raise IndexError("index out of range")
                return 0
            elif isinstance(key, slice):
                start, stop, step = key.indices(self._size)
                # step might be negative
                return Binary.ZeroBytes(len(range(start, stop, step)))
            else:
                raise TypeError("invalid index argument type")

        def __eq__(self, other):
            if isinstance(other, (bytes, bytearray)):
                return all(b == 0 for b in other) and len(other) == len(self)
            elif isinstance(other, ZeroBytes):
                return len(other) == len(self)
            else:
                raise NotImplementedError(
                    "invalid comparison with object of unexpected type")

        def __buffer__(self, flags):
            if self._view is not None:
                raise RuntimeError("Buffer already held")
            
            self._view = memoryview(b"\x00") * self._size
            return self._view

        def __release_buffer__(self, buffer):
            if view is not self._view:
                raise RuntimeError("Invalid buffer release")
            
            self._view.release()
            self._view = None

        def __contains__(self, item):
            return item == 0 and len(self) > 0

        def __iter__(self):
            for _ in range(self._size):
                yield 0

        def __bytes__(self):
            return bytes(b"\x00" * self._size)

    @property
    def chunks(self) -> Iterator[Tuple[int, BinaryChunkInfo]]:
        for chunk_handle, chunk_info in enumerate(self._chunks):
            if chunk_handle != ZeroChunkHandle:
                yield chunk_handle, chunk_info
                continue

            # TODO maybe cache this?
            zero_size = 0
            for range_info in self.address_space:
                if not range_info.mapping or range_info.mapping.chunk != ZeroChunkHandle:
                    continue

                zero_size = max(
                    zero_size, range_info.mapping.chunk_offset + range_info.address_range.size)

            yield ZeroChunkHandle, BinaryChunkInfo(chunk_info.name, b"\x00" * zero_size)

    @property
    def symbols(self) -> Iterator[BinarySymbolInfo]:
        for symbol in self._symbols:
            yield symbol

    @property
    def address_symbols(self) -> Iterator[BinaryAddressSymbolInfo]:
        for symbol in self._symbols:
            new_range_infos = self.translate_mapping_range(BinaryMappingRange(
                symbol.mapping, symbol.size))
            for new_range_info in new_range_infos:
                yield BinaryAddressSymbolInfo(symbol.name,
                                              new_range_info.mapping.chunk_offset - symbol.mapping.chunk_offset,
                                              new_range_info.address_range,
                                              new_range_info.mapping)

    @property
    def address_space(self) -> Iterator[BinaryAddressRangeInfo]:
        for address_range_info in self._address_space:
            yield address_range_info

    def __init__(self):
        # Only the zero chunk
        self._chunks = [BinaryChunkInfo(
            "zero_initialized", self.ZeroBytes(2 ** 63))]
        self._symbols = []
        self._address_space = []

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._chunks[key]

        if isinstance(key, BinaryAddressRangeInfo):
            chunk = self[key.mapping.chunk]
            return chunk.data[key.mapping.chunk_offset:
                              key.mapping.chunk_offset + key.address_range.size]

        raise TypeError("invalid index argument type")

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
        if symbol.mapping.chunk >= len(self._chunks) or symbol.mapping.chunk < 0:
            raise InvalidBinaryInfoError(
                "Symbol has an invalid chunk handle")
        if symbol.mapping.chunk_offset > self._chunks[symbol.mapping.chunk].size or symbol.mapping.chunk_offset < 0:
            raise InvalidBinaryInfoError(
                "Symbol chunk offset is out of bounds of chunk")
        if symbol.size < 0:
            raise InvalidBinaryInfoError(
                "Symbol chunk size is negative")
        if symbol.mapping.chunk_offset + symbol.size > self._chunks[symbol.mapping.chunk].size:
            raise InvalidBinaryInfoError(
                "Symbol chunk end offset is out of bounds of chunk")

        self._symbols.append(symbol)

    def translate_mapping_range(self, mapping_range: BinaryMappingRange) -> List[BinaryAddressRangeInfo]:
        mapping = mapping_range.mapping

        if mapping.chunk >= len(self._chunks) or mapping.chunk < 0:
            raise InvalidBinaryInfoError(
                "Mapping has an invalid chunk handle")
        if mapping_range.start > self._chunks[mapping.chunk].size or mapping_range.start < 0:
            raise InvalidBinaryInfoError(
                "Mapping chunk offset is out of bounds of chunk")
        if mapping_range.size < 0:
            raise InvalidBinaryInfoError(
                "Mapping range size is negative")
        if mapping_range.end > self._chunks[mapping.chunk].size or mapping_range.end < 0:
            raise InvalidBinaryInfoError(
                "Mapping end chunk offset is out of bounds of chunk")

        result = []
        for range_info in self.address_space:
            if not range_info.mapping or range_info.mapping.chunk != mapping.chunk:
                continue

            mapping_offset = mapping.chunk_offset - range_info.mapping.chunk_offset
            # if range_info.address_range.start + mapping_offset < 0
            new_range_info = range_info >> mapping_offset
            new_range_info.address_range.size = mapping_range.size

            intersection = new_range_info.address_range & range_info.address_range
            if not intersection:
                continue

            intersection_offset = intersection.start - new_range_info.address_range.start
            new_range_info >>= intersection_offset
            new_range_info.address_range.size = intersection.size

            # print(f"Mapping {str(mapping): <20} size 0x{size: <10x} through {str(range_info): <50} into {new_range_info}")
            result.append(new_range_info)
        return result

    def translate_address_range(self, address_range: BinaryAddressRange) -> List[BinaryAddressRangeInfo]:
        if address_range.start < 0:
            raise InvalidBinaryInfoError(
                "Address range has a negative start address")
        if address_range.size < 0:
            raise InvalidBinaryInfoError(
                "Address range has a negative size")

        result = []
        for range_info in self.address_space:
            if not range_info.mapping:
                continue

            intersection = address_range & range_info.address_range
            if not intersection:
                continue

            new_range_info = range_info >> (
                intersection.start - range_info.address_range.start)
            new_range_info.address_range.size = intersection.size

            result.append(new_range_info)

        return result

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

        # print(info)
        # print(self._address_space)
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
            # print("mapping_range", mapping_range)
            # print("anded_range", BinaryAddressRange.from_start_end(
            #     prev_range.end, next_range.end))
            # print("prev_range", prev_range)
            # print("next_range", next_range)
            # print("imposed_range", imposed_range)

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
                    info.mapping >> (mid_range.start - mapping_range.start)
                    if info.mapping else next_range_info.mapping,
                    info.permissions if info.permissions else next_range_info.permissions)

            if high_range1:
                high_range1 = BinaryAddressRangeInfo(high_range1,
                                                     next_range_info.mapping >> (
                                                         high_range1.start - next_range.start) if next_range_info.mapping else None,
                                                     next_range_info.permissions)

            if high_range2:
                high_range2 = BinaryAddressRangeInfo(high_range2,
                                                     next_range_info.mapping >> (
                                                         high_range2.start - next_range.start) if next_range_info.mapping else None,
                                                     next_range_info.permissions)

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
