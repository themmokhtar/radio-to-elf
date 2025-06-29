import os
import logging
import tarfile

from io import BytesIO
from collections import namedtuple
from dataclasses import dataclass
from typing import Iterator

from unpacker import Unpacker

from exceptions import BadFileError, FileParsingError

AddressRange = namedtuple('AddressRange', 'start end')


@dataclass
class BinarySection:
    name: str
    start_address: int
    data: bytes

    # Permissions
    readable: bool
    writable: bool
    executable: bool

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def end_address(self) -> int:
        return self.start_address + self.size

    @property
    def address_range(self) -> AddressRange:
        return AddressRange(self.start_address, self.size)


@dataclass
class BinarySymbol:
    name: str
    address: str

    @property
    def address_range(self) -> AddressRange:
        return AddressRange(self.address, self.address)


class Binary:

    @property
    def sections(self) -> Iterator[BinarySection]:
        for section in self._sections:
            yield section

    @property
    def symbols(self) -> Iterator[BinarySymbol]:
        for symbol in self._symbols:
            yield symbol

    def __init__(self):
        self._sections = []
        self._symbols = []

    def _check_range_overlap(self, first: AddressRange, second: AddressRange):
        return not (first.end <= second.start or second.end <= first.start)

    def add_section(self, section: BinarySection) -> None:
        for other in self._sections:
            if self._check_range_overlap(section.address_range, other.address_range):
                raise SectionOverlapError(
                    f"Cannot have overlapping sections \"{section.name}\" and \"{other.name}\" at {section.address_range} and {other.address_range}")

        self._sections.append(section)

    def add__sections(self, _sections: Iterator[BinarySection]) -> None:
        for section in _sections:
            self.add_section(section)

    def add_symbol(self, symbol: BinarySymbol) -> None:
        for other in self._sections:
            if self._check_range_overlap(symbol.address_range, section.address_range):
                self._symbols.append(symbol)

        raise DanglingSymbolError(
            f"Cannot have a symbol \"{symbol.name}\" at {symbol.address} that belongs to no section")

    def add__symbols(self, _symbols: Iterator[BinarySymbol]) -> None:
        for symbol in _symbols:
            self.add_symbol(symbol)
