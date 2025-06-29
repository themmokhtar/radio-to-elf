#!/usr/bin/env python
import logging

from sys import stdout
from argparse import ArgumentParser, Namespace
from typing import BinaryIO

try:
    from matryoshka import matryoshka_unpack
    from radio_parser import RadioParser
    from elfinator import Elfinator

except ImportError:
    from radio_to_elf.matryoshka import matryoshka_unpack
    from radio_to_elf.radio_parser import RadioParser
    from radio_to_elf.elfinator import Elfinator


def main():
    logging.basicConfig(stream=stdout, level=logging.DEBUG,
                        format='%(message)s')

    args = parse_args()

    # try:
    with open(args.input_file, 'rb') as input_file:
        with open(args.output_file, 'wb') as output_file:
            radio_data = input_file.read()
            transformed_data = transform(radio_data)
            output_file.write(transformed_data)

    # except FileNotFoundError:
    #     logging.error(
    #         "Input/Output file not found (check the provided paths and try again)")
    #     exit(-1)

        # TarParser.parse(radio_data)


def parse_args() -> Namespace:
    args = ArgumentParser(
        description='Turn a raw or compressed radio or modem image into a fully analyzable ELF file')

    args.add_argument(
        'input_file', help='Path to the radio.img or modem.bin file to make into an analyzable ELF file')
    args.add_argument(
        'output_file', help='Path to the analyzable ELF file to output')

    return args.parse_args()


def transform(input_data: bytes) -> bytes:
    unpacked_data = matryoshka_unpack(input_data)

    binary = RadioParser.parse(unpacked_data)

    elf_data = Elfinator.transform(binary)

    return elf_data


if __name__ == '__main__':
    main()
