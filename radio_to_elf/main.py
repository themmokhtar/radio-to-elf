#!/usr/bin/env python
import logging

from sys import stdout
from argparse import ArgumentParser, Namespace

try:
    from radio_parser import RadioParser
    from matryoshka import matryoshka_unpack

except ImportError:
    from radio_to_elf.radio_parser import RadioParser
    from radio_to_elf.tar_parser import TarParser


def main():
    logging.basicConfig(stream=stdout, level=logging.DEBUG,
                        format='%(message)s')

    args = parse_args()

    try:
        with open(args.input_file, 'rb') as radio_bin:
            radio_data = radio_bin.read()
    except FileNotFoundError:
        logging.error(
            "Input file not found (check the provided path and try again)")
        exit(-1)

    with open(args.output_file, 'wb') as elf_file:
        logging.info(parse_radio(radio_data))
        # TarParser.parse(radio_data)


def parse_args() -> Namespace:
    args = ArgumentParser(
        description='Turn a raw or compressed radio or modem image into a fully analyzable ELF file')

    args.add_argument(
        'input_file', help='Path to the radio.img or modem.bin file to make into an analyzable ELF file')
    args.add_argument(
        'output_file', help='Path to the analyzable ELF file to output')

    return args.parse_args()


def parse_radio(data: bytes) -> dict:
    unpacked_data = matryoshka_unpack(data)

    RadioParser.parse(unpacked_data)


if __name__ == '__main__':
    main()
