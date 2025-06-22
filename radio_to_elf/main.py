#!/usr/bin/python3
import logging

from sys import stdout
from argparse import ArgumentParser

try:
    from radio_parser import RadioParser

except ImportError:
    from radio_to_elf.radio_parser import RadioParser

if __name__ == '__main__':
    logging.basicConfig(stream=stdout, level=logging.DEBUG,
                        format='%(message)s')

    args = ArgumentParser(
        description='Turn a raw or compressed radio or modem image into a fully analyzable ELF file')

    args.add_argument(
        'input_file', help='Path to the radio.img or modem.bin file to make into an analyzable ELF file')
    args.add_argument(
        'output_file', help='Path to the analyzable ELF file to output')

    args = args.parse_args()

    try:
        with open(args.input_file, 'rb') as radio_bin:
            radio_data = radio_bin.read()
    except FileNotFoundError:
        logging.error(
            "Input file not found (check the provided path and try again)")
        exit(-1)

    with open(args.output_file, 'wb') as elf_file:
        RadioParser.parse(radio_data)
