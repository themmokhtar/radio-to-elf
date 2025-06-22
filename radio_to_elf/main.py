#!/usr/bin/python3
from sys import stdout
from argparse import ArgumentParser
import logging

if __name__ == '__main__':
    logging.basicConfig(stream=stdout, level=logging.INFO, format='%(message)s')

    args = ArgumentParser(description='Turn a raw or compressed radio or modem image into a fully analyzable ELF file')

    args.add_argument('input_file', help='Path to the radio.img/modem.img file to make into an analyzable ELF file')
    args.add_argument('input_file', help='Path to the analyzable ELF file to output')

    args = args.parse_args()

    print(args)
