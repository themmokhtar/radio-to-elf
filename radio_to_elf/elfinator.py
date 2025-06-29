from makeelf.elf import *

from binary import Binary, BinarySection, BinarySymbol, AddressRange

class Elfinator:

    @staticmethod
    def transform(binary: Binary) -> bytes:
        elf = ELF(e_machine=EM.EM_ARM)
        # print("binary")
        print(elf)
        # print("binary")
        return bytes(elf)