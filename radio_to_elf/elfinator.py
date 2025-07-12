import logging

# from ctypes import LittleEndianStructure, c_uint8

# from typing import ClassVar
# from makeelf.elf import *
# import lief

from io import BytesIO

from binary import Binary, BinaryChunkInfo, BinarySymbolInfo, BinaryAddressRange, BinaryMappingInfo, BinaryPermissionsInfo, ZeroChunkHandle

from elf import *


class Elfinator:

    # minimal_elf: ClassVar[list[int]] = b'\x7fELF\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00(\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00T\x00\x00\x00\x00\x004\x00 \x00\x01\x00(\x00\x02\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa4\x00\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00.shstrtab\x00'
    # minimal_elf: ClassVar[list[int]] = [
    #     0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    #     0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
    #     0x04, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x10, 0x00, 0xf1, 0xff,
    #     0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0xf1, 0xff,
    #     0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x10, 0x00, 0xf1, 0xff,
    #     0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00, 0xf1, 0xff,
    #     0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x5f, 0x5f, 0x62, 0x73, 0x73, 0x5f, 0x73,
    #     0x74, 0x61, 0x72, 0x74, 0x00, 0x5f, 0x65, 0x64, 0x61, 0x74, 0x61, 0x00,
    #     0x5f, 0x65, 0x6e, 0x64, 0x00, 0x00, 0x2e, 0x73, 0x79, 0x6d, 0x74, 0x61,
    #     0x62, 0x00, 0x2e, 0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0x00, 0x2e, 0x73,
    #     0x68, 0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    #     0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
    #     0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x11, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0xd1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00,
    # ]
    # minimal_elf: ClassVar[list[int]] = [
    #     0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00]
    #      0x10, 0x00, 0xf1, 0xff,
    #     0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0xf1, 0xff,
    #     0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x10, 0x00, 0xf1, 0xff,
    #     0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00, 0xf1, 0xff,
    #     0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x5f, 0x5f, 0x62, 0x73, 0x73, 0x5f, 0x73,
    #     0x74, 0x61, 0x72, 0x74, 0x00, 0x5f, 0x65, 0x64, 0x61, 0x74, 0x61, 0x00,
    #     0x5f, 0x65, 0x6e, 0x64, 0x00, 0x00, 0x2e, 0x73, 0x79, 0x6d, 0x74, 0x61,
    #     0x62, 0x00, 0x2e, 0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0x00, 0x2e, 0x73,
    #     0x68, 0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    #     0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
    #     0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x11, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0xd1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    #     0x00, 0x00, 0x00, 0x00,
    # ]

    @staticmethod
    def transform(binary: Binary) -> bytes:
        #####################
        ### Build headers ###
        #####################

        ehdr = Elf32_Ehdr()
        ehdr.e_ident[EI_MAG0] = ELFMAG0
        ehdr.e_ident[EI_MAG1] = ELFMAG1
        ehdr.e_ident[EI_MAG2] = ELFMAG2
        ehdr.e_ident[EI_MAG3] = ELFMAG3
        ehdr.e_ident[EI_CLASS] = ELFCLASS32
        ehdr.e_ident[EI_DATA] = ELFDATA2LSB
        ehdr.e_ident[EI_VERSION] = EV_CURRENT
        ehdr.e_ident[EI_OSABI] = ELFOSABI_ARM
        ehdr.e_ident[EI_ABIVERSION] = 0
        ehdr.e_type = ET_EXEC
        ehdr.e_machine = EM_ARM
        ehdr.e_version = EV_CURRENT
        ehdr.e_entry = 0
        ehdr.e_phoff = 0  # Deferred
        ehdr.e_shoff = 0  # Deferred
        ehdr.e_flags = 0
        ehdr.e_ehsize = len(bytes(Elf32_Ehdr()))
        ehdr.e_phentsize = len(bytes(Elf32_Phdr()))
        ehdr.e_phnum = 0  # Deferred
        ehdr.e_shentsize = len(bytes(Elf32_Shdr()))
        ehdr.e_shnum = 0  # Deferred
        ehdr.e_shstrndx = SHN_UNDEF  # Deferred

        shstrtab_data = b"\x00.shstrtab\x00"
        shstrtab_shdr = Elf32_Shdr()
        shstrtab_shdr.sh_name = 1
        shstrtab_shdr.sh_type = SHT_STRTAB
        shstrtab_shdr.sh_flags = 0
        shstrtab_shdr.sh_addr = 0
        shstrtab_shdr.sh_offset = 0  # Deferred
        shstrtab_shdr.sh_size = 0  # Deferred
        shstrtab_shdr.sh_link = 0
        shstrtab_shdr.sh_info = 0
        shstrtab_shdr.sh_addralign = 0
        shstrtab_shdr.sh_entsize = 0

        strtab_data = b"\x00"
        strtab_shdr = Elf32_Shdr()
        strtab_shdr.sh_name = len(shstrtab_data)
        strtab_shdr.sh_type = SHT_STRTAB
        strtab_shdr.sh_flags = 0
        strtab_shdr.sh_addr = 0
        strtab_shdr.sh_offset = 0  # Deferred
        strtab_shdr.sh_size = 0  # Deferred
        strtab_shdr.sh_link = 0
        strtab_shdr.sh_info = 0
        strtab_shdr.sh_addralign = 0
        strtab_shdr.sh_entsize = 0
        strtab_size = 0
        shstrtab_data += b".strtab\x00"

        symtab_data = b""
        symtab_shdr = Elf32_Shdr()
        symtab_shdr.sh_name = len(shstrtab_data)
        symtab_shdr.sh_type = SHT_SYMTAB
        symtab_shdr.sh_flags = 0
        symtab_shdr.sh_addr = 0
        symtab_shdr.sh_offset = 0  # Deferred
        symtab_shdr.sh_size = 0  # Deferred
        symtab_shdr.sh_link = 0  # Deferred
        symtab_shdr.sh_info = 1
        symtab_shdr.sh_addralign = 0
        symtab_shdr.sh_entsize = len(bytes(Elf32_Sym()))
        symtab_size = 0
        shstrtab_data += b".symtab\x00"

        unmapped_shdr = Elf32_Shdr()
        unmapped_shdr.sh_name = len(shstrtab_data)
        unmapped_shdr.sh_type = SHT_NOBITS
        unmapped_shdr.sh_flags = 0
        unmapped_shdr.sh_addr = 0
        unmapped_shdr.sh_offset = 0  # Deferred
        unmapped_shdr.sh_size = 0  # Deferred
        unmapped_shdr.sh_link = 0
        unmapped_shdr.sh_info = 0
        unmapped_shdr.sh_addralign = 0
        unmapped_shdr.sh_entsize = 0
        unmapped_size = 0
        shstrtab_data += b"unmapped\x00"

        shdrs = []
        chunk_to_shdr_idx = {}
        for chunk_handle, chunk in binary.chunks:
            shdr = Elf32_Shdr()
            shdr.sh_name = len(shstrtab_data)
            shdr.sh_type = SHT_NOBITS if chunk_handle == ZeroChunkHandle else SHT_PROGBITS
            shdr.sh_flags = 0
            shdr.sh_addr = 0
            shdr.sh_offset = 0  # Deferred
            shdr.sh_size = chunk.size
            shdr.sh_link = 0
            shdr.sh_info = 0
            shdr.sh_addralign = 0
            shdr.sh_entsize = 0

            shstrtab_data += chunk.name.encode('utf-8') + b"\x00"

            chunk_to_shdr_idx[chunk_handle] = len(shdrs)

            shdrs.append((shdr, None if shdr.sh_type == SHT_NOBITS else chunk))

        phdrs = []
        for range_info in binary.address_space:
            flags = 0

            # Default to RWX permissions
            if not range_info.permissions:
                range_info.permissions = BinaryPermissionsInfo(
                    True, True, True)

            # Get the corresponding shdr index
            shdr_idx = -1  # Default for the unmapped section
            if range_info.mapping:
                shdr_idx = chunk_to_shdr_idx[range_info.mapping.chunk]
            else:
                unmapped_shdr.sh_size = \
                    max(unmapped_shdr.sh_size,
                        range_info.address_range.size)  # Fulfilled

            phdr = Elf32_Phdr()
            phdr.p_type = PT_LOAD
            phdr.p_offset = range_info.mapping.chunk_offset if range_info.mapping else 0  # Deferred
            phdr.p_vaddr = range_info.address_range.address
            phdr.p_paddr = 0
            phdr.p_filesz = range_info.address_range.size if range_info.mapping else 0
            phdr.p_memsz = range_info.address_range.size
            phdr.p_flags = 0
            phdr.p_flags |= PF_R if range_info.permissions.readable else 0
            phdr.p_flags |= PF_W if range_info.permissions.writable else 0
            phdr.p_flags |= PF_X if range_info.permissions.executable else 0
            phdr.p_align = 1

            phdrs.append((phdr, shdr_idx))

        symtab_data += bytes(Elf32_Sym(st_shndx=SHN_UNDEF))
        for symbol in binary.address_symbols:
            sym = Elf32_Sym()
            sym.st_name = len(strtab_data)
            sym.st_value = symbol.address_range.address
            sym.st_size = symbol.address_range.size
            # TODO: Maybe we actually want to associate types here
            sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_NOTYPE)
            sym.st_other = STV_DEFAULT
            # +1 for the first empty shdr
            sym.st_shndx = chunk_to_shdr_idx[symbol.mapping.chunk] + 1
            strtab_data += f"{symbol.name}+0x{symbol.offset:x},0x{symbol.address_range.size:x}".encode(
                'utf-8') + b"\x00"

            symtab_data += bytes(sym)

        ######################
        ### Update offsets ###
        ######################
        ehdr.e_phnum = len(phdrs)  # Fulfilled

        # Fulfilled (+5 first NULL section, 'unmapped' section, 'symtab' section, 'strtab' section, '.shstrtab' section)
        ehdr.e_shnum = len(shdrs) + 5
        if ehdr.e_shnum > SHN_LORESERVE:
            raise NotImplementedError(
                f"Cannot handle more sections than SHN_LORESERVE ({SHN_LORESERVE})")

        ehdr.e_shstrndx = ehdr.e_shnum - 1  # Fulfilled

        offset = len(bytes(Elf32_Ehdr()))

        ehdr.e_phoff = offset  # Fulfilled
        offset += len(phdrs) * len(bytes(Elf32_Phdr()))

        for shdr, chunk in shdrs:
            shdr.sh_offset = offset  # Fulfilled

            if shdr.sh_type != SHT_NOBITS:
                offset += len(chunk.data)

        unmapped_shdr.sh_offset = offset  # Fulfilled

        strtab_shdr.sh_offset = offset  # Fulfilled
        strtab_shdr.sh_size = len(strtab_data)  # Fulfilled
        offset += strtab_shdr.sh_size

        symtab_shdr.sh_offset = offset  # Fulfilled
        symtab_shdr.sh_size = len(symtab_data)  # Fulfilled
        symtab_shdr.sh_link = ehdr.e_shnum - 3  # Fulfilled
        offset += symtab_shdr.sh_size

        shstrtab_shdr.sh_offset = offset  # Fulfilled
        shstrtab_shdr.sh_size = len(shstrtab_data)  # Fulfilled
        offset += shstrtab_shdr.sh_size

        ehdr.e_shoff = offset  # Fulfilled

        for i in range(len(phdrs)):
            shdr_idx = phdrs[i][1]
            shdr = unmapped_shdr if shdr_idx == -1 else shdrs[shdr_idx][0]
            phdrs[i][0].p_offset += shdr.sh_offset  # Fulfilled

        ######################
        ### Generate bytes ###
        ######################
        result = BytesIO()

        result.write(ehdr)

        for phdr, _ in phdrs:
            result.write(phdr)

        for shdr, chunk in shdrs:
            if shdr.sh_type == SHT_NOBITS:
                continue

            result.write(chunk.data)
        
        result.write(strtab_data)
        result.write(symtab_data)
        result.write(shstrtab_data)

        result.write(Elf32_Shdr())
        for shdr, _ in shdrs:
            result.write(shdr)
        result.write(unmapped_shdr)
        result.write(strtab_shdr)
        result.write(symtab_shdr)
        result.write(shstrtab_shdr)

        result.seek(0)
        return result.read()
        # elf = lief.ELF.parse(list(Elfinator.minimal_elf))
        # # print(bytes(elf))

        # chunk_to_section = {}

        # for section in elf.sections:
        #     elf.remove(section)
        # # for section in elf.segments:
        # #     elf.segments.remove(section)
        # # print(section)
        # for chunk_handle, chunk in binary.chunks:
        #     section = lief.ELF.Section(chunk.name)
        #     section.content = list(chunk.data)
        #     section = elf.add(section)
        #     print(f"section {section}")

        # # chunk_to_section[chunk_handle] = section

        # logging.info("Building ELF binary")
        # builder = lief.ELF.Builder(elf)
        # builder.build()

        # return bytes(builder.get_build())

    # @staticmethod
    # def transform(binary: Binary) -> bytes:
    #     elf = ELF(e_machine=EM.EM_ARM)
    #     print(bytes(elf))
    #     return bytes(elf)
    #     chunk_to_section = {}

    #     for chunk_handle, chunk in binary.chunks:
    #         section = elf.append_section(chunk.name, chunk.data, 0)

    #         chunk_to_section[chunk_handle] = section

    #     bss_section_size = 0
    #     for range_info in binary.address_space:
    #         if range_info.mapping:
    #             continue

    #         bss_section_size = max(range_info.address_range.size, bss_section_size)

    #     # TODO: FIXME it will be much better to use a NOBITS section, but that will do for now
    #     zero_section = elf.append_section(
    #         "unmapped", "\x00" * bss_section_size, 0)
    #     chunk_to_section["unmapped"] = zero_section

    #     phdr_and_chunk = []

    #     bss_section_offset = 0
    #     for range_info in binary.address_space:
    #         flags = 0

    #         # Default to RWX permissions
    #         if not range_info.permissions:
    #             range_info.permissions = BinaryPermissionsInfo(
    #                 True, True, True)

    #         # Skip unmapped mappings for now
    #         if not range_info.mapping:
    #             continue

    #         # Calculate flags
    #         flags |= PF.PF_R if range_info.permissions.readable else 0
    #         flags |= PF.PF_W if range_info.permissions.writable else 0
    #         flags |= PF.PF_X if range_info.permissions.executable else 0

    #         # Calculate chunk offset and fallback to the unmapped chunk
    #         if range_info.mapping:
    #             chunk = range_info.mapping.chunk
    #             chunk_offset = range_info.mapping.chunk_offset
    #         else:
    #             chunk = "unmapped"
    #             chunk_offset = 0
    #             bss_section_offset += range_info.address_range.size

    #         phdr = Elf32_Phdr(
    #             PT.PT_LOAD,
    #             chunk_offset,
    #             range_info.address_range.address,
    #             range_info.address_range.address,
    #             range_info.address_range.size,
    #             range_info.address_range.size,
    #             flags,
    #             1,
    #             elf.little
    #         )

    #         phdr_and_chunk.append(
    #             (len(elf.Elf.Phdr_table), chunk))

    #         elf.Elf.Phdr_table.append(phdr)

    #     # This is to trigger the calculation of the section offsets
    #     logging.info("Calculating ELF section offsets")
    #     bytes(elf)

    #     # Go back and patch the correct offsets for all the segments
    #     logging.info("Patching ELF section offsets")
    #     for phdr, chunk in phdr_and_chunk:
    #         section = elf.Elf.Shdr_table[chunk_to_section[chunk]]

    #         elf.Elf.Phdr_table[phdr].p_offset += section.sh_offset

    #     logging.info("Generating elf file")
    #     return bytes(elf)

    # # @property
    # # def chunks(self) -> Iterator[BinaryChunkInfo]:
    # #     for chunk in self._chunks:
    # #         yield chunk

    # # @property
    # # def symbols(self) -> Iterator[BinarySymbolInfo]:
    # #     for symbol in self._symbols:
    # #         yield symbol

    # # @property
    # # def address_space(self) -> Iterator[BinaryAddressRangeInfo]:
