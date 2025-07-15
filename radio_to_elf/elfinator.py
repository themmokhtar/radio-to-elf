import logging

# from ctypes import LittleEndianStructure, c_uint8

from typing import ClassVar

from io import BytesIO

from binary import Binary, BinaryChunkInfo, BinarySymbolType, BinarySymbolInfo, BinaryAddressRange, BinaryMappingRange, BinaryMappingInfo, BinaryPermissionsInfo, ZeroChunkHandle

from elf import *


class Elfinator:
    symbol_dict: ClassVar[dict] = {
        BinarySymbolType.NONE: STT_NOTYPE,
        BinarySymbolType.DATA: STT_OBJECT,
        BinarySymbolType.FUNCTION: STT_FUNC,
        BinarySymbolType.SECTION: STT_SECTION,
    }

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

        # Each item in here will contain: (shdr, phdr, data_bytes | None, address_range)
        hdrs = []
        for range_info in binary.address_space:
            # Default to RWX permissions
            if not range_info.permissions:
                range_info.permissions = BinaryPermissionsInfo(
                    True, True, True)

            # Get the section data
            data = None
            chunk_offset = 0
            size = range_info.address_range.size
            section_name = "unintialized"
            if range_info.mapping and range_info.mapping.chunk != ZeroChunkHandle:
                chunk = binary.chunks[range_info.mapping.chunk]
                chunk_offset = range_info.mapping.chunk_offset

                data = chunk.data
                data = data[chunk_offset:
                            chunk_offset + size]

                if len(data) != size:
                    raise RuntimeError(
                        "Chunk slice and mapping size do not match")

                section_name = f"{chunk.name}+{chunk_offset:#x}"

            # Create the section header
            shdr = Elf32_Shdr()
            shdr.sh_name = len(shstrtab_data)
            shdr.sh_type = SHT_NOBITS if data == None else SHT_PROGBITS
            shdr.sh_flags = SHF_ALLOC
            # This line is added for completeness, but there is no "readable" flag
            shdr.sh_flags |= 0 if range_info.permissions.readable else 0
            shdr.sh_flags |= SHF_WRITE if range_info.permissions.writable else 0
            shdr.sh_flags |= SHF_EXECINSTR if range_info.permissions.executable else 0
            shdr.sh_addr = range_info.address_range.address
            shdr.sh_offset = 0  # Deferred
            shdr.sh_size = size
            shdr.sh_link = 0
            shdr.sh_info = 0
            shdr.sh_addralign = 0
            shdr.sh_entsize = 0
            shstrtab_data += section_name.encode('utf-8') + b"\x00"

            # Create the program header
            phdr = Elf32_Phdr()
            phdr.p_type = PT_LOAD
            phdr.p_offset = 0  # Deferred
            phdr.p_vaddr = range_info.address_range.address
            phdr.p_paddr = 0
            phdr.p_filesz = 0 if data == None else size
            phdr.p_memsz = size
            phdr.p_flags = 0
            phdr.p_flags |= PF_R if range_info.permissions.readable else 0
            phdr.p_flags |= PF_W if range_info.permissions.writable else 0
            phdr.p_flags |= PF_X if range_info.permissions.executable else 0
            phdr.p_align = 1

            # Put it all as one list entry
            hdrs.append((shdr, phdr, data, range_info.address_range))

        symtab_data += bytes(Elf32_Sym(st_shndx=SHN_UNDEF))
        for symbol in binary.address_symbols:
            sym = Elf32_Sym()
            sym.st_name = len(strtab_data)
            sym.st_value = symbol.address_range.address
            sym.st_size = symbol.address_range.size
            sym.st_info = ELF64_ST_INFO(
                STB_GLOBAL, Elfinator.symbol_dict[symbol.stype])
            sym.st_other = STV_DEFAULT

            # No we want to find all the sections where that address range lies
            matching_ranges = [(idx, x) for idx, x in enumerate(
                hdrs) if symbol.address_range.address in x[3]]
            if len(matching_ranges) == 0:
                raise RuntimeError("Symbol is not present in any mapped range")
            if len(matching_ranges) > 1:
                raise NotImplementedError(
                    "Symbol is present in more than one mapped range")

            hdr_idx, matching_range = matching_ranges[0]
            intersection_range = BinaryAddressRange(
                symbol.address_range.address, 1) if symbol.address_range.size == 0 else symbol.address_range
            matching_range_intersection = matching_range[3] & intersection_range
            if matching_range_intersection != intersection_range:
                raise NotImplementedError(
                    "Symbol is not fully present in the target range")

            # +1 for the first empty shdr
            sym.st_shndx = hdr_idx + 1

            symbol_name = symbol.name
            if symbol.symbol_suboffset != 0:
                symbol_name += f"+0x{symbol.symbol_suboffset:x}"

            strtab_data += symbol_name.encode('utf-8') + b"\x00"

            symtab_data += bytes(sym)

        ######################
        ### Update offsets ###
        ######################
        ehdr.e_phnum = len(hdrs)  # Fulfilled

        # Fulfilled (+4 first NULL section, 'symtab' section, 'strtab' section, '.shstrtab' section)
        ehdr.e_shnum = len(hdrs) + 4
        if ehdr.e_shnum > SHN_LORESERVE:
            raise NotImplementedError(
                f"Cannot handle more sections than SHN_LORESERVE ({SHN_LORESERVE})")

        ehdr.e_shstrndx = ehdr.e_shnum - 1  # Fulfilled

        offset = len(bytes(Elf32_Ehdr()))

        ehdr.e_phoff = offset  # Fulfilled
        offset += len(hdrs) * len(bytes(Elf32_Phdr()))

        for shdr, phdr, data, address_range in hdrs:
            shdr.sh_offset = offset  # Fulfilled
            phdr.p_offset = offset  # Fulfilled

            if shdr.sh_type == SHT_NOBITS:
                continue

            offset += len(data)

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

        ######################
        ### Generate bytes ###
        ######################
        result = BytesIO()

        result.write(ehdr)

        for shdr, phdr, data, address_range in hdrs:
            result.write(phdr)

        for shdr, phdr, data, address_range in hdrs:
            if shdr.sh_type == SHT_NOBITS:
                continue

            result.write(data)

        result.write(strtab_data)
        result.write(symtab_data)
        result.write(shstrtab_data)

        result.write(Elf32_Shdr())
        for shdr, phdr, data, address_range in hdrs:
            result.write(shdr)
        # result.write(unmapped_shdr)
        result.write(strtab_shdr)
        result.write(symtab_shdr)
        result.write(shstrtab_shdr)

        result.seek(0)
        return result.read()

    # I'm leaving this here because I love it
    @staticmethod
    def transform_legacy(binary: Binary) -> bytes:
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
            sym.st_info = ELF64_ST_INFO(
                STB_GLOBAL, Elfinator.symbol_dict[symbol.stype])
            sym.st_other = STV_DEFAULT
            # +1 for the first empty shdr
            sym.st_shndx = chunk_to_shdr_idx[symbol.mapping.chunk] + 1

            symbol_name = symbol.name
            if symbol.symbol_suboffset != 0:
                symbol_name += f"+0x{symbol.symbol_suboffset:x}"

            strtab_data += symbol_name.encode('utf-8') + b"\x00"

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
