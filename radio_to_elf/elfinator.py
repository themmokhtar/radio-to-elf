import logging

from makeelf.elf import *

from binary import Binary, BinaryChunkInfo, BinarySymbolInfo, BinaryAddressRange, BinaryMappingInfo, BinaryPermissionsInfo


class Elfinator:

    @staticmethod
    def transform(binary: Binary) -> bytes:
        elf = ELF(e_machine=EM.EM_ARM)

        chunk_to_section = {}

        for chunk_handle, chunk in binary.chunks:
            section = elf.append_section(chunk.name, chunk.data, 0)

            chunk_to_section[chunk_handle] = section

        bss_section_size = 0
        for range_info in binary.address_space:
            if range_info.mapping:
                continue

            bss_section_size = max(range_info.address_range.size, bss_section_size)

        # TODO: FIXME it will be much better to use a NOBITS section, but that will do for now
        zero_section = elf.append_section(
            "unmapped", "\x00" * bss_section_size, 0)
        chunk_to_section["unmapped"] = zero_section

        phdr_and_chunk = []

        bss_section_offset = 0
        for range_info in binary.address_space:
            flags = 0

            # Default to RWX permissions
            if not range_info.permissions:
                range_info.permissions = BinaryPermissionsInfo(
                    True, True, True)

            # Skip unmapped mappings for now
            if not range_info.mapping:
                continue

            # Calculate flags
            flags |= PF.PF_R if range_info.permissions.readable else 0
            flags |= PF.PF_W if range_info.permissions.writable else 0
            flags |= PF.PF_X if range_info.permissions.executable else 0

            # Calculate chunk offset and fallback to the unmapped chunk
            if range_info.mapping:
                chunk = range_info.mapping.chunk
                chunk_offset = range_info.mapping.chunk_offset
            else:
                chunk = "unmapped"
                chunk_offset = 0
                bss_section_offset += range_info.address_range.size

            phdr = Elf32_Phdr(
                PT.PT_LOAD,
                chunk_offset,
                range_info.address_range.address,
                range_info.address_range.address,
                range_info.address_range.size,
                range_info.address_range.size,
                flags,
                1,
                elf.little
            )

            phdr_and_chunk.append(
                (len(elf.Elf.Phdr_table), chunk))

            elf.Elf.Phdr_table.append(phdr)

        # This is to trigger the calculation of the section offsets
        logging.info("Calculating ELF section offsets")
        bytes(elf)

        # Go back and patch the correct offsets for all the segments
        logging.info("Patching ELF section offsets")
        for phdr, chunk in phdr_and_chunk:
            section = elf.Elf.Shdr_table[chunk_to_section[chunk]]

            elf.Elf.Phdr_table[phdr].p_offset += section.sh_offset

        logging.info("Generating elf file")
        return bytes(elf)

    # @property
    # def chunks(self) -> Iterator[BinaryChunkInfo]:
    #     for chunk in self._chunks:
    #         yield chunk

    # @property
    # def symbols(self) -> Iterator[BinarySymbolInfo]:
    #     for symbol in self._symbols:
    #         yield symbol

    # @property
    # def address_space(self) -> Iterator[BinaryAddressRangeInfo]:
