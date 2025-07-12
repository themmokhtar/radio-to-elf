# This is just a python version of uapi/linux/elf.h

from ctypes import Structure, Union, c_uint8, c_uint16, c_uint32, c_uint64, c_int8, c_int16, c_int32, c_int64
from enum import Enum

# 32-bit ELF base types.
Elf32_Addr = c_uint32
Elf32_Half = c_uint16
Elf32_Off = c_uint32
Elf32_Sword = c_int32
Elf32_Word = c_uint32

# 64-bit ELF base types.
Elf64_Addr = c_uint64
Elf64_Half = c_uint16
Elf64_SHalf = c_int16
Elf64_Off = c_uint64
Elf64_Sword = c_int32
Elf64_Word = c_uint32
Elf64_Xword = c_uint64
Elf64_Sxword = c_int64

# These constants are for the segment types stored in the image headers
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7  # Thread local storage segment
PT_LOOS = 0x60000000  # OS-specific
PT_HIOS = 0x6fffffff  # OS-specific
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7fffffff
PT_GNU_EH_FRAME = (PT_LOOS + 0x474e550)
PT_GNU_STACK = (PT_LOOS + 0x474e551)
PT_GNU_RELRO = (PT_LOOS + 0x474e552)
PT_GNU_PROPERTY = (PT_LOOS + 0x474e553)

# ARM MTE memory tag segment type
PT_AARCH64_MEMTAG_MTE = (PT_LOPROC + 0x2)

#
# Extended Numbering
#
# If the real number of program header table entries is larger than
# or equal to PN_XNUM(0xffff), it is set to sh_info field of the
# section header at index 0, and PN_XNUM is set to e_phnum
# field. Otherwise, the section header at index 0 is zero
# initialized, if it exists.
#
# Specifications are available in:
#
# - Oracle: Linker and Libraries.
#   Part No: 817–1984–19, August 2011.
#   https://docs.oracle.com/cd/E18752_01/pdf/817-1984.pdf
#
# - System V ABI AMD64 Architecture Processor Supplement
#   Draft Version 0.99.4,
#   January 13, 2010.
#   http://www.cs.washington.edu/education/courses/cse351/12wi/supp-docs/abi.pdf
#
PN_XNUM = 0xffff

# These constants define the different elf file types
ET_NONE = 0
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
ET_CORE = 4
ET_LOPROC = 0xff00
ET_HIPROC = 0xffff

# Legal values for e_machine (architecture).  

EM_NONE = 0  # No machine 
EM_M32 = 1  # AT&T WE 32100 
EM_SPARC = 2  # SUN SPARC 
EM_386 = 3  # Intel 80386 
EM_68K = 4  # Motorola m68k family 
EM_88K = 5  # Motorola m88k family 
EM_IAMCU = 6  # Intel MCU 
EM_860 = 7  # Intel 80860 
EM_MIPS = 8  # MIPS R3000 big-endian 
EM_S370 = 9  # IBM System/370 
EM_MIPS_RS3_LE = 10  # MIPS R3000 little-endian 
		# reserved 11-14 
EM_PARISC = 15  # HPPA 
		# reserved 16 
EM_VPP500 = 17  # Fujitsu VPP500 
EM_SPARC32PLUS = 18  # Sun's "v8plus" 
EM_960 = 19  # Intel 80960 
EM_PPC = 20  # PowerPC 
EM_PPC64 = 21  # PowerPC 64-bit 
EM_S390 = 22  # IBM S390 
EM_SPU = 23  # IBM SPU/SPC 
		# reserved 24-35 
EM_V800 = 36  # NEC V800 series 
EM_FR20 = 37  # Fujitsu FR20 
EM_RH32 = 38  # TRW RH-32 
EM_RCE = 39  # Motorola RCE 
EM_ARM = 40  # ARM 
EM_FAKE_ALPHA = 41  # Digital Alpha 
EM_SH = 42  # Hitachi SH 
EM_SPARCV9 = 43  # SPARC v9 64-bit 
EM_TRICORE = 44  # Siemens Tricore 
EM_ARC = 45  # Argonaut RISC Core 
EM_H8_300 = 46  # Hitachi H8/300 
EM_H8_300H = 47  # Hitachi H8/300H 
EM_H8S = 48  # Hitachi H8S 
EM_H8_500 = 49  # Hitachi H8/500 
EM_IA_64 = 50  # Intel Merced 
EM_MIPS_X = 51  # Stanford MIPS-X 
EM_COLDFIRE = 52  # Motorola Coldfire 
EM_68HC12 = 53  # Motorola M68HC12 
EM_MMA = 54  # Fujitsu MMA Multimedia Accelerator 
EM_PCP = 55  # Siemens PCP 
EM_NCPU = 56  # Sony nCPU embedded RISC 
EM_NDR1 = 57  # Denso NDR1 microprocessor 
EM_STARCORE = 58  # Motorola Start*Core processor 
EM_ME16 = 59  # Toyota ME16 processor 
EM_ST100 = 60  # STMicroelectronic ST100 processor 
EM_TINYJ = 61  # Advanced Logic Corp. Tinyj emb.fam 
EM_X86_64 = 62  # AMD x86-64 architecture 
EM_PDSP = 63  # Sony DSP Processor 
EM_PDP10 = 64  # Digital PDP-10 
EM_PDP11 = 65  # Digital PDP-11 
EM_FX66 = 66  # Siemens FX66 microcontroller 
EM_ST9PLUS = 67  # STMicroelectronics ST9+ 8/16 mc 
EM_ST7 = 68  # STmicroelectronics ST7 8 bit mc 
EM_68HC16 = 69  # Motorola MC68HC16 microcontroller 
EM_68HC11 = 70  # Motorola MC68HC11 microcontroller 
EM_68HC08 = 71  # Motorola MC68HC08 microcontroller 
EM_68HC05 = 72  # Motorola MC68HC05 microcontroller 
EM_SVX = 73  # Silicon Graphics SVx 
EM_ST19 = 74  # STMicroelectronics ST19 8 bit mc 
EM_VAX = 75  # Digital VAX 
EM_CRIS = 76  # Axis Communications 32-bit emb.proc 
EM_JAVELIN = 77  # Infineon Technologies 32-bit emb.proc 
EM_FIREPATH = 78  # Element 14 64-bit DSP Processor 
EM_ZSP = 79  # LSI Logic 16-bit DSP Processor 
EM_MMIX = 80  # Donald Knuth's educational 64-bit proc 
EM_HUANY = 81  # Harvard University machine-independent object files 
EM_PRISM = 82  # SiTera Prism 
EM_AVR = 83  # Atmel AVR 8-bit microcontroller 
EM_FR30 = 84  # Fujitsu FR30 
EM_D10V = 85  # Mitsubishi D10V 
EM_D30V = 86  # Mitsubishi D30V 
EM_V850 = 87  # NEC v850 
EM_M32R = 88  # Mitsubishi M32R 
EM_MN10300 = 89  # Matsushita MN10300 
EM_MN10200 = 90  # Matsushita MN10200 
EM_PJ = 91  # picoJava 
EM_OPENRISC = 92  # OpenRISC 32-bit embedded processor 
EM_ARC_COMPACT = 93  # ARC International ARCompact 
EM_XTENSA = 94  # Tensilica Xtensa Architecture 
EM_VIDEOCORE = 95  # Alphamosaic VideoCore 
EM_TMM_GPP = 96  # Thompson Multimedia General Purpose Proc 
EM_NS32K = 97  # National Semi. 32000 
EM_TPC = 98  # Tenor Network TPC 
EM_SNP1K = 99  # Trebia SNP 1000 
EM_ST200 = 100  # STMicroelectronics ST200 
EM_IP2K = 101  # Ubicom IP2xxx 
EM_MAX = 102  # MAX processor 
EM_CR = 103  # National Semi. CompactRISC 
EM_F2MC16 = 104  # Fujitsu F2MC16 
EM_MSP430 = 105  # Texas Instruments msp430 
EM_BLACKFIN = 106  # Analog Devices Blackfin DSP 
EM_SE_C33 = 107  # Seiko Epson S1C33 family 
EM_SEP = 108  # Sharp embedded microprocessor 
EM_ARCA = 109  # Arca RISC 
EM_UNICORE = 110  # PKU-Unity & MPRC Peking Uni. mc series 
EM_EXCESS = 111  # eXcess configurable cpu 
EM_DXP = 112  # Icera Semi. Deep Execution Processor 
EM_ALTERA_NIOS2 = 113  # Altera Nios II 
EM_CRX = 114  # National Semi. CompactRISC CRX 
EM_XGATE = 115  # Motorola XGATE 
EM_C166 = 116  # Infineon C16x/XC16x 
EM_M16C = 117  # Renesas M16C 
EM_DSPIC30F = 118  # Microchip Technology dsPIC30F 
EM_CE = 119  # Freescale Communication Engine RISC 
EM_M32C = 120  # Renesas M32C 
		# reserved 121-130 
EM_TSK3000 = 131  # Altium TSK3000 
EM_RS08 = 132  # Freescale RS08 
EM_SHARC = 133  # Analog Devices SHARC family 
EM_ECOG2 = 134  # Cyan Technology eCOG2 
EM_SCORE7 = 135  # Sunplus S+core7 RISC 
EM_DSP24 = 136  # New Japan Radio (NJR) 24-bit DSP 
EM_VIDEOCORE3 = 137  # Broadcom VideoCore III 
EM_LATTICEMICO32 = 138  # RISC for Lattice FPGA 
EM_SE_C17 = 139  # Seiko Epson C17 
EM_TI_C6000 = 140  # Texas Instruments TMS320C6000 DSP 
EM_TI_C2000 = 141  # Texas Instruments TMS320C2000 DSP 
EM_TI_C5500 = 142  # Texas Instruments TMS320C55x DSP 
EM_TI_ARP32 = 143  # Texas Instruments App. Specific RISC 
EM_TI_PRU = 144  # Texas Instruments Prog. Realtime Unit 
		# reserved 145-159 
EM_MMDSP_PLUS = 160  # STMicroelectronics 64bit VLIW DSP 
EM_CYPRESS_M8C = 161  # Cypress M8C 
EM_R32C = 162  # Renesas R32C 
EM_TRIMEDIA = 163  # NXP Semi. TriMedia 
EM_QDSP6 = 164  # QUALCOMM DSP6 
EM_8051 = 165  # Intel 8051 and variants 
EM_STXP7X = 166  # STMicroelectronics STxP7x 
EM_NDS32 = 167  # Andes Tech. compact code emb. RISC 
EM_ECOG1X = 168  # Cyan Technology eCOG1X 
EM_MAXQ30 = 169  # Dallas Semi. MAXQ30 mc 
EM_XIMO16 = 170  # New Japan Radio (NJR) 16-bit DSP 
EM_MANIK = 171  # M2000 Reconfigurable RISC 
EM_CRAYNV2 = 172  # Cray NV2 vector architecture 
EM_RX = 173  # Renesas RX 
EM_METAG = 174  # Imagination Tech. META 
EM_MCST_ELBRUS = 175  # MCST Elbrus 
EM_ECOG16 = 176  # Cyan Technology eCOG16 
EM_CR16 = 177  # National Semi. CompactRISC CR16 
EM_ETPU = 178  # Freescale Extended Time Processing Unit 
EM_SLE9X = 179  # Infineon Tech. SLE9X 
EM_L10M = 180  # Intel L10M 
EM_K10M = 181  # Intel K10M 
		# reserved 182 
EM_AARCH64 = 183  # ARM AARCH64 
		# reserved 184 
EM_AVR32 = 185  # Amtel 32-bit microprocessor 
EM_STM8 = 186  # STMicroelectronics STM8 
EM_TILE64 = 187  # Tilera TILE64 
EM_TILEPRO = 188  # Tilera TILEPro 
EM_MICROBLAZE = 189  # Xilinx MicroBlaze 
EM_CUDA = 190  # NVIDIA CUDA 
EM_TILEGX = 191  # Tilera TILE-Gx 
EM_CLOUDSHIELD = 192  # CloudShield 
EM_COREA_1ST = 193  # KIPO-KAIST Core-A 1st gen. 
EM_COREA_2ND = 194  # KIPO-KAIST Core-A 2nd gen. 
EM_ARCV2 = 195  # Synopsys ARCv2 ISA.  
EM_OPEN8 = 196  # Open8 RISC 
EM_RL78 = 197  # Renesas RL78 
EM_VIDEOCORE5 = 198  # Broadcom VideoCore V 
EM_78KOR = 199  # Renesas 78KOR 
EM_56800EX = 200  # Freescale 56800EX DSC 
EM_BA1 = 201  # Beyond BA1 
EM_BA2 = 202  # Beyond BA2 
EM_XCORE = 203  # XMOS xCORE 
EM_MCHP_PIC = 204  # Microchip 8-bit PIC(r) 
EM_INTELGT = 205  # Intel Graphics Technology 
		# reserved 206-209 
EM_KM32 = 210  # KM211 KM32 
EM_KMX32 = 211  # KM211 KMX32 
EM_EMX16 = 212  # KM211 KMX16 
EM_EMX8 = 213  # KM211 KMX8 
EM_KVARC = 214  # KM211 KVARC 
EM_CDP = 215  # Paneve CDP 
EM_COGE = 216  # Cognitive Smart Memory Processor 
EM_COOL = 217  # Bluechip CoolEngine 
EM_NORC = 218  # Nanoradio Optimized RISC 
EM_CSR_KALIMBA = 219  # CSR Kalimba 
EM_Z80 = 220  # Zilog Z80 
EM_VISIUM = 221  # Controls and Data Services VISIUMcore 
EM_FT32 = 222  # FTDI Chip FT32 
EM_MOXIE = 223  # Moxie processor 
EM_AMDGPU = 224  # AMD GPU 
		# reserved 225-242 
EM_RISCV = 243  # RISC-V 
EM_BPF = 247  # Linux BPF -- in-kernel virtual machine 
EM_CSKY = 252  # C-SKY 
EM_LOONGARCH = 258  # LoongArch 
EM_NUM = 259

# This is the info that is needed to parse the dynamic section of the file
DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_ENCODING = 32
OLD_DT_LOOS = 0x60000000
DT_LOOS = 0x6000000d
DT_HIOS = 0x6ffff000
DT_VALRNGLO = 0x6ffffd00
DT_VALRNGHI = 0x6ffffdff
DT_ADDRRNGLO = 0x6ffffe00
DT_ADDRRNGHI = 0x6ffffeff
DT_VERSYM = 0x6ffffff0
DT_RELACOUNT = 0x6ffffff9
DT_RELCOUNT = 0x6ffffffa
DT_FLAGS_1 = 0x6ffffffb
DT_VERDEF = 0x6ffffffc
DT_VERDEFNUM = 0x6ffffffd
DT_VERNEED = 0x6ffffffe
DT_VERNEEDNUM = 0x6fffffff
OLD_DT_HIOS = 0x6fffffff
DT_LOPROC = 0x70000000
DT_HIPROC = 0x7fffffff

# This info is needed when parsing the symbol table
STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLS = 6

STV_DEFAULT = 0  # Default symbol visibility rules
STV_INTERNAL = 1  # Processor specific hidden class
STV_HIDDEN = 2  # Sym unavailable in other modules
STV_PROTECTED = 3  # Not preemptible, not exported

def ELF_ST_BIND(x): return ((x) >> 4)
def ELF_ST_TYPE(x): return ((x) & 0xf)
def ELF_ST_VISIBILITY(x): return ((x) & 0x03)
def ELF32_ST_BIND(x): return ELF_ST_BIND(x)
def ELF32_ST_TYPE(x): return ELF_ST_TYPE(x)
def ELF64_ST_BIND(x): return ELF_ST_BIND(x)
def ELF64_ST_TYPE(x): return ELF_ST_TYPE(x)
def ELF32_ST_VISIBILITY(x): return ELF_ST_VISIBILITY(x)
def ELF64_ST_VISIBILITY(x): return ELF_ST_VISIBILITY(x)

def ELF64_ST_INFO(st_bind, st_type): return (((st_bind) << 4) + ((st_type) & 0xf))

class Elf32_Dyn(Structure):
    class d_un_t(Union):
        _fields_ = [('d_val', Elf32_Sword),
                    ('d_ptr', Elf32_Addr)]

    _fields_ = [('d_tag', Elf32_Sword),
                ('d_un', d_un_t)]


class Elf64_Dyn(Structure):
    class d_un_t(Union):
        _fields_ = [('d_val', Elf64_Xword),
                    ('d_ptr', Elf64_Addr)]

    _fields_ = [('d_tag', Elf64_Sxword),
                ('d_un', d_un_t)]

# The following are used with relocations
def ELF32_R_SYM(x): return ((x) >> 8)
def ELF32_R_TYPE(x): return ((x) & 0xff)

def ELF64_R_SYM(i): return ((i) >> 32)
def ELF64_R_TYPE(i): return ((i) & 0xffffffff)


class Elf32_Rel(Structure):
    _fields_ = [('r_offset', Elf32_Addr),
                ('r_info', Elf32_Word)]


class Elf64_Rel(Structure):
    _fields_ = [('r_offset', Elf64_Addr),  # Location at which to apply the action
                ('r_info', Elf64_Xword)]  # index and type of relocation


class Elf32_Rela(Structure):
    _fields_ = [('r_offset', Elf32_Addr),
                ('r_info', Elf32_Word),
                ('r_addend', Elf32_Sword)]


class Elf64_Rela(Structure):
    _fields_ = [('r_offset', Elf64_Addr),  # Location at which to apply the action
                ('r_info', Elf64_Xword),  # index and type of relocation
                # Constant addend used to compute value
                ('r_addend', Elf64_Sxword)]


class Elf32_Sym(Structure):
    _fields_ = [('st_name', Elf32_Word),
                ('st_value', Elf32_Addr),
                ('st_size', Elf32_Word),
                ('st_info', c_uint8),
                ('st_other', c_uint8),
                ('st_shndx', Elf32_Half)]


class Elf64_Sym(Structure):
    _fields_ = [('st_name', Elf64_Word),  # Symbol name, index in string tbl
                ('st_info', c_uint8),  # Type and binding attributes
                ('st_other', c_uint8),  # No defined meaning, 0
                ('st_shndx', Elf64_Half),  # Associated section index
                ('st_value', Elf64_Addr),  # Value of the symbol
                ('st_size', Elf64_Xword)]  # Associated symbol size


EI_NIDENT = 16


class Elf32_Ehdr(Structure):
    _fields_ = [('e_ident', c_uint8 * EI_NIDENT),
                ('e_type', Elf32_Half),
                ('e_machine', Elf32_Half),
                ('e_version', Elf32_Word),
                ('e_entry', Elf32_Addr),  # Entry point
                ('e_phoff', Elf32_Off),
                ('e_shoff', Elf32_Off),
                ('e_flags', Elf32_Word),
                ('e_ehsize', Elf32_Half),
                ('e_phentsize', Elf32_Half),
                ('e_phnum', Elf32_Half),
                ('e_shentsize', Elf32_Half),
                ('e_shnum', Elf32_Half),
                ('e_shstrndx', Elf32_Half)]


class Elf64_Ehdr(Structure):
    _fields_ = [('e_ident', c_uint8 * EI_NIDENT),  # ELF "magic number"
                ('e_type', Elf64_Half),
                ('e_machine', Elf64_Half),
                ('e_version', Elf64_Word),
                ('e_entry', Elf64_Addr),  # Entry point virtual address
                ('e_phoff', Elf64_Off),  # Program header table file offset
                ('e_shoff', Elf64_Off),  # Section header table file offset
                ('e_flags', Elf64_Word),
                ('e_ehsize', Elf64_Half),
                ('e_phentsize', Elf64_Half),
                ('e_phnum', Elf64_Half),
                ('e_shentsize', Elf64_Half),
                ('e_shnum', Elf64_Half),
                ('e_shstrndx', Elf64_Half)]


# These constants define the permissions on sections in the program
# header, p_flags.
PF_R = 0x4
PF_W = 0x2
PF_X = 0x1


class Elf32_Phdr(Structure):
    _fields_ = [('p_type', Elf32_Word),
                ('p_offset', Elf32_Off),
                ('p_vaddr', Elf32_Addr),
                ('p_paddr', Elf32_Addr),
                ('p_filesz', Elf32_Word),
                ('p_memsz', Elf32_Word),
                ('p_flags', Elf32_Word),
                ('p_align', Elf32_Word)]


class Elf64_Phdr(Structure):
    _fields_ = [('p_type', Elf64_Word),
                ('p_flags', Elf64_Word),
                ('p_offset', Elf64_Off),  # Segment file offset
                ('p_vaddr', Elf64_Addr),  # Segment virtual address
                ('p_paddr', Elf64_Addr),  # Segment physical address
                ('p_filesz', Elf64_Xword),  # Segment size in file
                ('p_memsz', Elf64_Xword),  # Segment size in memory
                ('p_align', Elf64_Xword)]  # Segment alignment, file & memory


# sh_type
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7
SHT_NOBITS = 8
SHT_REL = 9
SHT_SHLIB = 10
SHT_DYNSYM = 11
SHT_NUM = 12
SHT_LOPROC = 0x70000000
SHT_HIPROC = 0x7fffffff
SHT_LOUSER = 0x80000000
SHT_HIUSER = 0xffffffff

# sh_flags
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_RELA_LIVEPATCH = 0x00100000
SHF_RO_AFTER_INIT = 0x00200000
SHF_MASKPROC = 0xf0000000

# special section indexes
SHN_UNDEF = 0
SHN_LORESERVE = 0xff00
SHN_LOPROC = 0xff00
SHN_HIPROC = 0xff1f
SHN_LIVEPATCH = 0xff20
SHN_ABS = 0xfff1
SHN_COMMON = 0xfff2
SHN_HIRESERVE = 0xffff


class Elf32_Shdr(Structure):
    _fields_ = [('sh_name', Elf32_Word),
                ('sh_type', Elf32_Word),
                ('sh_flags', Elf32_Word),
                ('sh_addr', Elf32_Addr),
                ('sh_offset', Elf32_Off),
                ('sh_size', Elf32_Word),
                ('sh_link', Elf32_Word),
                ('sh_info', Elf32_Word),
                ('sh_addralign', Elf32_Word),
                ('sh_entsize', Elf32_Word)]


class Elf64_Shdr(Structure):
    _fields_ = [('sh_name', Elf64_Word),  # Section name, index in string tbl
                ('sh_type', Elf64_Word),  # Type of section
                ('sh_flags', Elf64_Xword),  # Miscellaneous section attributes
                ('sh_addr', Elf64_Addr),  # Section virtual addr at execution
                ('sh_offset', Elf64_Off),  # Section file offset
                ('sh_size', Elf64_Xword),  # Size of section in bytes
                ('sh_link', Elf64_Word),  # Index of another section
                ('sh_info', Elf64_Word),  # Additional section information
                ('sh_addralign', Elf64_Xword),  # Section alignment
                ('sh_entsize', Elf64_Xword)]  # Entry size if section holds table


EI_MAG0 = 0  # e_ident[] indexes
EI_MAG1 = 1
EI_MAG2 = 2
EI_MAG3 = 3
EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_OSABI = 7
EI_ABIVERSION = 8
EI_PAD = 9

ELFMAG0 = 0x7f  # EI_MAG
ELFMAG1 = ord('E')
ELFMAG2 = ord('L')
ELFMAG3 = ord('F')
ELFMAG = b"\177ELF"
SELFMAG = 4

ELFCLASSNONE = 0  # EI_CLASS
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFCLASSNUM = 3

ELFDATANONE = 0  # e_ident[EI_DATA]
ELFDATA2LSB = 1
ELFDATA2MSB = 2

EV_NONE = 0  # e_version, EI_VERSION
EV_CURRENT = 1
EV_NUM = 2

ELFOSABI_NONE = 0  # UNIX System V ABI
ELFOSABI_SYSV = 0  # Alias. 
ELFOSABI_HPUX = 1  # HP-UX
ELFOSABI_NETBSD = 2  # NetBSD. 
ELFOSABI_GNU = 3  # Object uses GNU ELF extensions. 
ELFOSABI_LINUX = ELFOSABI_GNU  # Compatibility alias. 
ELFOSABI_SOLARIS = 6  # Sun Solaris. 
ELFOSABI_AIX = 7  # IBM AIX. 
ELFOSABI_IRIX = 8  # SGI Irix. 
ELFOSABI_FREEBSD = 9  # FreeBSD. 
ELFOSABI_TRU64 = 10  # Compaq TRU64 UNIX. 
ELFOSABI_MODESTO = 11  # Novell Modesto. 
ELFOSABI_OPENBSD = 12  # OpenBSD. 
ELFOSABI_ARM_AEABI = 64  # ARM EABI
ELFOSABI_ARM = 97  # ARM
ELFOSABI_STANDALONE = 255  # Standalone (embedded) application

#
# Notes used in ET_CORE. Architectures export some of the arch register sets
# using the corresponding note types via the PTRACE_GETREGSET and
# PTRACE_SETREGSET requests.
# The note name for all these is "LINUX".
#
NT_PRSTATUS = 1
NT_PRFPREG = 2
NT_PRPSINFO = 3
NT_TASKSTRUCT = 4
NT_AUXV = 6
#
# Note to userspace developers: size of NT_SIGINFO note may increase
# in the future to accomodate more fields, don't assume it is fixed!
#
NT_SIGINFO = 0x53494749
NT_FILE = 0x46494c45
NT_PRXFPREG = 0x46e62b7f  # copied from gdb5.1/include/elf/common.h
NT_PPC_VMX = 0x100  # PowerPC Altivec/VMX registers
NT_PPC_SPE = 0x101  # PowerPC SPE/EVR registers
NT_PPC_VSX = 0x102  # PowerPC VSX registers
NT_PPC_TAR = 0x103  # Target Address Register
NT_PPC_PPR = 0x104  # Program Priority Register
NT_PPC_DSCR = 0x105  # Data Stream Control Register
NT_PPC_EBB = 0x106  # Event Based Branch Registers
NT_PPC_PMU = 0x107  # Performance Monitor Registers
NT_PPC_TM_CGPR = 0x108  # TM checkpointed GPR Registers
NT_PPC_TM_CFPR = 0x109  # TM checkpointed FPR Registers
NT_PPC_TM_CVMX = 0x10a  # TM checkpointed VMX Registers
NT_PPC_TM_CVSX = 0x10b  # TM checkpointed VSX Registers
NT_PPC_TM_SPR = 0x10c  # TM Special Purpose Registers
NT_PPC_TM_CTAR = 0x10d  # TM checkpointed Target Address Register
NT_PPC_TM_CPPR = 0x10e  # TM checkpointed Program Priority Register
NT_PPC_TM_CDSCR = 0x10f  # TM checkpointed Data Stream Control Register
NT_PPC_PKEY = 0x110  # Memory Protection Keys registers
NT_386_TLS = 0x200  # i386 TLS slots(struct user_desc)
NT_386_IOPERM = 0x201  # x86 io permission bitmap(1=deny)
NT_X86_XSTATE = 0x202  # x86 extended state using xsave
NT_S390_HIGH_GPRS = 0x300  # s390 upper register halves
NT_S390_TIMER = 0x301  # s390 timer register
NT_S390_TODCMP = 0x302  # s390 TOD clock comparator register
NT_S390_TODPREG = 0x303  # s390 TOD programmable register
NT_S390_CTRS = 0x304  # s390 control registers
NT_S390_PREFIX = 0x305  # s390 prefix register
NT_S390_LAST_BREAK = 0x306  # s390 breaking event address
NT_S390_SYSTEM_CALL = 0x307  # s390 system call restart data
NT_S390_TDB = 0x308  # s390 transaction diagnostic block
NT_S390_VXRS_LOW = 0x309  # s390 vector registers 0-15 upper half
NT_S390_VXRS_HIGH = 0x30a  # s390 vector registers 16-31
NT_S390_GS_CB = 0x30b  # s390 guarded storage registers
NT_S390_GS_BC = 0x30c  # s390 guarded storage broadcast control block
NT_S390_RI_CB = 0x30d  # s390 runtime instrumentation
NT_S390_PV_CPU_DATA = 0x30e  # s390 protvirt cpu dump data
NT_ARM_VFP = 0x400  # ARM VFP/NEON registers
NT_ARM_TLS = 0x401  # ARM TLS register
NT_ARM_HW_BREAK = 0x402  # ARM hardware breakpoint registers
NT_ARM_HW_WATCH = 0x403  # ARM hardware watchpoint registers
NT_ARM_SYSTEM_CALL = 0x404  # ARM system call number
NT_ARM_SVE = 0x405  # ARM Scalable Vector Extension registers
NT_ARM_PAC_MASK = 0x406  # ARM pointer authentication code masks
NT_ARM_PACA_KEYS = 0x407  # ARM pointer authentication address keys
NT_ARM_PACG_KEYS = 0x408  # ARM pointer authentication generic key
NT_ARM_TAGGED_ADDR_CTRL = 0x409  # arm64 tagged address control(prctl())
NT_ARM_PAC_ENABLED_KEYS = 0x40a  # arm64 ptr auth enabled keys(prctl())
NT_ARM_SSVE = 0x40b  # ARM Streaming SVE registers
NT_ARM_ZA = 0x40c  # ARM SME ZA registers
NT_ARC_V2 = 0x600  # ARCv2 accumulator/extra registers
NT_VMCOREDD = 0x700  # Vmcore Device Dump Note
NT_MIPS_DSP = 0x800  # MIPS DSP ASE registers
NT_MIPS_FP_MODE = 0x801  # MIPS floating-point mode
NT_MIPS_MSA = 0x802  # MIPS SIMD registers
NT_LOONGARCH_CPUCFG = 0xa00  # LoongArch CPU config registers
NT_LOONGARCH_CSR = 0xa01  # LoongArch control and status registers
NT_LOONGARCH_LSX = 0xa02  # LoongArch Loongson SIMD Extension registers
NT_LOONGARCH_LASX = 0xa03  # LoongArch Loongson Advanced SIMD Extension registers
NT_LOONGARCH_LBT = 0xa04  # LoongArch Loongson Binary Translation registers

# Note types with note name "GNU"
NT_GNU_PROPERTY_TYPE_0 = 5

# Note header in a PT_NOTE section
class Elf32_Nhdr(Structure):
    _fields_ = [('n_namesz', Elf32_Word),  # Name size
                ('n_descsz', Elf32_Word),  # Content size
                ('n_type', Elf32_Word)]  # Content type


class Elf64_Nhdr(Structure):
    _fields_ = [('n_namesz', Elf64_Word),  # Name size
                ('n_descsz', Elf64_Word),  # Content size
                ('n_type', Elf64_Word)]  # Content type


# .note.gnu.property types for EM_AARCH64:
GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000

# Bits for GNU_PROPERTY_AARCH64_FEATURE_1_BTI
GNU_PROPERTY_AARCH64_FEATURE_1_BTI = (1 << 0)
