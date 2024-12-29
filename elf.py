from ctypes import *

# Kind: StructDecl
class __fsid_t(Structure):
	_fields_ = [
		("__val", c_int * 2)]

EI_NIDENT = (16)

# Kind: StructDecl
class Elf32_Ehdr(Structure):
	_fields_ = [
		("e_ident", c_ubyte * 16),
		("e_type", c_ushort),
		("e_machine", c_ushort),
		("e_version", c_uint),
		("e_entry", c_uint),
		("e_phoff", c_uint),
		("e_shoff", c_uint),
		("e_flags", c_uint),
		("e_ehsize", c_ushort),
		("e_phentsize", c_ushort),
		("e_phnum", c_ushort),
		("e_shentsize", c_ushort),
		("e_shnum", c_ushort),
		("e_shstrndx", c_ushort)]


# Kind: StructDecl
class Elf64_Ehdr(Structure):
	_fields_ = [
		("e_ident", c_ubyte * 16),
		("e_type", c_ushort),
		("e_machine", c_ushort),
		("e_version", c_uint),
		("e_entry", c_ulong),
		("e_phoff", c_ulong),
		("e_shoff", c_ulong),
		("e_flags", c_uint),
		("e_ehsize", c_ushort),
		("e_phentsize", c_ushort),
		("e_phnum", c_ushort),
		("e_shentsize", c_ushort),
		("e_shnum", c_ushort),
		("e_shstrndx", c_ushort)]

# /* Fields in the e_ident array.  The EI_* macros are indices into the
#    array.  The macros under each EI_* macro are the values the byte
#    may have.  */

EI_MAG0 = 0 # /* File identification byte 0 index */
ELFMAG0 = 0x7f # /* Magic number byte 0 */
EI_MAG1 = 1 # /* File identification byte 1 index */
ELFMAG1 = 'E' # /* Magic number byte 1 */
EI_MAG2 = 2 # /* File identification byte 2 index */
ELFMAG2 = 'L' # /* Magic number byte 2 */
EI_MAG3 = 3 # /* File identification byte 3 index */
ELFMAG3 = 'F' # /* Magic number byte 3 */

# /* Conglomeration of the identification bytes, for easy testing as a word.  */

ELFMAG = "\177ELF"
SELFMAG = 4
EI_CLASS = 4 # /* File class byte index */
ELFCLASSNONE = 0 # /* Invalid class */
ELFCLASS32 = 1 # /* 32-bit objects */
ELFCLASS64 = 2 # /* 64-bit objects */
ELFCLASSNUM = 3
EI_DATA = 5 # /* Data encoding byte index */
ELFDATANONE = 0 # /* Invalid data encoding */
ELFDATA2LSB = 1 # /* 2's complement, little endian */
ELFDATA2MSB = 2 # /* 2's complement, big endian */
ELFDATANUM = 3
EI_VERSION = 6 # /* File version byte index */
EI_OSABI = 7 # /* OS ABI identification */
ELFOSABI_NONE = 0 # /* UNIX System V ABI */
ELFOSABI_SYSV = 0 # /* Alias.  */
ELFOSABI_HPUX = 1 # /* HP-UX */
ELFOSABI_NETBSD = 2 # /* NetBSD.  */
ELFOSABI_GNU = 3 # /* Object uses GNU ELF extensions.  */
ELFOSABI_LINUX = ELFOSABI_GNU # /* Compatibility alias.  */
ELFOSABI_SOLARIS = 6 # /* Sun Solaris.  */
ELFOSABI_AIX = 7 # /* IBM AIX.  */
ELFOSABI_IRIX = 8 # /* SGI Irix.  */
ELFOSABI_FREEBSD = 9 # /* FreeBSD.  */
ELFOSABI_TRU64 = 10 # /* Compaq TRU64 UNIX.  */
ELFOSABI_MODESTO = 11 # /* Novell Modesto.  */
ELFOSABI_OPENBSD = 12 # /* OpenBSD.  */
ELFOSABI_ARM_AEABI = 64 # /* ARM EABI */
ELFOSABI_ARM = 97 # /* ARM */
ELFOSABI_STANDALONE = 255 # /* Standalone (embedded) application */
EI_ABIVERSION = 8 # /* ABI version */
EI_PAD = 9 # /* Byte index of padding bytes */

# /* Legal values for e_type (object file type).  */

ET_NONE = 0 # /* No file type */
ET_REL = 1 # /* Relocatable file */
ET_EXEC = 2 # /* Executable file */
ET_DYN = 3 # /* Shared object file */
ET_CORE = 4 # /* Core file */
ET_NUM = 5 # /* Number of defined types */
ET_LOOS = 0xfe00 # /* OS-specific range start */
ET_HIOS = 0xfeff # /* OS-specific range end */
ET_LOPROC = 0xff00 # /* Processor-specific range start */
ET_HIPROC = 0xffff # /* Processor-specific range end */

# /* Legal values for e_machine (architecture).  */ 
EM_NONE = 0 # /* No machine */
EM_M32 = 1 # /* AT&T WE 32100 */
EM_SPARC = 2 # /* SUN SPARC */
EM_386 = 3 # /* Intel 80386 */
EM_68K = 4 # /* Motorola m68k family */
EM_88K = 5 # /* Motorola m88k family */
EM_IAMCU = 6 # /* Intel MCU */
EM_860 = 7 # /* Intel 80860 */
EM_MIPS = 8 # /* MIPS R3000 big-endian */
EM_S370 = 9 # /* IBM System/370 */
EM_MIPS_RS3_LE = 10 # /* MIPS R3000 little-endian */
# /* reserved 11-14 */ 
EM_PARISC = 15 # /* HPPA */
# /* reserved 16 */ 
EM_VPP500 = 17 # /* Fujitsu VPP500 */
EM_SPARC32PLUS = 18 # /* Sun's "v8plus" */
EM_960 = 19 # /* Intel 80960 */
EM_PPC = 20 # /* PowerPC */
EM_PPC64 = 21 # /* PowerPC 64-bit */
EM_S390 = 22 # /* IBM S390 */
EM_SPU = 23 # /* IBM SPU/SPC */
# /* reserved 24-35 */ 
EM_V800 = 36 # /* NEC V800 series */
EM_FR20 = 37 # /* Fujitsu FR20 */
EM_RH32 = 38 # /* TRW RH-32 */
EM_RCE = 39 # /* Motorola RCE */
EM_ARM = 40 # /* ARM */
EM_FAKE_ALPHA = 41 # /* Digital Alpha */
EM_SH = 42 # /* Hitachi SH */
EM_SPARCV9 = 43 # /* SPARC v9 64-bit */
EM_TRICORE = 44 # /* Siemens Tricore */
EM_ARC = 45 # /* Argonaut RISC Core */
EM_H8_300 = 46 # /* Hitachi H8/300 */
EM_H8_300H = 47 # /* Hitachi H8/300H */
EM_H8S = 48 # /* Hitachi H8S */
EM_H8_500 = 49 # /* Hitachi H8/500 */
EM_IA_64 = 50 # /* Intel Merced */
EM_MIPS_X = 51 # /* Stanford MIPS-X */
EM_COLDFIRE = 52 # /* Motorola Coldfire */
EM_68HC12 = 53 # /* Motorola M68HC12 */
EM_MMA = 54 # /* Fujitsu MMA Multimedia Accelerator */
EM_PCP = 55 # /* Siemens PCP */
EM_NCPU = 56 # /* Sony nCPU embeeded RISC */
EM_NDR1 = 57 # /* Denso NDR1 microprocessor */
EM_STARCORE = 58 # /* Motorola Start*Core processor */
EM_ME16 = 59 # /* Toyota ME16 processor */
EM_ST100 = 60 # /* STMicroelectronic ST100 processor */
EM_TINYJ = 61 # /* Advanced Logic Corp. Tinyj emb.fam */
EM_X86_64 = 62 # /* AMD x86-64 architecture */
EM_PDSP = 63 # /* Sony DSP Processor */
EM_PDP10 = 64 # /* Digital PDP-10 */
EM_PDP11 = 65 # /* Digital PDP-11 */
EM_FX66 = 66 # /* Siemens FX66 microcontroller */
EM_ST9PLUS = 67 # /* STMicroelectronics ST9+ 8/16 mc */
EM_ST7 = 68 # /* STmicroelectronics ST7 8 bit mc */
EM_68HC16 = 69 # /* Motorola MC68HC16 microcontroller */
EM_68HC11 = 70 # /* Motorola MC68HC11 microcontroller */
EM_68HC08 = 71 # /* Motorola MC68HC08 microcontroller */
EM_68HC05 = 72 # /* Motorola MC68HC05 microcontroller */
EM_SVX = 73 # /* Silicon Graphics SVx */
EM_ST19 = 74 # /* STMicroelectronics ST19 8 bit mc */
EM_VAX = 75 # /* Digital VAX */
EM_CRIS = 76 # /* Axis Communications 32-bit emb.proc */
EM_JAVELIN = 77 # /* Infineon Technologies 32-bit emb.proc */
EM_FIREPATH = 78 # /* Element 14 64-bit DSP Processor */
EM_ZSP = 79 # /* LSI Logic 16-bit DSP Processor */
EM_MMIX = 80 # /* Donald Knuth's educational 64-bit proc */
EM_HUANY = 81 # /* Harvard University machine-independent object files */
EM_PRISM = 82 # /* SiTera Prism */
EM_AVR = 83 # /* Atmel AVR 8-bit microcontroller */
EM_FR30 = 84 # /* Fujitsu FR30 */
EM_D10V = 85 # /* Mitsubishi D10V */
EM_D30V = 86 # /* Mitsubishi D30V */
EM_V850 = 87 # /* NEC v850 */
EM_M32R = 88 # /* Mitsubishi M32R */
EM_MN10300 = 89 # /* Matsushita MN10300 */
EM_MN10200 = 90 # /* Matsushita MN10200 */
EM_PJ = 91 # /* picoJava */
EM_OPENRISC = 92 # /* OpenRISC 32-bit embedded processor */
EM_ARC_COMPACT = 93 # /* ARC International ARCompact */
EM_XTENSA = 94 # /* Tensilica Xtensa Architecture */
EM_VIDEOCORE = 95 # /* Alphamosaic VideoCore */
EM_TMM_GPP = 96 # /* Thompson Multimedia General Purpose Proc */
EM_NS32K = 97 # /* National Semi. 32000 */
EM_TPC = 98 # /* Tenor Network TPC */
EM_SNP1K = 99 # /* Trebia SNP 1000 */
EM_ST200 = 100 # /* STMicroelectronics ST200 */
EM_IP2K = 101 # /* Ubicom IP2xxx */
EM_MAX = 102 # /* MAX processor */
EM_CR = 103 # /* National Semi. CompactRISC */
EM_F2MC16 = 104 # /* Fujitsu F2MC16 */
EM_MSP430 = 105 # /* Texas Instruments msp430 */
EM_BLACKFIN = 106 # /* Analog Devices Blackfin DSP */
EM_SE_C33 = 107 # /* Seiko Epson S1C33 family */
EM_SEP = 108 # /* Sharp embedded microprocessor */
EM_ARCA = 109 # /* Arca RISC */
EM_UNICORE = 110 # /* PKU-Unity & MPRC Peking Uni. mc series */
EM_EXCESS = 111 # /* eXcess configurable cpu */
EM_DXP = 112 # /* Icera Semi. Deep Execution Processor */
EM_ALTERA_NIOS2 = 113 # /* Altera Nios II */
EM_CRX = 114 # /* National Semi. CompactRISC CRX */
EM_XGATE = 115 # /* Motorola XGATE */
EM_C166 = 116 # /* Infineon C16x/XC16x */
EM_M16C = 117 # /* Renesas M16C */
EM_DSPIC30F = 118 # /* Microchip Technology dsPIC30F */
EM_CE = 119 # /* Freescale Communication Engine RISC */
EM_M32C = 120 # /* Renesas M32C */
# /* reserved 121-130 */ 
EM_TSK3000 = 131 # /* Altium TSK3000 */
EM_RS08 = 132 # /* Freescale RS08 */
EM_SHARC = 133 # /* Analog Devices SHARC family */
EM_ECOG2 = 134 # /* Cyan Technology eCOG2 */
EM_SCORE7 = 135 # /* Sunplus S+core7 RISC */
EM_DSP24 = 136 # /* New Japan Radio (NJR) 24-bit DSP */
EM_VIDEOCORE3 = 137 # /* Broadcom VideoCore III */
EM_LATTICEMICO32 = 138 # /* RISC for Lattice FPGA */
EM_SE_C17 = 139 # /* Seiko Epson C17 */
EM_TI_C6000 = 140 # /* Texas Instruments TMS320C6000 DSP */
EM_TI_C2000 = 141 # /* Texas Instruments TMS320C2000 DSP */
EM_TI_C5500 = 142 # /* Texas Instruments TMS320C55x DSP */
EM_TI_ARP32 = 143 # /* Texas Instruments App. Specific RISC */
EM_TI_PRU = 144 # /* Texas Instruments Prog. Realtime Unit */
# /* reserved 145-159 */ 
EM_MMDSP_PLUS = 160 # /* STMicroelectronics 64bit VLIW DSP */
EM_CYPRESS_M8C = 161 # /* Cypress M8C */
EM_R32C = 162 # /* Renesas R32C */
EM_TRIMEDIA = 163 # /* NXP Semi. TriMedia */
EM_QDSP6 = 164 # /* QUALCOMM DSP6 */
EM_8051 = 165 # /* Intel 8051 and variants */
EM_STXP7X = 166 # /* STMicroelectronics STxP7x */
EM_NDS32 = 167 # /* Andes Tech. compact code emb. RISC */
EM_ECOG1X = 168 # /* Cyan Technology eCOG1X */
EM_MAXQ30 = 169 # /* Dallas Semi. MAXQ30 mc */
EM_XIMO16 = 170 # /* New Japan Radio (NJR) 16-bit DSP */
EM_MANIK = 171 # /* M2000 Reconfigurable RISC */
EM_CRAYNV2 = 172 # /* Cray NV2 vector architecture */
EM_RX = 173 # /* Renesas RX */
EM_METAG = 174 # /* Imagination Tech. META */
EM_MCST_ELBRUS = 175 # /* MCST Elbrus */
EM_ECOG16 = 176 # /* Cyan Technology eCOG16 */
EM_CR16 = 177 # /* National Semi. CompactRISC CR16 */
EM_ETPU = 178 # /* Freescale Extended Time Processing Unit */
EM_SLE9X = 179 # /* Infineon Tech. SLE9X */
EM_L10M = 180 # /* Intel L10M */
EM_K10M = 181 # /* Intel K10M */
# /* reserved 182 */ 
EM_AARCH64 = 183 # /* ARM AARCH64 */
# /* reserved 184 */ 
EM_AVR32 = 185 # /* Amtel 32-bit microprocessor */
EM_STM8 = 186 # /* STMicroelectronics STM8 */
EM_TILE64 = 187 # /* Tilera TILE64 */
EM_TILEPRO = 188 # /* Tilera TILEPro */
EM_MICROBLAZE = 189 # /* Xilinx MicroBlaze */
EM_CUDA = 190 # /* NVIDIA CUDA */
EM_TILEGX = 191 # /* Tilera TILE-Gx */
EM_CLOUDSHIELD = 192 # /* CloudShield */
EM_COREA_1ST = 193 # /* KIPO-KAIST Core-A 1st gen. */
EM_COREA_2ND = 194 # /* KIPO-KAIST Core-A 2nd gen. */
EM_ARCV2 = 195 # /* Synopsys ARCv2 ISA.  */
EM_OPEN8 = 196 # /* Open8 RISC */
EM_RL78 = 197 # /* Renesas RL78 */
EM_VIDEOCORE5 = 198 # /* Broadcom VideoCore V */
EM_78KOR = 199 # /* Renesas 78KOR */
EM_56800EX = 200 # /* Freescale 56800EX DSC */
EM_BA1 = 201 # /* Beyond BA1 */
EM_BA2 = 202 # /* Beyond BA2 */
EM_XCORE = 203 # /* XMOS xCORE */
EM_MCHP_PIC = 204 # /* Microchip 8-bit PIC(r) */
EM_INTELGT = 205 # /* Intel Graphics Technology */
# /* reserved 206-209 */ 
EM_KM32 = 210 # /* KM211 KM32 */
EM_KMX32 = 211 # /* KM211 KMX32 */
EM_EMX16 = 212 # /* KM211 KMX16 */
EM_EMX8 = 213 # /* KM211 KMX8 */
EM_KVARC = 214 # /* KM211 KVARC */
EM_CDP = 215 # /* Paneve CDP */
EM_COGE = 216 # /* Cognitive Smart Memory Processor */
EM_COOL = 217 # /* Bluechip CoolEngine */
EM_NORC = 218 # /* Nanoradio Optimized RISC */
EM_CSR_KALIMBA = 219 # /* CSR Kalimba */
EM_Z80 = 220 # /* Zilog Z80 */
EM_VISIUM = 221 # /* Controls and Data Services VISIUMcore */
EM_FT32 = 222 # /* FTDI Chip FT32 */
EM_MOXIE = 223 # /* Moxie processor */
EM_AMDGPU = 224 # /* AMD GPU */
# /* reserved 225-242 */ 
EM_RISCV = 243 # /* RISC-V */
EM_BPF = 247 # /* Linux BPF -- in-kernel virtual machine */
EM_CSKY = 252 # /* C-SKY */
EM_LOONGARCH = 258 # /* LoongArch */
EM_NUM = 259

# /* Old spellings/synonyms.  */

EM_ARC_A5 = EM_ARC_COMPACT # /* If it is necessary to assign new unofficial EM_* values, please
#   pick large random numbers ("0x8523", 0xa7f2, etc.) to minimize the
#   chances of collision with official or non-GNU unofficial values.  */
EM_ALPHA = 0x9026 # /* Legal values for e_version (version).  */
EV_NONE = 0 # /* Invalid ELF version */
EV_CURRENT = 1 # /* Current version */
EV_NUM = 2 # /* Section header.  */

# Kind: StructDecl
class Elf32_Shdr(Structure):
	_fields_ = [
		("sh_name", c_uint),
		("sh_type", c_uint),
		("sh_flags", c_uint),
		("sh_addr", c_uint),
		("sh_offset", c_uint),
		("sh_size", c_uint),
		("sh_link", c_uint),
		("sh_info", c_uint),
		("sh_addralign", c_uint),
		("sh_entsize", c_uint)]


# Kind: StructDecl
class Elf64_Shdr(Structure):
	_fields_ = [
		("sh_name", c_uint),
		("sh_type", c_uint),
		("sh_flags", c_ulong),
		("sh_addr", c_ulong),
		("sh_offset", c_ulong),
		("sh_size", c_ulong),
		("sh_link", c_uint),
		("sh_info", c_uint),
		("sh_addralign", c_ulong),
		("sh_entsize", c_ulong)]

# /* Special section indices.  */

SHN_UNDEF = 0 # /* Undefined section */
SHN_LORESERVE = 0xff00 # /* Start of reserved indices */
SHN_LOPROC = 0xff00 # /* Start of processor-specific */
SHN_BEFORE = 0xff00 # /* Order section before all others
                    #   (Solaris).  */
SHN_AFTER = 0xff01 # /* Order section after all others
                   #    (Solaris).  */
SHN_HIPROC = 0xff1f # /* End of processor-specific */
SHN_LOOS = 0xff20 # /* Start of OS-specific */
SHN_HIOS = 0xff3f # /* End of OS-specific */
SHN_ABS = 0xfff1 # /* Associated symbol is absolute */
SHN_COMMON = 0xfff2 # /* Associated symbol is common */
SHN_XINDEX = 0xffff # /* Index is in extra table.  */
SHN_HIRESERVE = 0xffff # /* End of reserved indices */

# /* Legal values for sh_type (section type).  */ 

SHT_NULL = 0 # /* Section header table entry unused */
SHT_PROGBITS = 1 # /* Program data */
SHT_SYMTAB = 2 # /* Symbol table */
SHT_STRTAB = 3 # /* String table */
SHT_RELA = 4 # /* Relocation entries with addends */
SHT_HASH = 5 # /* Symbol hash table */
SHT_DYNAMIC = 6 # /* Dynamic linking information */
SHT_NOTE = 7 # /* Notes */
SHT_NOBITS = 8 # /* Program space with no data (bss) */
SHT_REL = 9 # /* Relocation entries, no addends */
SHT_SHLIB = 10 # /* Reserved */
SHT_DYNSYM = 11 # /* Dynamic linker symbol table */
SHT_INIT_ARRAY = 14 # /* Array of constructors */
SHT_FINI_ARRAY = 15 # /* Array of destructors */
SHT_PREINIT_ARRAY = 16 # /* Array of pre-constructors */
SHT_GROUP = 17 # /* Section group */
SHT_SYMTAB_SHNDX = 18 # /* Extended section indices */
SHT_RELR = 19 # /* RELR relative relocations */
SHT_NUM = 20 # /* Number of defined types.  */
SHT_LOOS = 0x60000000 # /* Start OS-specific.  */
SHT_GNU_ATTRIBUTES = 0x6ffffff5 # /* Object attributes.  */
SHT_GNU_HASH = 0x6ffffff6 # /* GNU-style hash table.  */
SHT_GNU_LIBLIST = 0x6ffffff7 # /* Prelink library list */
SHT_CHECKSUM = 0x6ffffff8 # /* Checksum for DSO content.  */
SHT_LOSUNW = 0x6ffffffa # /* Sun-specific low bound.  */
SHT_SUNW_move = 0x6ffffffa
SHT_SUNW_COMDAT = 0x6ffffffb
SHT_SUNW_syminfo = 0x6ffffffc
SHT_GNU_verdef = 0x6ffffffd # /* Version definition section.  */
SHT_GNU_verneed = 0x6ffffffe # /* Version needs section.  */
SHT_GNU_versym = 0x6fffffff # /* Version symbol table.  */
SHT_HISUNW = 0x6fffffff # /* Sun-specific high bound.  */
SHT_HIOS = 0x6fffffff # /* End OS-specific type */
SHT_LOPROC = 0x70000000 # /* Start of processor-specific */
SHT_HIPROC = 0x7fffffff # /* End of processor-specific */
SHT_LOUSER = 0x80000000 # /* Start of application-specific */
SHT_HIUSER = 0x8fffffff # /* End of application-specific */

# /* Legal values for sh_flags (section flags).  */

SHF_WRITE =        (1 << 0)   # /* Writable */
SHF_ALLOC =        (1 << 1)   # /* Occupies memory during execution */
SHF_EXECINSTR =        (1 << 2)   # /* Executable */
SHF_MERGE =        (1 << 4)   # /* Might be merged */
SHF_STRINGS =      (1 << 5)   # /* Contains nul-terminated strings */
SHF_INFO_LINK =        (1 << 6)   # /* `sh_info' contains SHT index */
SHF_LINK_ORDER =       (1 << 7)   # /* Preserve order after combining */
SHF_OS_NONCONFORMING = (1 << 8)   # /* Non-standard OS specific handling
                       # required */
SHF_GROUP =        (1 << 9)   # /* Section is member of a group.  */
SHF_TLS =          (1 << 10)  # /* Section hold thread-local data.  */
SHF_COMPRESSED =       (1 << 11)  # /* Section with compressed data. */
SHF_MASKOS =       0x0ff00000 # /* OS-specific.  */
SHF_MASKPROC =         0xf0000000 # /* Processor-specific */
SHF_GNU_RETAIN =       (1 << 21)  # /* Not to be GCed by linker.  */
SHF_ORDERED =      (1 << 30)  # /* Special ordering requirement
                       # (Solaris).  */
SHF_EXCLUDE =     (1 << 31) # /* Section is excluded unless
                       # referenced or allocated (Solaris).*/

# /* Section compression header.  Used when SHF_COMPRESSED is set.  */ 

# Kind: StructDecl
class Elf32_Chdr(Structure):
	_fields_ = [
		("ch_type", c_uint), # /* Compression format.  */
		("ch_size", c_uint), # /* Uncompressed data size.  */ 
		("ch_addralign", c_uint)] # /* Uncompressed data alignment.  */ 


# Kind: StructDecl
class Elf64_Chdr(Structure):
	_fields_ = [
		("ch_type", c_uint), # /* Compression format.  */ 
		("ch_reserved", c_uint),
		("ch_size", c_ulong), # /* Uncompressed data size.  */ 
		("ch_addralign", c_ulong)] # /* Uncompressed data alignment.  */ 

# /* Legal values for ch_type (compression algorithm).  */ 
ELFCOMPRESS_ZLIB = 1 # /* ZLIB/DEFLATE algorithm.  */
ELFCOMPRESS_LOOS = 0x60000000 # /* Start of OS-specific.  */
ELFCOMPRESS_HIOS = 0x6fffffff # /* End of OS-specific.  */
ELFCOMPRESS_LOPROC = 0x70000000 # /* Start of processor-specific.  */
ELFCOMPRESS_HIPROC = 0x7fffffff # /* End of processor-specific.  */

# /* Section group handling.  */ 
GRP_COMDAT = 0x1 # /* Mark group as COMDAT.  */

# /* Symbol table entry.  */ 

# Kind: StructDecl
class Elf32_Sym(Structure):
	_fields_ = [
		("st_name", c_uint), # /* Symbol name (string tbl index) */ 
		("st_value", c_uint), # /* Symbol value */ 
		("st_size", c_uint), # /* Symbol size */ 
		("st_info", c_ubyte), # /* Symbol type and binding */ 
		("st_other", c_ubyte), # /* Symbol visibility */ 
		("st_shndx", c_ushort)] # /* Section index */ 


# Kind: StructDecl
class Elf64_Sym(Structure):
	_fields_ = [
		("st_name", c_uint), # /* Symbol name (string tbl index) */ 
		("st_info", c_ubyte), # /* Symbol type and binding */ 
		("st_other", c_ubyte), # /* Symbol visibility */ 
		("st_shndx", c_ushort), # /* Section index */ 
		("st_value", c_ulong), # /* Symbol value */ 
		("st_size", c_ulong)] # /* Symbol size */ 

# /* The syminfo section if available contains additional information about
   # every dynamic symbol.  */ 

# Kind: StructDecl
class Elf32_Syminfo(Structure):
	_fields_ = [
		("si_boundto", c_ushort), # /* Direct bindings, symbol bound to */ 
		("si_flags", c_ushort)] # /* Per symbol flags */ 

# Kind: StructDecl
class Elf64_Syminfo(Structure):
	_fields_ = [
		("si_boundto", c_ushort), # /* Direct bindings, symbol bound to */ 
		("si_flags", c_ushort)] # /* Per symbol flags */ 

# /* Possible values for si_boundto.  */ 
SYMINFO_BT_SELF = 0xffff # /* Symbol bound to self */
SYMINFO_BT_PARENT = 0xfffe # /* Symbol bound to parent */
SYMINFO_BT_LOWRESERVE = 0xff00 # /* Beginning of reserved entries */

# /* Possible bitmasks for si_flags.  */ 
SYMINFO_FLG_DIRECT = 0x0001 # /* Direct bound symbol */
SYMINFO_FLG_PASSTHRU = 0x0002 # /* Pass-thru symbol for translator */
SYMINFO_FLG_COPY = 0x0004 # /* Symbol is a copy-reloc */
SYMINFO_FLG_LAZYLOAD = 0x0008 # /* Symbol bound to object to be lazy
                       # loaded */

# /* Syminfo version values.  */ 
SYMINFO_NONE = 0
SYMINFO_CURRENT = 1
SYMINFO_NUM = 2 # /* How to extract and insert information held in the st_info field.  */

# /* How to extract and insert information held in the st_info field.  */

ELF32_ST_BIND = lambda val:       (((val) & 0xff) >> 4)
ELF32_ST_TYPE = lambda val:       ((val) & 0xf)
ELF32_ST_INFO = lambda bind, typ:   (((bind) << 4) + ((typ) & 0xf))

# /* Both Elf32_Sym and Elf64_Sym use the same one-byte st_info field.  */
ELF64_ST_BIND = lambda val:      ELF32_ST_BIND (val)
ELF64_ST_TYPE = lambda val:      ELF32_ST_TYPE (val)
ELF64_ST_INFO = lambda bind, typ:   ELF32_ST_INFO ((bind), (typ))

# /* Legal values for ST_BIND subfield of st_info (symbol binding).  */ 
STB_LOCAL = 0 # /* Local symbol */
STB_GLOBAL = 1 # /* Global symbol */
STB_WEAK = 2 # /* Weak symbol */
STB_NUM = 3 # /* Number of defined types.  */
STB_LOOS = 10 # /* Start of OS-specific */
STB_GNU_UNIQUE = 10 # /* Unique symbol.  */
STB_HIOS = 12 # /* End of OS-specific */
STB_LOPROC = 13 # /* Start of processor-specific */
STB_HIPROC = 15 # /* End of processor-specific */

# /* Legal values for ST_TYPE subfield of st_info (symbol type).  */ 
STT_NOTYPE = 0 # /* Symbol type is unspecified */
STT_OBJECT = 1 # /* Symbol is a data object */
STT_FUNC = 2 # /* Symbol is a code object */
STT_SECTION = 3 # /* Symbol associated with a section */
STT_FILE = 4 # /* Symbol's name is file name */
STT_COMMON = 5 # /* Symbol is a common data object */
STT_TLS = 6 # /* Symbol is thread-local data object*/
STT_NUM = 7 # /* Number of defined types.  */
STT_LOOS = 10 # /* Start of OS-specific */
STT_GNU_IFUNC = 10 # /* Symbol is indirect code object */
STT_HIOS = 12 # /* End of OS-specific */
STT_LOPROC = 13 # /* Start of processor-specific */
STT_HIPROC = 15 # /* End of processor-specific */

# /* Symbol table indices are found in the hash buckets and chain table
#    of a symbol hash table section.  This special index value indicates
#    the end of a chain, meaning no further symbols are found in that bucket.  */ 
STN_UNDEF = 0 # /* End of a chain.  */

# /* How to extract and insert information held in the st_other field.  */ 
ELF32_ST_VISIBILITY = lambda o: ((o) & 0x03)

# /* For ELF64 the definitions are the same.  */ 
ELF64_ST_VISIBILITY = lambda o: ELF32_ST_VISIBILITY(o)

# /* Symbol visibility specification encoded in the st_other field.  */ 
STV_DEFAULT = 0 # /* Default symbol visibility rules */
STV_INTERNAL = 1 # /* Processor specific hidden class */
STV_HIDDEN = 2 # /* Sym unavailable in other modules */
STV_PROTECTED = 3 # /* Not preemptible, not exported */

# /* Relocation table entry without addend (in section of type SHT_REL).  */ 

# Kind: StructDecl
class Elf32_Rel(Structure):
	_fields_ = [
		("r_offset", c_uint), # /* Address */ 
		("r_info", c_uint)] # /* Relocation type and symbol index */ 

# /* I have seen two different definitions of the Elf64_Rel and
#   Elf64_Rela structures, so we'll leave them out until Novell (or
#   whoever) gets their act together.  */ 
# /* The following, at least, is used on Sparc v9, MIPS, and Alpha.  */ 

# Kind: StructDecl
class Elf64_Rel(Structure):
	_fields_ = [
		("r_offset", c_ulong), # /* Address */ 
		("r_info", c_ulong)] # /* Relocation type and symbol index */ 

# /* Relocation table entry with addend (in section of type SHT_RELA).  */ 

# Kind: StructDecl
class Elf32_Rela(Structure):
	_fields_ = [
		("r_offset", c_uint), # /* Address */ 
		("r_info", c_uint), # /* Relocation type and symbol index */ 
		("r_addend", c_int)] # /* Addend */ 

# Kind: StructDecl
class Elf64_Rela(Structure):
	_fields_ = [
		("r_offset", c_ulong), # /* Address */ 
		("r_info", c_ulong), # /* Relocation type and symbol index */ 
		("r_addend", c_long)] # /* Addend */ 

# /* How to extract and insert information held in the r_info field.  */ 
ELF32_R_SYM = lambda val:        ((val) >> 8)
ELF32_R_TYPE = lambda val:       ((val) & 0xff)
ELF32_R_INFO = lambda sym, typ:     (((sym) << 8) + ((typ) & 0xff))

ELF64_R_SYM = lambda i:          ((i) >> 32)
ELF64_R_TYPE = lambda i:         ((i) & 0xffffffff)
ELF64_R_INFO = lambda sym,typ:      ((((Elf64_Xword) (sym)) << 32) + (typ))

# /* Program segment header.  */ 

# Kind: StructDecl
class Elf32_Phdr(Structure):
	_fields_ = [
		("p_type", c_uint), # /* Segment type */ 
		("p_offset", c_uint), # /* Segment file offset */ 
		("p_vaddr", c_uint), # /* Segment virtual address */ 
		("p_paddr", c_uint), # /* Segment physical address */ 
		("p_filesz", c_uint), # /* Segment size in file */ 
		("p_memsz", c_uint), # /* Segment size in memory */ 
		("p_flags", c_uint), # /* Segment flags */ 
		("p_align", c_uint)] # /* Segment alignment */ 


# Kind: StructDecl
class Elf64_Phdr(Structure):
	_fields_ = [
		("p_type", c_uint), # /* Segment type */ 
		("p_flags", c_uint), # /* Segment flags */ 
		("p_offset", c_ulong), # /* Segment file offset */ 
		("p_vaddr", c_ulong), # /* Segment virtual address */ 
		("p_paddr", c_ulong), # /* Segment physical address */ 
		("p_filesz", c_ulong), # /* Segment size in file */ 
		("p_memsz", c_ulong), # /* Segment size in memory */ 
		("p_align", c_ulong)] # /* Segment alignment */ 

# /* Special value for e_phnum.  This indicates that the real number of
#   program headers is too large to fit into e_phnum.  Instead the real
#   value is in the field sh_info of section 0.  */ 

PN_XNUM = 0xffff # /* Legal values for p_type (segment type).  */
PT_NULL = 0 # /* Program header table entry unused */
PT_LOAD = 1 # /* Loadable program segment */
PT_DYNAMIC = 2 # /* Dynamic linking information */
PT_INTERP = 3 # /* Program interpreter */
PT_NOTE = 4 # /* Auxiliary information */
PT_SHLIB = 5 # /* Reserved */
PT_PHDR = 6 # /* Entry for header table itself */
PT_TLS = 7 # /* Thread-local storage segment */
PT_NUM = 8 # /* Number of defined types */
PT_LOOS = 0x60000000 # /* Start of OS-specific */
PT_GNU_EH_FRAME = 0x6474e550 # /* GCC .eh_frame_hdr segment */
PT_GNU_STACK = 0x6474e551 # /* Indicates stack executability */
PT_GNU_RELRO = 0x6474e552 # /* Read-only after relocation */
PT_GNU_PROPERTY = 0x6474e553 # /* GNU property */
PT_LOSUNW = 0x6ffffffa
PT_SUNWBSS = 0x6ffffffa # /* Sun Specific segment */
PT_SUNWSTACK = 0x6ffffffb # /* Stack segment */
PT_HISUNW = 0x6fffffff
PT_HIOS = 0x6fffffff # /* End of OS-specific */
PT_LOPROC = 0x70000000 # /* Start of processor-specific */
PT_HIPROC = 0x7fffffff # /* End of processor-specific */

# /* Legal values for p_flags (segment flags).  */ 
PF_X = (1 << 0) # /* Segment is executable */ 
PF_W = (1 << 1) # /* Segment is writable */ 
PF_R = (1 << 2) # /* Segment is readable */ 
PF_MASKOS = 0x0ff00000 # /* OS-specific */
PF_MASKPROC = 0xf0000000 # /* Processor-specific */

# /* Legal values for note segment descriptor types for core files. */ 
NT_PRSTATUS = 1 # /* Contains copy of prstatus struct */
NT_PRFPREG = 2 # /* Contains copy of fpregset
#                       struct.  */
NT_FPREGSET = 2 # /* Contains copy of fpregset struct */
NT_PRPSINFO = 3 # /* Contains copy of prpsinfo struct */
NT_PRXREG = 4 # /* Contains copy of prxregset struct */
NT_TASKSTRUCT = 4 # /* Contains copy of task structure */
NT_PLATFORM = 5 # /* String from sysinfo(SI_PLATFORM) */
NT_AUXV = 6 # /* Contains copy of auxv array */
NT_GWINDOWS = 7 # /* Contains copy of gwindows struct */
NT_ASRS = 8 # /* Contains copy of asrset struct */
NT_PSTATUS = 10 # /* Contains copy of pstatus struct */
NT_PSINFO = 13 # /* Contains copy of psinfo struct */
NT_PRCRED = 14 # /* Contains copy of prcred struct */
NT_UTSNAME = 15 # /* Contains copy of utsname struct */
NT_LWPSTATUS = 16 # /* Contains copy of lwpstatus struct */
NT_LWPSINFO = 17 # /* Contains copy of lwpinfo struct */
NT_PRFPXREG = 20 # /* Contains copy of fprxregset struct */
NT_SIGINFO = 0x53494749 # /* Contains copy of siginfo_t,
#                       size might increase */
NT_FILE = 0x46494c45 # /* Contains information about mapped
#                       files */
NT_PRXFPREG = 0x46e62b7f # /* Contains copy of user_fxsr_struct */
NT_PPC_VMX = 0x100 # /* PowerPC Altivec/VMX registers */
NT_PPC_SPE = 0x101 # /* PowerPC SPE/EVR registers */
NT_PPC_VSX = 0x102 # /* PowerPC VSX registers */
NT_PPC_TAR = 0x103 # /* Target Address Register */
NT_PPC_PPR = 0x104 # /* Program Priority Register */
NT_PPC_DSCR = 0x105 # /* Data Stream Control Register */
NT_PPC_EBB = 0x106 # /* Event Based Branch Registers */
NT_PPC_PMU = 0x107 # /* Performance Monitor Registers */
NT_PPC_TM_CGPR = 0x108 # /* TM checkpointed GPR Registers */
NT_PPC_TM_CFPR = 0x109 # /* TM checkpointed FPR Registers */
NT_PPC_TM_CVMX = 0x10a # /* TM checkpointed VMX Registers */
NT_PPC_TM_CVSX = 0x10b # /* TM checkpointed VSX Registers */
NT_PPC_TM_SPR = 0x10c # /* TM Special Purpose Registers */
NT_PPC_TM_CTAR = 0x10d # /* TM checkpointed Target Address
#                       Register */
NT_PPC_TM_CPPR = 0x10e # /* TM checkpointed Program Priority
#                       Register */
NT_PPC_TM_CDSCR = 0x10f # /* TM checkpointed Data Stream Control
#                       Register */
NT_PPC_PKEY = 0x110 # /* Memory Protection Keys
#                       registers.  */
NT_386_TLS = 0x200 # /* i386 TLS slots (struct user_desc) */
NT_386_IOPERM = 0x201 # /* x86 io permission bitmap (1=deny) */
NT_X86_XSTATE = 0x202 # /* x86 extended state using xsave */
NT_S390_HIGH_GPRS = 0x300 # /* s390 upper register halves */
NT_S390_TIMER = 0x301 # /* s390 timer register */
NT_S390_TODCMP = 0x302 # /* s390 TOD clock comparator register */
NT_S390_TODPREG = 0x303 # /* s390 TOD programmable register */
NT_S390_CTRS = 0x304 # /* s390 control registers */
NT_S390_PREFIX = 0x305 # /* s390 prefix register */
NT_S390_LAST_BREAK = 0x306 # /* s390 breaking event address */
NT_S390_SYSTEM_CALL = 0x307 # /* s390 system call restart data */
NT_S390_TDB = 0x308 # /* s390 transaction diagnostic block */
NT_S390_VXRS_LOW = 0x309 # /* s390 vector registers 0-15
#                       upper half.  */
NT_S390_VXRS_HIGH = 0x30a # /* s390 vector registers 16-31.  */
NT_S390_GS_CB = 0x30b # /* s390 guarded storage registers.  */
NT_S390_GS_BC = 0x30c # /* s390 guarded storage
#                       broadcast control block.  */
NT_S390_RI_CB = 0x30d # /* s390 runtime instrumentation.  */
NT_ARM_VFP = 0x400 # /* ARM VFP/NEON registers */
NT_ARM_TLS = 0x401 # /* ARM TLS register */
NT_ARM_HW_BREAK = 0x402 # /* ARM hardware breakpoint registers */
NT_ARM_HW_WATCH = 0x403 # /* ARM hardware watchpoint registers */
NT_ARM_SYSTEM_CALL = 0x404 # /* ARM system call number */
NT_ARM_SVE = 0x405 # /* ARM Scalable Vector Extension
#                       registers */
NT_ARM_PAC_MASK = 0x406 # /* ARM pointer authentication
#                       code masks.  */
NT_ARM_PACA_KEYS = 0x407 # /* ARM pointer authentication
#                       address keys.  */
NT_ARM_PACG_KEYS = 0x408 # /* ARM pointer authentication
#                       generic key.  */
NT_ARM_TAGGED_ADDR_CTRL = 0x409 # /* AArch64 tagged address
#                       control.  */
NT_ARM_PAC_ENABLED_KEYS = 0x40a # /* AArch64 pointer authentication
#                       enabled keys.  */
NT_VMCOREDD = 0x700 # /* Vmcore Device Dump Note.  */
NT_MIPS_DSP = 0x800 # /* MIPS DSP ASE registers.  */
NT_MIPS_FP_MODE = 0x801 # /* MIPS floating-point mode.  */
NT_MIPS_MSA = 0x802 # /* MIPS SIMD registers.  */

# /* Legal values for the note segment descriptor types for object files.  */ 
NT_VERSION = 1 # /* Contains a version string.  */

# /* Dynamic section entry.  */ 

# Kind: UnionDecl
class Elf32_Dyn_Anon1(Union):
	_fields_ = [
		("d_val", c_uint), # /* Integer value */ 
		("d_ptr", c_uint)] # /* Address value */ 

# Kind: StructDecl
class Elf32_Dyn(Structure):
	_fields_ = [
		("d_tag", c_int), # /* Dynamic entry type */ 
		("d_un", Elf32_Dyn_Anon1)]

# /* Legal values for d_tag field of Elf32_Dyn.  */
DT_MIPS_RLD_VERSION = 0x70000001# /* Runtime linker interface version */
DT_MIPS_TIME_STAMP = 0x70000002 # /* Timestamp */
DT_MIPS_ICHECKSUM = 0x70000003 # /* Checksum */
DT_MIPS_IVERSION = 0x70000004 # /* Version string (string tbl index) */
DT_MIPS_FLAGS = 0x70000005 # /* Flags */
DT_MIPS_BASE_ADDRESS = 0x70000006 # /* Base address */
DT_MIPS_MSYM = 0x70000007
DT_MIPS_CONFLICT = 0x70000008 # /* Address of CONFLICT section */
DT_MIPS_LIBLIST = 0x70000009 # /* Address of LIBLIST section */
DT_MIPS_LOCAL_GOTNO = 0x7000000a # /* Number of local GOT entries */
DT_MIPS_CONFLICTNO = 0x7000000b # /* Number of CONFLICT entries */
DT_MIPS_LIBLISTNO = 0x70000010 # /* Number of LIBLIST entries */
DT_MIPS_SYMTABNO = 0x70000011 # /* Number of DYNSYM entries */
DT_MIPS_UNREFEXTNO = 0x70000012 # /* First external DYNSYM */
DT_MIPS_GOTSYM = 0x70000013 # /* First GOT entry in DYNSYM */
DT_MIPS_HIPAGENO = 0x70000014 # /* Number of GOT page table entries */
DT_MIPS_RLD_MAP = 0x70000016 # /* Address of run time loader map.  */
DT_MIPS_DELTA_CLASS = 0x70000017 # /* Delta C++ class definition.  */
DT_MIPS_DELTA_CLASS_NO = 0x70000018 # /* Number of entries in
#                         DT_MIPS_DELTA_CLASS.  */
DT_MIPS_DELTA_INSTANCE = 0x70000019 # /* Delta C++ class instances.  */
DT_MIPS_DELTA_INSTANCE_NO = 0x7000001a # /* Number of entries in
#                         DT_MIPS_DELTA_INSTANCE.  */
DT_MIPS_DELTA_RELOC = 0x7000001b # /* Delta relocations.  */
DT_MIPS_DELTA_RELOC_NO = 0x7000001c # /* Number of entries in
#                          DT_MIPS_DELTA_RELOC.  */
DT_MIPS_DELTA_SYM = 0x7000001d # /* Delta symbols that Delta
#                        relocations refer to.  */
DT_MIPS_DELTA_SYM_NO = 0x7000001e # /* Number of entries in
#                        DT_MIPS_DELTA_SYM.  */
DT_MIPS_DELTA_CLASSSYM = 0x70000020 # /* Delta symbols that hold the
#                          class declaration.  */
DT_MIPS_DELTA_CLASSSYM_NO = 0x70000021 # /* Number of entries in
#                         DT_MIPS_DELTA_CLASSSYM.  */
DT_MIPS_CXX_FLAGS = 0x70000022 # /* Flags indicating for C++ flavor.  */
DT_MIPS_PIXIE_INIT = 0x70000023
DT_MIPS_SYMBOL_LIB = 0x70000024
DT_MIPS_LOCALPAGE_GOTIDX = 0x70000025
DT_MIPS_LOCAL_GOTIDX = 0x70000026
DT_MIPS_HIDDEN_GOTIDX = 0x70000027
DT_MIPS_PROTECTED_GOTIDX = 0x70000028
DT_MIPS_OPTIONS = 0x70000029 # /* Address of .options.  */
DT_MIPS_INTERFACE = 0x7000002a # /* Address of .interface.  */
DT_MIPS_DYNSTR_ALIGN = 0x7000002b
DT_MIPS_INTERFACE_SIZE = 0x7000002c # /* Size of the .interface section. */
DT_MIPS_RLD_TEXT_RESOLVE_ADDR = 0x7000002d # /* Address of rld_text_rsolve
#                             function stored in GOT.  */
DT_MIPS_PERF_SUFFIX = 0x7000002e # /* Default suffix of dso to be added
#                        by rld on dlopen() calls.  */
DT_MIPS_COMPACT_SIZE = 0x7000002f # /* (O32)Size of compact rel section. */
DT_MIPS_GP_VALUE = 0x70000030 # /* GP value for aux GOTs.  */
DT_MIPS_AUX_DYNAMIC = 0x70000031 # /* Address of aux .dynamic.  */
# /* The address of .got.plt in an executable using the new non-PIC ABI.  */ 
DT_MIPS_PLTGOT = 0x70000032
# /* The base of the PLT in an executable using the new non-PIC ABI if that
#    PLT is writable.  For a non-writable PLT, this is omitted or has a zero
#    value.  */
DT_MIPS_RWPLT = 0x70000034
# /* An alternative description of the classic MIPS RLD_MAP that is usable
#    in a PIE as it stores a relative offset from the address of the tag
#    rather than an absolute address.  */
DT_MIPS_RLD_MAP_REL = 0x70000035 # /* GNU-style hash table with xlat.  */
DT_MIPS_XHASH = 0x70000036
DT_MIPS_NUM = 0x37

# Kind: UnionDecl
class Elf64_Dyn_Anon1(Union):
	_fields_ = [
		("d_val", c_ulong), # /* Integer value */ 
		("d_ptr", c_ulong)] # /* Address value */ 

# Kind: StructDecl
class Elf64_Dyn(Structure):
	_fields_ = [
		("d_tag", c_long), # /* Dynamic entry type */ 
		("d_un", Elf64_Dyn_Anon1)] 

# /* Legal values for d_tag (dynamic entry type).  */ 

DT_NULL = 0 # /* Marks end of dynamic section */
DT_NEEDED = 1 # /* Name of needed library */
DT_PLTRELSZ = 2 # /* Size in bytes of PLT relocs */
DT_PLTGOT = 3 # /* Processor defined value */
DT_HASH = 4 # /* Address of symbol hash table */
DT_STRTAB = 5 # /* Address of string table */
DT_SYMTAB = 6 # /* Address of symbol table */
DT_RELA = 7 # /* Address of Rela relocs */
DT_RELASZ = 8 # /* Total size of Rela relocs */
DT_RELAENT = 9 # /* Size of one Rela reloc */
DT_STRSZ = 10 # /* Size of string table */
DT_SYMENT = 11 # /* Size of one symbol table entry */
DT_INIT = 12 # /* Address of init function */
DT_FINI = 13 # /* Address of termination function */
DT_SONAME = 14 # /* Name of shared object */
DT_RPATH = 15 # /* Library search path (deprecated) */
DT_SYMBOLIC = 16 # /* Start symbol search here */
DT_REL = 17 # /* Address of Rel relocs */
DT_RELSZ = 18 # /* Total size of Rel relocs */
DT_RELENT = 19 # /* Size of one Rel reloc */
DT_PLTREL = 20 # /* Type of reloc in PLT */
DT_DEBUG = 21 # /* For debugging; unspecified */
DT_TEXTREL = 22 # /* Reloc might modify .text */
DT_JMPREL = 23 # /* Address of PLT relocs */
DT_BIND_NOW = 24 # /* Process relocations of object */
DT_INIT_ARRAY = 25 # /* Array with addresses of init fct */
DT_FINI_ARRAY = 26 # /* Array with addresses of fini fct */
DT_INIT_ARRAYSZ = 27 # /* Size in bytes of DT_INIT_ARRAY */
DT_FINI_ARRAYSZ = 28 # /* Size in bytes of DT_FINI_ARRAY */
DT_RUNPATH = 29 # /* Library search path */
DT_FLAGS = 30 # /* Flags for the object being loaded */
DT_ENCODING = 32 # /* Start of encoded range */
DT_PREINIT_ARRAY = 32 # /* Array with addresses of preinit fct*/
DT_PREINIT_ARRAYSZ = 33 # /* size in bytes of DT_PREINIT_ARRAY */
DT_SYMTAB_SHNDX = 34 # /* Address of SYMTAB_SHNDX section */
DT_RELRSZ = 35 # /* Total size of RELR relative relocations */
DT_RELR = 36 # /* Address of RELR relative relocations */
DT_RELRENT = 37 # /* Size of one RELR relative relocaction */
DT_NUM = 38 # /* Number used */
DT_LOOS = 0x6000000d # /* Start of OS-specific */
DT_HIOS = 0x6ffff000 # /* End of OS-specific */
DT_LOPROC = 0x70000000 # /* Start of processor-specific */
DT_HIPROC = 0x7fffffff # /* End of processor-specific */
DT_PROCNUM = DT_MIPS_NUM # /* Most used by any processor */

# /* DT_* entries which fall between DT_VALRNGHI & DT_VALRNGLO use the
#    Dyn.d_un.d_val field of the Elf*_Dyn structure.  This follows Sun's
#    approach.  */ 
DT_VALRNGLO = 0x6ffffd00
DT_GNU_PRELINKED = 0x6ffffdf5 # /* Prelinking timestamp */
DT_GNU_CONFLICTSZ = 0x6ffffdf6 # /* Size of conflict section */
DT_GNU_LIBLISTSZ = 0x6ffffdf7 # /* Size of library list */
DT_CHECKSUM = 0x6ffffdf8
DT_PLTPADSZ = 0x6ffffdf9
DT_MOVEENT = 0x6ffffdfa
DT_MOVESZ = 0x6ffffdfb
DT_FEATURE_1 = 0x6ffffdfc # /* Feature selection (DTF_*).  */
DT_POSFLAG_1 = 0x6ffffdfd # /* Flags for DT_* entries, effecting
#                       the following DT_* entry.  */
DT_SYMINSZ = 0x6ffffdfe # /* Size of syminfo table (in bytes) */
DT_SYMINENT = 0x6ffffdff # /* Entry size of syminfo */
DT_VALRNGHI = 0x6ffffdff
DT_VALTAGIDX = lambda tag: (DT_VALRNGHI - (tag)) # /* Reverse order! */ 
DT_VALNUM = 12

# /* DT_* entries which fall between DT_ADDRRNGHI & DT_ADDRRNGLO use the
#    Dyn.d_un.d_ptr field of the Elf*_Dyn structure.
# 
#    If any adjustment is made to the ELF object after it has been
#    built these entries will need to be adjusted.  */
DT_ADDRRNGLO = 0x6ffffe00
DT_GNU_HASH = 0x6ffffef5 # /* GNU-style hash table.  */
DT_TLSDESC_PLT = 0x6ffffef6
DT_TLSDESC_GOT = 0x6ffffef7
DT_GNU_CONFLICT = 0x6ffffef8 # /* Start of conflict section */
DT_GNU_LIBLIST = 0x6ffffef9 # /* Library list */
DT_CONFIG = 0x6ffffefa # /* Configuration information.  */
DT_DEPAUDIT = 0x6ffffefb # /* Dependency auditing.  */
DT_AUDIT = 0x6ffffefc # /* Object auditing.  */
DT_PLTPAD = 0x6ffffefd # /* PLT padding.  */
DT_MOVETAB = 0x6ffffefe # /* Move table.  */
DT_SYMINFO = 0x6ffffeff # /* Syminfo table.  */
DT_ADDRRNGHI = 0x6ffffeff
DT_ADDRTAGIDX = lambda tag: (DT_ADDRRNGHI - (tag)) # /* Reverse order! */ 
DT_ADDRNUM = 11

# /* The versioning entry types.  The next are defined as part of the
#    GNU extension.  */
DT_VERSYM = 0x6ffffff0
DT_RELACOUNT = 0x6ffffff9
DT_RELCOUNT = 0x6ffffffa # /* These were chosen by Sun.  */
DT_FLAGS_1 = 0x6ffffffb # /* State flags, see DF_1_* below.  */
DT_VERDEF = 0x6ffffffc # /* Address of version definition
#                        table */
DT_VERDEFNUM = 0x6ffffffd # /* Number of version definitions */
DT_VERNEED = 0x6ffffffe # /* Address of table with needed
#                        versions */
DT_VERNEEDNUM = 0x6fffffff # /* Number of needed versions */
DT_VERSIONTAGIDX = lambda tag: (DT_VERNEEDNUM - (tag)) # /* Reverse order! */ 
DT_VERSIONTAGNUM = 16

# /* Sun added these machine-independent extensions in the "processor-specific"
#    range.  Be compatible.  */
DT_AUXILIARY = 0x7ffffffd # /* Shared object to load before self */
DT_FILTER = 0x7fffffff # /* Shared object to get values from */
# DT_EXTRATAGIDX = ((Elf32_Word)-((Elf32_Sword) (tag) <<1>>1)-1)
DT_EXTRANUM = 3

# /* Values of `d_un.d_val' in the DT_FLAGS entry.  */
DF_ORIGIN = 0x00000001 # /* Object may use DF_ORIGIN */
DF_SYMBOLIC = 0x00000002 # /* Symbol resolutions starts here */
DF_TEXTREL = 0x00000004 # /* Object contains text relocations */
DF_BIND_NOW = 0x00000008 # /* No lazy binding for this object */
DF_STATIC_TLS = 0x00000010 # /* Module uses the static TLS model */
# /* State flags selectable in the `d_un.d_val' element of the DT_FLAGS_1
#   entry in the dynamic section.  */ 
DF_1_NOW = 0x00000001 # /* Set RTLD_NOW for this object.  */
DF_1_GLOBAL = 0x00000002 # /* Set RTLD_GLOBAL for this object.  */
DF_1_GROUP = 0x00000004 # /* Set RTLD_GROUP for this object.  */
DF_1_NODELETE = 0x00000008 # /* Set RTLD_NODELETE for this object.*/
DF_1_LOADFLTR = 0x00000010 # /* Trigger filtee loading at runtime.*/
DF_1_INITFIRST = 0x00000020 # /* Set RTLD_INITFIRST for this object*/
DF_1_NOOPEN = 0x00000040 # /* Set RTLD_NOOPEN for this object.  */
DF_1_ORIGIN = 0x00000080 # /* $ORIGIN must be handled.  */
DF_1_DIRECT = 0x00000100 # /* Direct binding enabled.  */
DF_1_TRANS = 0x00000200
DF_1_INTERPOSE = 0x00000400 # /* Object is used to interpose.  */
DF_1_NODEFLIB = 0x00000800 # /* Ignore default lib search path.  */
DF_1_NODUMP = 0x00001000 # /* Object can't be dldump'ed.  */
DF_1_CONFALT = 0x00002000 # /* Configuration alternative created.*/
DF_1_ENDFILTEE = 0x00004000 # /* Filtee terminates filters search. */
DF_1_DISPRELDNE = 0x00008000 # /* Disp reloc applied at build time. */
DF_1_DISPRELPND = 0x00010000 # /* Disp reloc applied at run-time.  */
DF_1_NODIRECT = 0x00020000 # /* Object has no-direct binding. */
DF_1_IGNMULDEF = 0x00040000
DF_1_NOKSYMS = 0x00080000
DF_1_NOHDR = 0x00100000
DF_1_EDITED = 0x00200000 # /* Object is modified after built.  */
DF_1_NORELOC = 0x00400000
DF_1_SYMINTPOSE = 0x00800000 # /* Object has individual interposers.  */
DF_1_GLOBAUDIT = 0x01000000 # /* Global auditing required.  */
DF_1_SINGLETON = 0x02000000 # /* Singleton symbols are used.  */
DF_1_STUB = 0x04000000
DF_1_PIE = 0x08000000
DF_1_KMOD = 0x10000000
DF_1_WEAKFILTER = 0x20000000
DF_1_NOCOMMON = 0x40000000

# /* Flags for the feature selection in DT_FEATURE_1.  */
DTF_1_PARINIT = 0x00000001
DTF_1_CONFEXP = 0x00000002

# /* Flags in the DT_POSFLAG_1 entry effecting only the next DT_* entry.  */
DF_P1_LAZYLOAD = 0x00000001 # /* Lazyload following object.  */
DF_P1_GROUPPERM = 0x00000002 # /* Symbols from next object are not
#                        generally available.  */

# /* Version definition sections.  */

# Kind: StructDecl
class Elf32_Verdef(Structure):
	_fields_ = [
		("vd_version", c_ushort), # /* Version revision */ 
		("vd_flags", c_ushort), # /* Version information */ 
		("vd_ndx", c_ushort), # /* Version Index */ 
		("vd_cnt", c_ushort), # /* Number of associated aux entries */ 
		("vd_hash", c_uint), # /* Version name hash value */ 
		("vd_aux", c_uint), # /* Offset in bytes to verdaux array */ 
		("vd_next", c_uint)] # /* Offset in bytes to next verdef entry */ 


# Kind: StructDecl
class Elf64_Verdef(Structure):
	_fields_ = [
		("vd_version", c_ushort), # /* Version revision */ 
		("vd_flags", c_ushort), # /* Version information */ 
		("vd_ndx", c_ushort), # /* Version Index */ 
		("vd_cnt", c_ushort), # /* Number of associated aux entries */ 
		("vd_hash", c_uint), # /* Version name hash value */ 
		("vd_aux", c_uint), # /* Offset in bytes to verdaux array */ 
		("vd_next", c_uint)] # /* Offset in bytes to next verdef entry */ 

# /* Legal values for vd_version (version revision).  */ 
VER_DEF_NONE = 0 # /* No version */
VER_DEF_CURRENT = 1 # /* Current version */
VER_DEF_NUM = 2 # /* Given version number */

# /* Legal values for vd_flags (version information flags).  */ 
VER_FLG_BASE = 0x1 # /* Version definition of file itself */
VER_FLG_WEAK = 0x2 # /* Weak version identifier */

# /* Versym symbol index values.  */ 
VER_NDX_LOCAL = 0 # /* Symbol is local.  */
VER_NDX_GLOBAL = 1 # /* Symbol is global.  */
VER_NDX_LORESERVE = 0xff00 # /* Beginning of reserved entries.  */
VER_NDX_ELIMINATE = 0xff01 # /* Symbol is to be eliminated.  */

# /* Auxiliary version information.  */ 

# Kind: StructDecl
class Elf32_Verdaux(Structure):
	_fields_ = [
		("vda_name", c_uint), # /* Version or dependency names */ 
		("vda_next", c_uint)] # /* Offset in bytes to next verdaux entry


# Kind: StructDecl
class Elf64_Verdaux(Structure):
	_fields_ = [
		("vda_name", c_uint), # /* Version or dependency names */ 
		("vda_next", c_uint)] # /* Offset in bytes to next verdaux entry

# /* Version dependency section.  */ 

# Kind: StructDecl
class Elf32_Verneed(Structure):
	_fields_ = [
		("vn_version", c_ushort), # /* Version of structure */ 
		("vn_cnt", c_ushort), # /* Number of associated aux entries */ 
		("vn_file", c_uint), # /* Offset of filename for this dependency
		("vn_aux", c_uint), # /* Offset in bytes to vernaux array */ 
		("vn_next", c_uint)] # /* Offset in bytes to next verneed entry


# Kind: StructDecl
class Elf64_Verneed(Structure):
	_fields_ = [
		("vn_version", c_ushort), # /* Version of structure */ 
		("vn_cnt", c_ushort), # /* Number of associated aux entries */ 
		("vn_file", c_uint), # /* Offset of filename for this dependency
		("vn_aux", c_uint), # /* Offset in bytes to vernaux array */ 
		("vn_next", c_uint)] # /* Offset in bytes to next verneed entry

# /* Legal values for vn_version (version revision).  */ 
VER_NEED_NONE = 0 # /* No version */
VER_NEED_CURRENT = 1 # /* Current version */
VER_NEED_NUM = 2 # /* Given version number */

# /* Auxiliary needed version information.  */ 

# Kind: StructDecl
class Elf32_Vernaux(Structure):
	_fields_ = [
		("vna_hash", c_uint), # /* Hash value of dependency name */ 
		("vna_flags", c_ushort), # /* Dependency specific information */ 
		("vna_other", c_ushort), # /* Unused */ 
		("vna_name", c_uint), # /* Dependency name string offset */ 
		("vna_next", c_uint)] # /* Offset in bytes to next vernaux entry


# Kind: StructDecl
class Elf64_Vernaux(Structure):
	_fields_ = [
		("vna_hash", c_uint), # /* Hash value of dependency name */ 
		("vna_flags", c_ushort), # /* Dependency specific information */ 
		("vna_other", c_ushort), # /* Unused */ 
		("vna_name", c_uint), # /* Dependency name string offset */ 
		("vna_next", c_uint)] # /* Offset in bytes to next vernaux

# /* Legal values for vna_flags.  */ 
VER_FLG_WEAK = 0x2 # /* Weak version identifier */

# /* Auxiliary vector.  */ 
# /* This vector is normally only used by the program interpreter.  The
#    usual definition in an ABI supplement uses the name auxv_t.  The
#    vector is not usually defined in a standard <elf.h> file, but it
#    can't hurt.  We rename it to avoid conflicts.  The sizes of these
#    types are an arrangement between the exec server and the program
#    interpreter, so we don't fully specify them here.  */ 

# Kind: UnionDecl
class Elf32_auxv_t_Anon1(Union):
	_fields_ = [
		("a_val", c_uint)] # /* Integer value */ 
        # /* We use to have pointer elements added here.  We cannot do that,
        #    though, since it does not work when using 32-bit definitions
        #    on 64-bit platforms and vice versa.  */ 

# Kind: StructDecl
class Elf32_auxv_t(Structure):
	_fields_ = [
		("a_type", c_uint), # /* Entry type */ 
		("a_un", Elf32_auxv_t_Anon1)]

# Kind: UnionDecl
class Elf64_auxv_t_Anon1(Union):
	_fields_ = [
		("a_val", c_ulong)] # /* Integer value */
        # /* We use to have pointer elements added here.  We cannot do that,
        #    though, since it does not work when using 32-bit definitions
        #    on 64-bit platforms and vice versa.  */ 

# Kind: StructDecl
class Elf64_auxv_t(Structure):
	_fields_ = [
		("a_type", c_ulong), # /* Entry type */ 
		("a_un", Elf64_auxv_t_Anon1)]

# /* Legal values for a_type (entry type).  */ 
AT_NULL = 0 # /* End of vector */
AT_IGNORE = 1 # /* Entry should be ignored */
AT_EXECFD = 2 # /* File descriptor of program */
AT_PHDR = 3 # /* Program headers for program */
AT_PHENT = 4 # /* Size of program header entry */
AT_PHNUM = 5 # /* Number of program headers */
AT_PAGESZ = 6 # /* System page size */
AT_BASE = 7 # /* Base address of interpreter */
AT_FLAGS = 8 # /* Flags */
AT_ENTRY = 9 # /* Entry point of program */
AT_NOTELF = 10 # /* Program is not ELF */
AT_UID = 11 # /* Real uid */
AT_EUID = 12 # /* Effective uid */
AT_GID = 13 # /* Real gid */
AT_EGID = 14 # /* Effective gid */
AT_CLKTCK = 17 # /* Frequency of times() */

# /* Some more special a_type values describing the hardware.  */ 
AT_PLATFORM = 15 # /* String identifying platform.  */
AT_HWCAP = 16 # /* Machine-dependent hints about
#                        processor capabilities.  */

# /* This entry gives some information about the FPU initialization
#    performed by the kernel.  */ 
AT_FPUCW = 18 # /* Used FPU control word.  */

# /* Cache block sizes.  */ 
AT_DCACHEBSIZE = 19 # /* Data cache block size.  */
AT_ICACHEBSIZE = 20 # /* Instruction cache block size.  */
AT_UCACHEBSIZE = 21 # /* Unified cache block size.  */

# /* A special ignored value for PPC, used by the kernel to control the
#    interpretation of the AUXV. Must be > 16.  */ 
AT_IGNOREPPC = 22 # /* Entry should be ignored.  */
AT_SECURE = 23 # /* Boolean, was exec setuid-like?  */
AT_BASE_PLATFORM = 24 # /* String identifying real platforms.*/
AT_RANDOM = 25 # /* Address of 16 random bytes.  */
AT_HWCAP2 = 26 # /* More machine-dependent hints about
#                        processor capabilities.  */
AT_EXECFN = 31 # /* Filename of executable.  */

# /* Pointer to the global system page used for system calls and other
#    nice things.  */ 
AT_SYSINFO = 32
AT_SYSINFO_EHDR = 33

# /* Shapes of the caches.  Bits 0-3 contains associativity; bits 4-7 contains
#    log2 of line size; mask those to get cache size.  */
AT_L1I_CACHESHAPE = 34
AT_L1D_CACHESHAPE = 35
AT_L2_CACHESHAPE = 36
AT_L3_CACHESHAPE = 37
# /* Shapes of the caches, with more room to describe them.
#    *GEOMETRY are comprised of cache line size in bytes in the bottom 16 bits
#    and the cache associativity in the next 16 bits.  */
AT_L1I_CACHESIZE = 40
AT_L1I_CACHEGEOMETRY = 41
AT_L1D_CACHESIZE = 42
AT_L1D_CACHEGEOMETRY = 43
AT_L2_CACHESIZE = 44
AT_L2_CACHEGEOMETRY = 45
AT_L3_CACHESIZE = 46
AT_L3_CACHEGEOMETRY = 47
AT_MINSIGSTKSZ = 51 # /* Stack needed for signal delivery  */

# /* Note section contents.  Each entry in the note section begins with
#    a header of a fixed form.  */ 

# Kind: StructDecl
class Elf32_Nhdr(Structure):
	_fields_ = [
		("n_namesz", c_uint), # /* Length of the note's name.  */ 
		("n_descsz", c_uint), # /* Length of the note's descriptor.  */ 
		("n_type", c_uint)] # /* Type of the note.  */ 


# Kind: StructDecl
class Elf64_Nhdr(Structure):
	_fields_ = [
		("n_namesz", c_uint), # /* Length of the note's name.  */ 
		("n_descsz", c_uint), # /* Length of the note's descriptor.  */ 
		("n_type", c_uint)] # /* Type of the note.  */ 

# /* Known names of notes.  */ 

# /* Solaris entries in the note section have this name.  */ 
ELF_NOTE_SOLARIS = "SUNW Solaris"

# /* Note entries for GNU systems have this name.  */
ELF_NOTE_GNU = "GNU"

# /* Note entries for freedesktop.org have this name.  */
ELF_NOTE_FDO = "FDO"

# /* Defined types of notes for Solaris.  */

# /* Value of descriptor (one word) is desired pagesize for the binary.  */ 
ELF_NOTE_PAGESIZE_HINT = 1

# /* Defined note types for GNU systems.  */

# /* ABI information.  The descriptor consists of words:
#    word 0: OS descriptor
#    word 1: major version of the ABI
#    word 2: minor version of the ABI
#    word 3: subminor version of the ABI
# */ 
NT_GNU_ABI_TAG = 1
ELF_NOTE_ABI = NT_GNU_ABI_TAG # /* Old name.  */

# /* Known OSes.  These values can appear in word 0 of an
#   NT_GNU_ABI_TAG note section entry.  */ 
ELF_NOTE_OS_LINUX = 0
ELF_NOTE_OS_GNU = 1
ELF_NOTE_OS_SOLARIS2 = 2
ELF_NOTE_OS_FREEBSD = 3

# /* Synthetic hwcap information.  The descriptor begins with two words:
#    word 0: number of entries
#    word 1: bitmask of enabled entries
#    Then follow variable-length entries, one byte followed by a
#    '\0'-terminated hwcap name string.  The byte gives the bit
#    number to test if enabled, (1U << bit) & bitmask.  */
NT_GNU_HWCAP = 2

# /* Build ID bits as generated by ld --build-id.
#    The descriptor consists of any nonzero number of bytes.  */
NT_GNU_BUILD_ID = 3

# /* Version note generated by GNU gold containing a version string.  */
NT_GNU_GOLD_VERSION = 4

# /* Program property.  */
NT_GNU_PROPERTY_TYPE_0 = 5

# /* Packaging metadata as defined on
#    https://systemd.io/COREDUMP_PACKAGE_METADATA/ */
NT_FDO_PACKAGING_METADATA = 0xcafe1a7e

# /* Note section name of program property.   */
NOTE_GNU_PROPERTY_SECTION_NAME = ".note.gnu.property"

# /* Values used in GNU .note.gnu.property notes (NT_GNU_PROPERTY_TYPE_0).  */

# /* Stack size.  */ 
GNU_PROPERTY_STACK_SIZE = 1
# /* No copy relocation on protected data symbol.  */
GNU_PROPERTY_NO_COPY_ON_PROTECTED = 2

# /* A 4-byte unsigned integer property: A bit is set if it is set in all
#    relocatable inputs.  */
GNU_PROPERTY_UINT32_AND_LO = 0xb0000000
GNU_PROPERTY_UINT32_AND_HI = 0xb0007fff

# /* A 4-byte unsigned integer property: A bit is set if it is set in any
#    relocatable inputs.  */
GNU_PROPERTY_UINT32_OR_LO = 0xb0008000
GNU_PROPERTY_UINT32_OR_HI = 0xb000ffff

# /* The needed properties by the object file.  */
GNU_PROPERTY_1_NEEDED = GNU_PROPERTY_UINT32_OR_LO

# /* Set if the object file requires canonical function pointers and
#    cannot be used with copy relocation.  */
GNU_PROPERTY_1_NEEDED_INDIRECT_EXTERN_ACCESS = (1 << 0)

# /* Processor-specific semantics, lo */ 
GNU_PROPERTY_LOPROC = 0xc0000000
# /* Processor-specific semantics, hi */
GNU_PROPERTY_HIPROC = 0xdfffffff
# /* Application-specific semantics, lo */
GNU_PROPERTY_LOUSER = 0xe0000000
# /* Application-specific semantics, hi */
GNU_PROPERTY_HIUSER = 0xffffffff

# /* AArch64 specific GNU properties.  */
GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000

GNU_PROPERTY_AARCH64_FEATURE_1_BTI = (1 << 0)
GNU_PROPERTY_AARCH64_FEATURE_1_PAC = (1 << 1)

# /* The x86 instruction sets indicated by the corresponding bits are
#    used in program.  Their support in the hardware is optional.  */ 
GNU_PROPERTY_X86_ISA_1_USED = 0xc0010002
# /* The x86 instruction sets indicated by the corresponding bits are
#    used in program and they must be supported by the hardware.   */
GNU_PROPERTY_X86_ISA_1_NEEDED = 0xc0008002
# /* X86 processor-specific features used in program.  */
GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002

# /* GNU_PROPERTY_X86_ISA_1_BASELINE: CMOV, CX8 (cmpxchg8b), FPU (fld),
#    MMX, OSFXSR (fxsave), SCE (syscall), SSE and SSE2.  */
GNU_PROPERTY_X86_ISA_1_BASELINE = (1 << 0)
# /* GNU_PROPERTY_X86_ISA_1_V2: GNU_PROPERTY_X86_ISA_1_BASELINE,
#   CMPXCHG16B (cmpxchg16b), LAHF-SAHF (lahf), POPCNT (popcnt), SSE3,
#   SSSE3, SSE4.1 and SSE4.2.  */ 
GNU_PROPERTY_X86_ISA_1_V2 = (1 << 1)
# /* GNU_PROPERTY_X86_ISA_1_V3: GNU_PROPERTY_X86_ISA_1_V2, AVX, AVX2, BMI1,
#   BMI2, F16C, FMA, LZCNT, MOVBE, XSAVE.  */ 
GNU_PROPERTY_X86_ISA_1_V3 = (1 << 2)
# /* GNU_PROPERTY_X86_ISA_1_V4: GNU_PROPERTY_X86_ISA_1_V3, AVX512F,
#   AVX512BW, AVX512CD, AVX512DQ and AVX512VL.  */ 
GNU_PROPERTY_X86_ISA_1_V4 = (1 << 3)

# /* This indicates that all executable sections are compatible with
#    IBT.  */ 
GNU_PROPERTY_X86_FEATURE_1_IBT = (1 << 0)
# /* This indicates that all executable sections are compatible with
#    SHSTK.  */ 
GNU_PROPERTY_X86_FEATURE_1_SHSTK = (1 << 1)

# /* Move records.  */ 

# Kind: StructDecl
class Elf32_Move(Structure):
	_fields_ = [
		("m_value", c_ulong), # /* Symbol value.  */
		("m_info", c_uint), # /* Size and index.  */
		("m_poffset", c_uint), # /* Symbol offset.  */
		("m_repeat", c_ushort), # /* Repeat count.  */
		("m_stride", c_ushort)] # /* Stride info.  */


# Kind: StructDecl
class Elf64_Move(Structure):
	_fields_ = [
		("m_value", c_ulong), # /* Symbol value.  */
		("m_info", c_ulong), # /* Size and index.  */
		("m_poffset", c_ulong), # /* Symbol offset.  */
		("m_repeat", c_ushort), # /* Repeat count.  */
		("m_stride", c_ushort)] # /* Stride info.  */

# /* Macro to construct move records.  */
ELF32_M_SYM = lambda info:   ((info) >> 8) & 0xff
ELF32_M_SIZE = lambda info:  ((info) & 0xff)
ELF32_M_INFO = lambda sym, size: (((sym & 0xff) << 8) + (size & 0xff))

ELF64_M_SYM = lambda info:   ELF32_M_SYM (info)
ELF64_M_SIZE = lambda info:  ELF32_M_SIZE (info)
ELF64_M_INFO = lambda sym, size: ELF32_M_INFO (sym, size)

# /* Motorola 68k specific definitions.  */ 

# /* Values for Elf32_Ehdr.e_flags.  */ 
EF_CPU32 = 0x00810000

# /* m68k relocs.  */
R_68K_NONE = 0 # /* No reloc */
R_68K_32 = 1 # /* Direct 32 bit  */
R_68K_16 = 2 # /* Direct 16 bit  */
R_68K_8 = 3 # /* Direct 8 bit  */
R_68K_PC32 = 4 # /* PC relative 32 bit */
R_68K_PC16 = 5 # /* PC relative 16 bit */
R_68K_PC8 = 6 # /* PC relative 8 bit */
R_68K_GOT32 = 7 # /* 32 bit PC relative GOT entry */
R_68K_GOT16 = 8 # /* 16 bit PC relative GOT entry */
R_68K_GOT8 = 9 # /* 8 bit PC relative GOT entry */
R_68K_GOT32O = 10 # /* 32 bit GOT offset */
R_68K_GOT16O = 11 # /* 16 bit GOT offset */
R_68K_GOT8O = 12 # /* 8 bit GOT offset */
R_68K_PLT32 = 13 # /* 32 bit PC relative PLT address */
R_68K_PLT16 = 14 # /* 16 bit PC relative PLT address */
R_68K_PLT8 = 15 # /* 8 bit PC relative PLT address */
R_68K_PLT32O = 16 # /* 32 bit PLT offset */
R_68K_PLT16O = 17 # /* 16 bit PLT offset */
R_68K_PLT8O = 18 # /* 8 bit PLT offset */
R_68K_COPY = 19 # /* Copy symbol at runtime */
R_68K_GLOB_DAT = 20 # /* Create GOT entry */
R_68K_JMP_SLOT = 21 # /* Create PLT entry */
R_68K_RELATIVE = 22 # /* Adjust by program base */
R_68K_TLS_GD32 = 25 # /* 32 bit GOT offset for GD */
R_68K_TLS_GD16 = 26 # /* 16 bit GOT offset for GD */
R_68K_TLS_GD8 = 27 # /* 8 bit GOT offset for GD */
R_68K_TLS_LDM32 = 28 # /* 32 bit GOT offset for LDM */
R_68K_TLS_LDM16 = 29 # /* 16 bit GOT offset for LDM */
R_68K_TLS_LDM8 = 30 # /* 8 bit GOT offset for LDM */
R_68K_TLS_LDO32 = 31 # /* 32 bit module-relative offset */
R_68K_TLS_LDO16 = 32 # /* 16 bit module-relative offset */
R_68K_TLS_LDO8 = 33 # /* 8 bit module-relative offset */
R_68K_TLS_IE32 = 34 # /* 32 bit GOT offset for IE */
R_68K_TLS_IE16 = 35 # /* 16 bit GOT offset for IE */
R_68K_TLS_IE8 = 36 # /* 8 bit GOT offset for IE */
R_68K_TLS_LE32 = 37 # /* 32 bit offset relative to
#                        static TLS block */
R_68K_TLS_LE16 = 38 # /* 16 bit offset relative to
#                        static TLS block */
R_68K_TLS_LE8 = 39 # /* 8 bit offset relative to
#                        static TLS block */
R_68K_TLS_DTPMOD32 = 40 # /* 32 bit module number */
R_68K_TLS_DTPREL32 = 41 # /* 32 bit module-relative offset */
R_68K_TLS_TPREL32 = 42 # /* 32 bit TP-relative offset */

# /* Keep this the last entry.  */ 
R_68K_NUM = 43

# /* Intel 80386 specific definitions.  */

# /* i386 relocs.  */ 
R_386_NONE = 0 # /* No reloc */
R_386_32 = 1 # /* Direct 32 bit  */
R_386_PC32 = 2 # /* PC relative 32 bit */
R_386_GOT32 = 3 # /* 32 bit GOT entry */
R_386_PLT32 = 4 # /* 32 bit PLT address */
R_386_COPY = 5 # /* Copy symbol at runtime */
R_386_GLOB_DAT = 6 # /* Create GOT entry */
R_386_JMP_SLOT = 7 # /* Create PLT entry */
R_386_RELATIVE = 8 # /* Adjust by program base */
R_386_GOTOFF = 9 # /* 32 bit offset to GOT */
R_386_GOTPC = 10 # /* 32 bit PC relative offset to GOT */
R_386_32PLT = 11
R_386_TLS_TPOFF = 14 # /* Offset in static TLS block */
R_386_TLS_IE = 15 # /* Address of GOT entry for static TLS
#                        block offset */
R_386_TLS_GOTIE = 16 # /* GOT entry for static TLS block
#                        offset */
R_386_TLS_LE = 17 # /* Offset relative to static TLS
#                        block */
R_386_TLS_GD = 18 # /* Direct 32 bit for GNU version of
#                        general dynamic thread local data */
R_386_TLS_LDM = 19 # /* Direct 32 bit for GNU version of
#                        local dynamic thread local data
#                        in LE code */
R_386_16 = 20
R_386_PC16 = 21
R_386_8 = 22
R_386_PC8 = 23
R_386_TLS_GD_32 = 24 # /* Direct 32 bit for general dynamic
#                        thread local data */
R_386_TLS_GD_PUSH = 25 # /* Tag for pushl in GD TLS code */
R_386_TLS_GD_CALL = 26 # /* Relocation for call to
#                        __tls_get_addr() */
R_386_TLS_GD_POP = 27 # /* Tag for popl in GD TLS code */
R_386_TLS_LDM_32 = 28 # /* Direct 32 bit for local dynamic
#                        thread local data in LE code */
R_386_TLS_LDM_PUSH = 29 # /* Tag for pushl in LDM TLS code */
R_386_TLS_LDM_CALL = 30 # /* Relocation for call to
#                        __tls_get_addr() in LDM code */
R_386_TLS_LDM_POP = 31 # /* Tag for popl in LDM TLS code */
R_386_TLS_LDO_32 = 32 # /* Offset relative to TLS block */
R_386_TLS_IE_32 = 33 # /* GOT entry for negated static TLS
#                        block offset */
R_386_TLS_LE_32 = 34 # /* Negated offset relative to static
#                        TLS block */
R_386_TLS_DTPMOD32 = 35 # /* ID of module containing symbol */
R_386_TLS_DTPOFF32 = 36 # /* Offset in TLS block */
R_386_TLS_TPOFF32 = 37 # /* Negated offset in static TLS block */
R_386_SIZE32 = 38 # /* 32-bit symbol size */
R_386_TLS_GOTDESC = 39 # /* GOT offset for TLS descriptor.  */
R_386_TLS_DESC_CALL = 40 # /* Marker of call through TLS
#                        descriptor for
#                        relaxation.  */
R_386_TLS_DESC = 41 # /* TLS descriptor containing
#                        pointer to code and to
#                        argument, returning the TLS
#                        offset for the symbol.  */
R_386_IRELATIVE = 42 # /* Adjust indirectly by program base */
R_386_GOT32X = 43 # /* Load from 32 bit GOT entry,
#                        relaxable. */
# /* Keep this the last entry.  */ 
R_386_NUM = 44

# /* SUN SPARC specific definitions.  */

# /* Legal values for ST_TYPE subfield of st_info (symbol type).  */ 

STT_SPARC_REGISTER = 13 # /* Global register reserved to app. */

# /* Values for Elf64_Ehdr.e_flags.  */ 
EF_SPARCV9_MM = 3
EF_SPARCV9_TSO = 0
EF_SPARCV9_PSO = 1
EF_SPARCV9_RMO = 2
EF_SPARC_LEDATA = 0x800000 # /* little endian data */
EF_SPARC_EXT_MASK = 0xFFFF00
EF_SPARC_32PLUS = 0x000100 # /* generic V8+ features */
EF_SPARC_SUN_US1 = 0x000200 # /* Sun UltraSPARC1 extensions */
EF_SPARC_HAL_R1 = 0x000400 # /* HAL R1 extensions */
EF_SPARC_SUN_US3 = 0x000800 # /* Sun UltraSPARCIII extensions */

# /* SPARC relocs.  */ 
R_SPARC_NONE = 0 # /* No reloc */
R_SPARC_8 = 1 # /* Direct 8 bit */
R_SPARC_16 = 2 # /* Direct 16 bit */
R_SPARC_32 = 3 # /* Direct 32 bit */
R_SPARC_DISP8 = 4 # /* PC relative 8 bit */
R_SPARC_DISP16 = 5 # /* PC relative 16 bit */
R_SPARC_DISP32 = 6 # /* PC relative 32 bit */
R_SPARC_WDISP30 = 7 # /* PC relative 30 bit shifted */
R_SPARC_WDISP22 = 8 # /* PC relative 22 bit shifted */
R_SPARC_HI22 = 9 # /* High 22 bit */
R_SPARC_22 = 10 # /* Direct 22 bit */
R_SPARC_13 = 11 # /* Direct 13 bit */
R_SPARC_LO10 = 12 # /* Truncated 10 bit */
R_SPARC_GOT10 = 13 # /* Truncated 10 bit GOT entry */
R_SPARC_GOT13 = 14 # /* 13 bit GOT entry */
R_SPARC_GOT22 = 15 # /* 22 bit GOT entry shifted */
R_SPARC_PC10 = 16 # /* PC relative 10 bit truncated */
R_SPARC_PC22 = 17 # /* PC relative 22 bit shifted */
R_SPARC_WPLT30 = 18 # /* 30 bit PC relative PLT address */
R_SPARC_COPY = 19 # /* Copy symbol at runtime */
R_SPARC_GLOB_DAT = 20 # /* Create GOT entry */
R_SPARC_JMP_SLOT = 21 # /* Create PLT entry */
R_SPARC_RELATIVE = 22 # /* Adjust by program base */
R_SPARC_UA32 = 23 # /* Direct 32 bit unaligned */

# /* Additional Sparc64 relocs.  */ 
R_SPARC_PLT32 = 24 # /* Direct 32 bit ref to PLT entry */
R_SPARC_HIPLT22 = 25 # /* High 22 bit PLT entry */
R_SPARC_LOPLT10 = 26 # /* Truncated 10 bit PLT entry */
R_SPARC_PCPLT32 = 27 # /* PC rel 32 bit ref to PLT entry */
R_SPARC_PCPLT22 = 28 # /* PC rel high 22 bit PLT entry */
R_SPARC_PCPLT10 = 29 # /* PC rel trunc 10 bit PLT entry */
R_SPARC_10 = 30 # /* Direct 10 bit */
R_SPARC_11 = 31 # /* Direct 11 bit */
R_SPARC_64 = 32 # /* Direct 64 bit */
R_SPARC_OLO10 = 33 # /* 10bit with secondary 13bit addend */
R_SPARC_HH22 = 34 # /* Top 22 bits of direct 64 bit */
R_SPARC_HM10 = 35 # /* High middle 10 bits of ... */
R_SPARC_LM22 = 36 # /* Low middle 22 bits of ... */
R_SPARC_PC_HH22 = 37 # /* Top 22 bits of pc rel 64 bit */
R_SPARC_PC_HM10 = 38 # /* High middle 10 bit of ... */
R_SPARC_PC_LM22 = 39 # /* Low miggle 22 bits of ... */
R_SPARC_WDISP16 = 40 # /* PC relative 16 bit shifted */
R_SPARC_WDISP19 = 41 # /* PC relative 19 bit shifted */
R_SPARC_GLOB_JMP = 42 # /* was part of v9 ABI but was removed */
R_SPARC_7 = 43 # /* Direct 7 bit */
R_SPARC_5 = 44 # /* Direct 5 bit */
R_SPARC_6 = 45 # /* Direct 6 bit */
R_SPARC_DISP64 = 46 # /* PC relative 64 bit */
R_SPARC_PLT64 = 47 # /* Direct 64 bit ref to PLT entry */
R_SPARC_HIX22 = 48 # /* High 22 bit complemented */
R_SPARC_LOX10 = 49 # /* Truncated 11 bit complemented */
R_SPARC_H44 = 50 # /* Direct high 12 of 44 bit */
R_SPARC_M44 = 51 # /* Direct mid 22 of 44 bit */
R_SPARC_L44 = 52 # /* Direct low 10 of 44 bit */
R_SPARC_REGISTER = 53 # /* Global register usage */
R_SPARC_UA64 = 54 # /* Direct 64 bit unaligned */
R_SPARC_UA16 = 55 # /* Direct 16 bit unaligned */
R_SPARC_TLS_GD_HI22 = 56
R_SPARC_TLS_GD_LO10 = 57
R_SPARC_TLS_GD_ADD = 58
R_SPARC_TLS_GD_CALL = 59
R_SPARC_TLS_LDM_HI22 = 60
R_SPARC_TLS_LDM_LO10 = 61
R_SPARC_TLS_LDM_ADD = 62
R_SPARC_TLS_LDM_CALL = 63
R_SPARC_TLS_LDO_HIX22 = 64
R_SPARC_TLS_LDO_LOX10 = 65
R_SPARC_TLS_LDO_ADD = 66
R_SPARC_TLS_IE_HI22 = 67
R_SPARC_TLS_IE_LO10 = 68
R_SPARC_TLS_IE_LD = 69
R_SPARC_TLS_IE_LDX = 70
R_SPARC_TLS_IE_ADD = 71
R_SPARC_TLS_LE_HIX22 = 72
R_SPARC_TLS_LE_LOX10 = 73
R_SPARC_TLS_DTPMOD32 = 74
R_SPARC_TLS_DTPMOD64 = 75
R_SPARC_TLS_DTPOFF32 = 76
R_SPARC_TLS_DTPOFF64 = 77
R_SPARC_TLS_TPOFF32 = 78
R_SPARC_TLS_TPOFF64 = 79
R_SPARC_GOTDATA_HIX22 = 80
R_SPARC_GOTDATA_LOX10 = 81
R_SPARC_GOTDATA_OP_HIX22 = 82
R_SPARC_GOTDATA_OP_LOX10 = 83
R_SPARC_GOTDATA_OP = 84
R_SPARC_H34 = 85
R_SPARC_SIZE32 = 86
R_SPARC_SIZE64 = 87
R_SPARC_WDISP10 = 88
R_SPARC_JMP_IREL = 248
R_SPARC_IRELATIVE = 249
R_SPARC_GNU_VTINHERIT = 250
R_SPARC_GNU_VTENTRY = 251
R_SPARC_REV32 = 252
# /* Keep this the last entry.  */
R_SPARC_NUM = 253

# /* For Sparc64, legal values for d_tag of Elf64_Dyn.  */
DT_SPARC_REGISTER = 0x70000001
DT_SPARC_NUM = 2

# /* MIPS R3000 specific definitions.  */

# /* Legal values for e_flags field of Elf32_Ehdr.  */ 
EF_MIPS_NOREORDER = 1 # /* A .noreorder directive was used.  */
EF_MIPS_PIC = 2 # /* Contains PIC code.  */
EF_MIPS_CPIC = 4 # /* Uses PIC calling sequence.  */
EF_MIPS_XGOT = 8
EF_MIPS_64BIT_WHIRL = 16
EF_MIPS_ABI2 = 32
EF_MIPS_ABI_ON32 = 64
EF_MIPS_FP64 = 512 # /* Uses FP64 (12 callee-saved).  */
EF_MIPS_NAN2008 = 1024 # /* Uses IEEE 754-2008 NaN encoding.  */
EF_MIPS_ARCH = 0xf0000000 # /* MIPS architecture level.  */

# /* Legal values for MIPS architecture level.  */ 
EF_MIPS_ARCH_1 = 0x00000000 # /* -mips1 code.  */
EF_MIPS_ARCH_2 = 0x10000000 # /* -mips2 code.  */
EF_MIPS_ARCH_3 = 0x20000000 # /* -mips3 code.  */
EF_MIPS_ARCH_4 = 0x30000000 # /* -mips4 code.  */
EF_MIPS_ARCH_5 = 0x40000000 # /* -mips5 code.  */
EF_MIPS_ARCH_32 = 0x50000000 # /* MIPS32 code.  */
EF_MIPS_ARCH_64 = 0x60000000 # /* MIPS64 code.  */
EF_MIPS_ARCH_32R2 = 0x70000000 # /* MIPS32r2 code.  */
EF_MIPS_ARCH_64R2 = 0x80000000 # /* MIPS64r2 code.  */

# /* The following are unofficial names and should not be used.  */ 
E_MIPS_ARCH_1 = EF_MIPS_ARCH_1
E_MIPS_ARCH_2 = EF_MIPS_ARCH_2
E_MIPS_ARCH_3 = EF_MIPS_ARCH_3
E_MIPS_ARCH_4 = EF_MIPS_ARCH_4
E_MIPS_ARCH_5 = EF_MIPS_ARCH_5
E_MIPS_ARCH_32 = EF_MIPS_ARCH_32
E_MIPS_ARCH_64 = EF_MIPS_ARCH_64

# /* Special section indices.  */
SHN_MIPS_ACOMMON = 0xff00 # /* Allocated common symbols.  */
SHN_MIPS_TEXT = 0xff01 # /* Allocated test symbols.  */
SHN_MIPS_DATA = 0xff02 # /* Allocated data symbols.  */
SHN_MIPS_SCOMMON = 0xff03 # /* Small common symbols.  */
SHN_MIPS_SUNDEFINED = 0xff04 # /* Small undefined symbols.  */

# /* Legal values for sh_type field of Elf32_Shdr.  */ 
SHT_MIPS_LIBLIST = 0x70000000 # /* Shared objects used in link.  */
SHT_MIPS_MSYM = 0x70000001
SHT_MIPS_CONFLICT = 0x70000002 # /* Conflicting symbols.  */
SHT_MIPS_GPTAB = 0x70000003 # /* Global data area sizes.  */
SHT_MIPS_UCODE = 0x70000004 # /* Reserved for SGI/MIPS compilers */
SHT_MIPS_DEBUG = 0x70000005 # /* MIPS ECOFF debugging info.  */
SHT_MIPS_REGINFO = 0x70000006 # /* Register usage information.  */
SHT_MIPS_PACKAGE = 0x70000007
SHT_MIPS_PACKSYM = 0x70000008
SHT_MIPS_RELD = 0x70000009
SHT_MIPS_IFACE = 0x7000000b
SHT_MIPS_CONTENT = 0x7000000c
SHT_MIPS_OPTIONS = 0x7000000d # /* Miscellaneous options.  */
SHT_MIPS_SHDR = 0x70000010
SHT_MIPS_FDESC = 0x70000011
SHT_MIPS_EXTSYM = 0x70000012
SHT_MIPS_DENSE = 0x70000013
SHT_MIPS_PDESC = 0x70000014
SHT_MIPS_LOCSYM = 0x70000015
SHT_MIPS_AUXSYM = 0x70000016
SHT_MIPS_OPTSYM = 0x70000017
SHT_MIPS_LOCSTR = 0x70000018
SHT_MIPS_LINE = 0x70000019
SHT_MIPS_RFDESC = 0x7000001a
SHT_MIPS_DELTASYM = 0x7000001b
SHT_MIPS_DELTAINST = 0x7000001c
SHT_MIPS_DELTACLASS = 0x7000001d
SHT_MIPS_DWARF = 0x7000001e # /* DWARF debugging information.  */
SHT_MIPS_DELTADECL = 0x7000001f
SHT_MIPS_SYMBOL_LIB = 0x70000020
SHT_MIPS_EVENTS = 0x70000021 # /* Event section.  */
SHT_MIPS_TRANSLATE = 0x70000022
SHT_MIPS_PIXIE = 0x70000023
SHT_MIPS_XLATE = 0x70000024
SHT_MIPS_XLATE_DEBUG = 0x70000025
SHT_MIPS_WHIRL = 0x70000026
SHT_MIPS_EH_REGION = 0x70000027
SHT_MIPS_XLATE_OLD = 0x70000028
SHT_MIPS_PDR_EXCEPTION = 0x70000029
SHT_MIPS_XHASH = 0x7000002b

# /* Legal values for sh_flags field of Elf32_Shdr.  */
SHF_MIPS_GPREL = 0x10000000 # /* Must be in global data area.  */
SHF_MIPS_MERGE = 0x20000000
SHF_MIPS_ADDR = 0x40000000
SHF_MIPS_STRINGS = 0x80000000
SHF_MIPS_NOSTRIP = 0x08000000
SHF_MIPS_LOCAL = 0x04000000
SHF_MIPS_NAMES = 0x02000000
SHF_MIPS_NODUPE = 0x01000000

# /* Symbol tables.  */
# /* MIPS specific values for `st_other'.  */ 
STO_MIPS_DEFAULT = 0x0
STO_MIPS_INTERNAL = 0x1
STO_MIPS_HIDDEN = 0x2
STO_MIPS_PROTECTED = 0x3
STO_MIPS_PLT = 0x8
STO_MIPS_SC_ALIGN_UNUSED = 0xff

# /* MIPS specific values for `st_info'.  */
STB_MIPS_SPLIT_COMMON = 13

# /* Entries found in sections of type SHT_MIPS_GPTAB.  */

# Kind: StructDecl
class Elf32_gptab_Anon1(Structure):
	_fields_ = [
		("gt_current_g_value", c_uint), # /* -G value used for compilation.  */ 
		("gt_unused", c_uint)] # /* Not used.  */ 

# Kind: StructDecl
class Elf32_gptab_Anon2(Structure):
	_fields_ = [
		("gt_g_value", c_uint), # /* If this value were used for -G.  */ 
		("gt_bytes", c_uint)] # /* This many bytes would be used.  */ 

# Kind: UnionDecl
class Elf32_gptab(Union):
	_fields_ = [
		("gt_header", Elf32_gptab_Anon1), # /* First entry in section.  */ 
		("gt_entry", Elf32_gptab_Anon2)] # /* Subsequent entries in section.  */ 

# /* Entry found in sections of type SHT_MIPS_REGINFO.  */ 

# Kind: StructDecl
class Elf32_RegInfo(Structure):
	_fields_ = [
		("ri_gprmask", c_uint), # /* General registers used.  */ 
		("ri_cprmask", c_uint * 4), # /* Coprocessor registers used.  */ 
		("ri_gp_value", c_int)] # /* $gp register value.  */ 

# /* Entries found in sections of type SHT_MIPS_OPTIONS.  */ 

# Kind: StructDecl
class Elf_Options(Structure):
	_fields_ = [
		("kind", c_ubyte), # /* Determines interpretation of the
                           # variable part of descriptor.  */ 
		("size", c_ubyte), # /* Size of descriptor, including header.  */ 
		("section", c_ushort), # /* Section header index of section affected,
                               # 0 for global options.  */ 
		("info", c_uint)] # /* Kind-specific information.  */ 

# /* Values for `kind' field in Elf_Options.  */ 
ODK_NULL = 0 # /* Undefined.  */
ODK_REGINFO = 1 # /* Register usage information.  */
ODK_EXCEPTIONS = 2 # /* Exception processing options.  */
ODK_PAD = 3 # /* Section padding options.  */
ODK_HWPATCH = 4 # /* Hardware workarounds performed */
ODK_FILL = 5 # /* record the fill value used by the linker. */
ODK_TAGS = 6 # /* reserve space for desktop tools to write. */
ODK_HWAND = 7 # /* HW workarounds.  'AND' bits when merging. */
ODK_HWOR = 8 # /* HW workarounds.  'OR' bits when merging.  */

# /* Values for `info' in Elf_Options for ODK_EXCEPTIONS entries.  */ 
OEX_FPU_MIN = 0x1f # /* FPE's which MUST be enabled.  */
OEX_FPU_MAX = 0x1f00 # /* FPE's which MAY be enabled.  */
OEX_PAGE0 = 0x10000 # /* page zero must be mapped.  */
OEX_SMM = 0x20000 # /* Force sequential memory mode?  */
OEX_FPDBUG = 0x40000 # /* Force floating point debug mode?  */
OEX_PRECISEFP = OEX_FPDBUG
OEX_DISMISS = 0x80000 # /* Dismiss invalid address faults?  */

OEX_FPU_INVAL = 0x10
OEX_FPU_DIV0 = 0x08
OEX_FPU_OFLO = 0x04
OEX_FPU_UFLO = 0x02
OEX_FPU_INEX = 0x01

# /* Masks for `info' in Elf_Options for an ODK_HWPATCH entry.  */
OHW_R4KEOP = 0x1 # /* R4000 end-of-page patch.  */
OHW_R8KPFETCH = 0x2 # /* may need R8000 prefetch patch.  */
OHW_R5KEOP = 0x4 # /* R5000 end-of-page patch.  */
OHW_R5KCVTL = 0x8 # /* R5000 cvt.[ds].l bug.  clean=1.  */

OPAD_PREFIX = 0x1
OPAD_POSTFIX = 0x2
OPAD_SYMBOL = 0x4

# /* Entry found in `.options' section.  */


# Kind: StructDecl
class Elf_Options_Hw(Structure):
	_fields_ = [
		("hwp_flags1", c_uint), # /* Extra flags.  */ 
		("hwp_flags2", c_uint)] # /* Extra flags.  */ 



# /* Masks for `info' in ElfOptions for ODK_HWAND and ODK_HWOR entries.  */ 
OHWA0_R4KEOP_CHECKED = 0x00000001
OHWA1_R4KEOP_CLEAN = 0x00000002 # /* MIPS relocs.  */
R_MIPS_NONE = 0 # /* No reloc */
R_MIPS_16 = 1 # /* Direct 16 bit */
R_MIPS_32 = 2 # /* Direct 32 bit */
R_MIPS_REL32 = 3 # /* PC relative 32 bit */
R_MIPS_26 = 4 # /* Direct 26 bit shifted */
R_MIPS_HI16 = 5 # /* High 16 bit */
R_MIPS_LO16 = 6 # /* Low 16 bit */
R_MIPS_GPREL16 = 7 # /* GP relative 16 bit */
R_MIPS_LITERAL = 8 # /* 16 bit literal entry */
R_MIPS_GOT16 = 9 # /* 16 bit GOT entry */
R_MIPS_PC16 = 10 # /* PC relative 16 bit */
R_MIPS_CALL16 = 11 # /* 16 bit GOT entry for function */
R_MIPS_GPREL32 = 12 # /* GP relative 32 bit */
R_MIPS_SHIFT5 = 16
R_MIPS_SHIFT6 = 17
R_MIPS_64 = 18
R_MIPS_GOT_DISP = 19
R_MIPS_GOT_PAGE = 20
R_MIPS_GOT_OFST = 21
R_MIPS_GOT_HI16 = 22
R_MIPS_GOT_LO16 = 23
R_MIPS_SUB = 24
R_MIPS_INSERT_A = 25
R_MIPS_INSERT_B = 26
R_MIPS_DELETE = 27
R_MIPS_HIGHER = 28
R_MIPS_HIGHEST = 29
R_MIPS_CALL_HI16 = 30
R_MIPS_CALL_LO16 = 31
R_MIPS_SCN_DISP = 32
R_MIPS_REL16 = 33
R_MIPS_ADD_IMMEDIATE = 34
R_MIPS_PJUMP = 35
R_MIPS_RELGOT = 36
R_MIPS_JALR = 37
R_MIPS_TLS_DTPMOD32 = 38 # /* Module number 32 bit */
R_MIPS_TLS_DTPREL32 = 39 # /* Module-relative offset 32 bit */
R_MIPS_TLS_DTPMOD64 = 40 # /* Module number 64 bit */
R_MIPS_TLS_DTPREL64 = 41 # /* Module-relative offset 64 bit */
R_MIPS_TLS_GD = 42 # /* 16 bit GOT offset for GD */
R_MIPS_TLS_LDM = 43 # /* 16 bit GOT offset for LDM */
R_MIPS_TLS_DTPREL_HI16 = 44 # /* Module-relative offset, high 16 bits */
R_MIPS_TLS_DTPREL_LO16 = 45 # /* Module-relative offset, low 16 bits */
R_MIPS_TLS_GOTTPREL = 46 # /* 16 bit GOT offset for IE */
R_MIPS_TLS_TPREL32 = 47 # /* TP-relative offset, 32 bit */
R_MIPS_TLS_TPREL64 = 48 # /* TP-relative offset, 64 bit */
R_MIPS_TLS_TPREL_HI16 = 49 # /* TP-relative offset, high 16 bits */
R_MIPS_TLS_TPREL_LO16 = 50 # /* TP-relative offset, low 16 bits */
R_MIPS_GLOB_DAT = 51
R_MIPS_COPY = 126
R_MIPS_JUMP_SLOT = 127
# /* Keep this the last entry.  */
R_MIPS_NUM = 128

# /* Legal values for p_type field of Elf32_Phdr.  */
PT_MIPS_REGINFO = 0x70000000 # /* Register usage information. */
PT_MIPS_RTPROC = 0x70000001 # /* Runtime procedure table. */
PT_MIPS_OPTIONS = 0x70000002
PT_MIPS_ABIFLAGS = 0x70000003 # /* FP mode requirement. */

# /* Special program header types.  */ 
PF_MIPS_LOCAL = 0x10000000

# /* Legal values for DT_MIPS_FLAGS Elf32_Dyn entry.  */
RHF_NONE = 0 # /* No flags */
RHF_QUICKSTART = (1 << 0) # /* Use quickstart */ 
RHF_NOTPOT = (1 << 1) # /* Hash size not power of 2 */ 
RHF_NO_LIBRARY_REPLACEMENT = (1 << 2) # /* Ignore LD_LIBRARY_PATH */ 
RHF_NO_MOVE = (1 << 3)
RHF_SGI_ONLY = (1 << 4)
RHF_GUARANTEE_INIT = (1 << 5)
RHF_DELTA_C_PLUS_PLUS = (1 << 6)
RHF_GUARANTEE_START_INIT = (1 << 7)
RHF_PIXIE = (1 << 8)
RHF_DEFAULT_DELAY_LOAD = (1 << 9)
RHF_REQUICKSTART = (1 << 10)
RHF_REQUICKSTARTED = (1 << 11)
RHF_CORD = (1 << 12)
RHF_NO_UNRES_UNDEF = (1 << 13)
RHF_RLD_ORDER_SAFE = (1 << 14)

# /* Entries found in sections of type SHT_MIPS_LIBLIST.  */ 

# Kind: StructDecl
class Elf32_Lib(Structure):
	_fields_ = [
		("l_name", c_uint), # /* Name (string table index) */ 
		("l_time_stamp", c_uint), # /* Timestamp */ 
		("l_checksum", c_uint), # /* Checksum */ 
		("l_version", c_uint), # /* Interface version */ 
		("l_flags", c_uint)] # /* Flags */ 


# Kind: StructDecl
class Elf64_Lib(Structure):
	_fields_ = [
		("l_name", c_uint), # /* Name (string table index) */ 
		("l_time_stamp", c_uint), # /* Timestamp */ 
		("l_checksum", c_uint), # /* Checksum */ 
		("l_version", c_uint), # /* Interface version */ 
		("l_flags", c_uint)] # /* Flags */ 

# /* Legal values for l_flags.  */ 
LL_NONE = 0
LL_EXACT_MATCH = (1 << 0) # /* Require exact match */ 
LL_IGNORE_INT_VER = (1 << 1) # /* Ignore interface version */ 
LL_REQUIRE_MINOR = (1 << 2)
LL_EXPORTS = (1 << 3)
LL_DELAY_LOAD = (1 << 4)
LL_DELTA = (1 << 5)

# /* Entries found in sections of type SHT_MIPS_CONFLICT.  */ 

# Kind: StructDecl
class Elf_MIPS_ABIFlags_v0(Structure):
	_fields_ = [
		("version", c_ushort), # /* Version of flags structure.  */ 
		("isa_level", c_ubyte), # /* The level of the ISA: 1-5, 32, 64.  */ 
		("isa_rev", c_ubyte), # /* The revision of ISA: 0 for MIPS V and below, 1-n otherwise.  */ 
		("gpr_size", c_ubyte), # /* The size of general purpose registers.  */ 
		("cpr1_size", c_ubyte), # /* The size of co-processor 1 registers.  */ 
		("cpr2_size", c_ubyte), # /* The size of co-processor 2 registers.  */ 
		("fp_abi", c_ubyte), # /* The floating-point ABI.  */ 
		("isa_ext", c_uint), # /* Processor-specific extension.  */ 
		("ases", c_uint), # /* Mask of ASEs used.  */ 
		("flags1", c_uint), # /* Mask of general flags.  */ 
		("flags2", c_uint)]

# /* Values for the register size bytes of an abi flags structure.  */ 
MIPS_AFL_REG_NONE = 0x00 # /* No registers.  */
MIPS_AFL_REG_32 = 0x01 # /* 32-bit registers.  */
MIPS_AFL_REG_64 = 0x02 # /* 64-bit registers.  */
MIPS_AFL_REG_128 = 0x03 # /* 128-bit registers.  */

# /* Masks for the ases word of an ABI flags structure.  */ 
MIPS_AFL_ASE_DSP = 0x00000001 # /* DSP ASE.  */
MIPS_AFL_ASE_DSPR2 = 0x00000002 # /* DSP R2 ASE.  */
MIPS_AFL_ASE_EVA = 0x00000004 # /* Enhanced VA Scheme.  */
MIPS_AFL_ASE_MCU = 0x00000008 # /* MCU (MicroController) ASE.  */
MIPS_AFL_ASE_MDMX = 0x00000010 # /* MDMX ASE.  */
MIPS_AFL_ASE_MIPS3D = 0x00000020 # /* MIPS-3D ASE.  */
MIPS_AFL_ASE_MT = 0x00000040 # /* MT ASE.  */
MIPS_AFL_ASE_SMARTMIPS = 0x00000080 # /* SmartMIPS ASE.  */
MIPS_AFL_ASE_VIRT = 0x00000100 # /* VZ ASE.  */
MIPS_AFL_ASE_MSA = 0x00000200 # /* MSA ASE.  */
MIPS_AFL_ASE_MIPS16 = 0x00000400 # /* MIPS16 ASE.  */
MIPS_AFL_ASE_MICROMIPS = 0x00000800 # /* MICROMIPS ASE.  */
MIPS_AFL_ASE_XPA = 0x00001000 # /* XPA ASE.  */
MIPS_AFL_ASE_MASK = 0x00001fff # /* All ASEs.  */

# /* Values for the isa_ext word of an ABI flags structure.  */ 
MIPS_AFL_EXT_XLR = 1 # /* RMI Xlr instruction.  */
MIPS_AFL_EXT_OCTEON2 = 2 # /* Cavium Networks Octeon2.  */
MIPS_AFL_EXT_OCTEONP = 3 # /* Cavium Networks OcteonP.  */
MIPS_AFL_EXT_LOONGSON_3A = 4 # /* Loongson 3A.  */
MIPS_AFL_EXT_OCTEON = 5 # /* Cavium Networks Octeon.  */
MIPS_AFL_EXT_5900 = 6 # /* MIPS R5900 instruction.  */
MIPS_AFL_EXT_4650 = 7 # /* MIPS R4650 instruction.  */
MIPS_AFL_EXT_4010 = 8 # /* LSI R4010 instruction.  */
MIPS_AFL_EXT_4100 = 9 # /* NEC VR4100 instruction.  */
MIPS_AFL_EXT_3900 = 10 # /* Toshiba R3900 instruction.  */
MIPS_AFL_EXT_10000 = 11 # /* MIPS R10000 instruction.  */
MIPS_AFL_EXT_SB1 = 12 # /* Broadcom SB-1 instruction.  */
MIPS_AFL_EXT_4111 = 13 # /* NEC VR4111/VR4181 instruction.  */
MIPS_AFL_EXT_4120 = 14 # /* NEC VR4120 instruction.  */
MIPS_AFL_EXT_5400 = 15 # /* NEC VR5400 instruction.  */
MIPS_AFL_EXT_5500 = 16 # /* NEC VR5500 instruction.  */
MIPS_AFL_EXT_LOONGSON_2E = 17 # /* ST Microelectronics Loongson 2E.  */
MIPS_AFL_EXT_LOONGSON_2F = 18 # /* ST Microelectronics Loongson 2F.  */

# /* Masks for the flags1 word of an ABI flags structure.  */ 
MIPS_AFL_FLAGS1_ODDSPREG = 1 # /* Uses odd single-precision registers.  */

# /* Object attribute values.  */ 

# /* Not tagged or not using any ABIs affected by the differences.  */
Val_GNU_MIPS_ABI_FP_ANY = 0,
# /* Using hard-float -mdouble-float.  */
Val_GNU_MIPS_ABI_FP_DOUBLE = 1,
# /* Using hard-float -msingle-float.  */
Val_GNU_MIPS_ABI_FP_SINGLE = 2,
# /* Using soft-float.  */
Val_GNU_MIPS_ABI_FP_SOFT = 3,
# /* Using -mips32r2 -mfp64.  */
Val_GNU_MIPS_ABI_FP_OLD_64 = 4,
# /* Using -mfpxx.  */
Val_GNU_MIPS_ABI_FP_XX = 5,
# /* Using -mips32r2 -mfp64.  */
Val_GNU_MIPS_ABI_FP_64 = 6,
# /* Using -mips32r2 -mfp64 -mno-odd-spreg.  */
Val_GNU_MIPS_ABI_FP_64A = 7,
# /* Maximum allocated FP ABI value.  */
Val_GNU_MIPS_ABI_FP_MAX = 7

# /* Maximum allocated FP ABI value.  */ 
# /* HPPA specific definitions.  */ 
# /* Legal values for e_flags field of Elf32_Ehdr.  */ 
EF_PARISC_TRAPNIL = 0x00010000 # /* Trap nil pointer dereference.  */
EF_PARISC_EXT = 0x00020000 # /* Program uses arch. extensions. */
EF_PARISC_LSB = 0x00040000 # /* Program expects little endian. */
EF_PARISC_WIDE = 0x00080000 # /* Program expects wide mode.  */
EF_PARISC_NO_KABP = 0x00100000 # /* No kernel assisted branch
#                           prediction.  */
EF_PARISC_LAZYSWAP = 0x00400000 # /* Allow lazy swapping.  */
EF_PARISC_ARCH = 0x0000ffff # /* Architecture version.  */
# /* Defined values for `e_flags & EF_PARISC_ARCH' are:  */ 

EFA_PARISC_1_0 = 0x020b # /* PA-RISC 1.0 big-endian.  */
EFA_PARISC_1_1 = 0x0210 # /* PA-RISC 1.1 big-endian.  */
EFA_PARISC_2_0 = 0x0214 # /* PA-RISC 2.0 big-endian.  */

# /* Additional section indices.  */ 
SHN_PARISC_ANSI_COMMON = 0xff00 # /* Section for tentatively declared
#                           symbols in ANSI C.  */
SHN_PARISC_HUGE_COMMON = 0xff01 # /* Common blocks in huge model.  */

# /* Legal values for sh_type field of Elf32_Shdr.  */ 
SHT_PARISC_EXT = 0x70000000 # /* Contains product specific ext. */
SHT_PARISC_UNWIND = 0x70000001 # /* Unwind information.  */
SHT_PARISC_DOC = 0x70000002 # /* Debug info for optimized code. */

# /* Legal values for sh_flags field of Elf32_Shdr.  */ 
SHF_PARISC_SHORT = 0x20000000 # /* Section with short addressing. */
SHF_PARISC_HUGE = 0x40000000 # /* Section far from gp.  */
SHF_PARISC_SBP = 0x80000000 # /* Static branch prediction code. */

# /* Legal values for ST_TYPE subfield of st_info (symbol type).  */ 
STT_PARISC_MILLICODE = 13 # /* Millicode function entry point.  */
STT_HP_OPAQUE = (STT_LOOS + 0x1)
STT_HP_STUB = (STT_LOOS + 0x2)

# /* HPPA relocs.  */ 
R_PARISC_NONE = 0 # /* No reloc.  */
R_PARISC_DIR32 = 1 # /* Direct 32-bit reference.  */
R_PARISC_DIR21L = 2 # /* Left 21 bits of eff. address.  */
R_PARISC_DIR17R = 3 # /* Right 17 bits of eff. address.  */
R_PARISC_DIR17F = 4 # /* 17 bits of eff. address.  */
R_PARISC_DIR14R = 6 # /* Right 14 bits of eff. address.  */
R_PARISC_PCREL32 = 9 # /* 32-bit rel. address.  */
R_PARISC_PCREL21L = 10 # /* Left 21 bits of rel. address.  */
R_PARISC_PCREL17R = 11 # /* Right 17 bits of rel. address.  */
R_PARISC_PCREL17F = 12 # /* 17 bits of rel. address.  */
R_PARISC_PCREL14R = 14 # /* Right 14 bits of rel. address.  */
R_PARISC_DPREL21L = 18 # /* Left 21 bits of rel. address.  */
R_PARISC_DPREL14R = 22 # /* Right 14 bits of rel. address.  */
R_PARISC_GPREL21L = 26 # /* GP-relative, left 21 bits.  */
R_PARISC_GPREL14R = 30 # /* GP-relative, right 14 bits.  */
R_PARISC_LTOFF21L = 34 # /* LT-relative, left 21 bits.  */
R_PARISC_LTOFF14R = 38 # /* LT-relative, right 14 bits.  */
R_PARISC_SECREL32 = 41 # /* 32 bits section rel. address.  */
R_PARISC_SEGBASE = 48 # /* No relocation, set segment base.  */
R_PARISC_SEGREL32 = 49 # /* 32 bits segment rel. address.  */
R_PARISC_PLTOFF21L = 50 # /* PLT rel. address, left 21 bits.  */
R_PARISC_PLTOFF14R = 54 # /* PLT rel. address, right 14 bits.  */
R_PARISC_LTOFF_FPTR32 = 57 # /* 32 bits LT-rel. function pointer. */
R_PARISC_LTOFF_FPTR21L = 58 # /* LT-rel. fct ptr, left 21 bits. */
R_PARISC_LTOFF_FPTR14R = 62 # /* LT-rel. fct ptr, right 14 bits. */
R_PARISC_FPTR64 = 64 # /* 64 bits function address.  */
R_PARISC_PLABEL32 = 65 # /* 32 bits function address.  */
R_PARISC_PLABEL21L = 66 # /* Left 21 bits of fdesc address.  */
R_PARISC_PLABEL14R = 70 # /* Right 14 bits of fdesc address.  */
R_PARISC_PCREL64 = 72 # /* 64 bits PC-rel. address.  */
R_PARISC_PCREL22F = 74 # /* 22 bits PC-rel. address.  */
R_PARISC_PCREL14WR = 75 # /* PC-rel. address, right 14 bits.  */
R_PARISC_PCREL14DR = 76 # /* PC rel. address, right 14 bits.  */
R_PARISC_PCREL16F = 77 # /* 16 bits PC-rel. address.  */
R_PARISC_PCREL16WF = 78 # /* 16 bits PC-rel. address.  */
R_PARISC_PCREL16DF = 79 # /* 16 bits PC-rel. address.  */
R_PARISC_DIR64 = 80 # /* 64 bits of eff. address.  */
R_PARISC_DIR14WR = 83 # /* 14 bits of eff. address.  */
R_PARISC_DIR14DR = 84 # /* 14 bits of eff. address.  */
R_PARISC_DIR16F = 85 # /* 16 bits of eff. address.  */
R_PARISC_DIR16WF = 86 # /* 16 bits of eff. address.  */
R_PARISC_DIR16DF = 87 # /* 16 bits of eff. address.  */
R_PARISC_GPREL64 = 88 # /* 64 bits of GP-rel. address.  */
R_PARISC_GPREL14WR = 91 # /* GP-rel. address, right 14 bits.  */
R_PARISC_GPREL14DR = 92 # /* GP-rel. address, right 14 bits.  */
R_PARISC_GPREL16F = 93 # /* 16 bits GP-rel. address.  */
R_PARISC_GPREL16WF = 94 # /* 16 bits GP-rel. address.  */
R_PARISC_GPREL16DF = 95 # /* 16 bits GP-rel. address.  */
R_PARISC_LTOFF64 = 96 # /* 64 bits LT-rel. address.  */
R_PARISC_LTOFF14WR = 99 # /* LT-rel. address, right 14 bits.  */
R_PARISC_LTOFF14DR = 100 # /* LT-rel. address, right 14 bits.  */
R_PARISC_LTOFF16F = 101 # /* 16 bits LT-rel. address.  */
R_PARISC_LTOFF16WF = 102 # /* 16 bits LT-rel. address.  */
R_PARISC_LTOFF16DF = 103 # /* 16 bits LT-rel. address.  */
R_PARISC_SECREL64 = 104 # /* 64 bits section rel. address.  */
R_PARISC_SEGREL64 = 112 # /* 64 bits segment rel. address.  */
R_PARISC_PLTOFF14WR = 115 # /* PLT-rel. address, right 14 bits.  */
R_PARISC_PLTOFF14DR = 116 # /* PLT-rel. address, right 14 bits.  */
R_PARISC_PLTOFF16F = 117 # /* 16 bits LT-rel. address.  */
R_PARISC_PLTOFF16WF = 118 # /* 16 bits PLT-rel. address.  */
R_PARISC_PLTOFF16DF = 119 # /* 16 bits PLT-rel. address.  */
R_PARISC_LTOFF_FPTR64 = 120 # /* 64 bits LT-rel. function ptr.  */
R_PARISC_LTOFF_FPTR14WR = 123 # /* LT-rel. fct. ptr., right 14 bits. */
R_PARISC_LTOFF_FPTR14DR = 124 # /* LT-rel. fct. ptr., right 14 bits. */
R_PARISC_LTOFF_FPTR16F = 125 # /* 16 bits LT-rel. function ptr.  */
R_PARISC_LTOFF_FPTR16WF = 126 # /* 16 bits LT-rel. function ptr.  */
R_PARISC_LTOFF_FPTR16DF = 127 # /* 16 bits LT-rel. function ptr.  */
R_PARISC_LORESERVE = 128
R_PARISC_COPY = 128 # /* Copy relocation.  */
R_PARISC_IPLT = 129 # /* Dynamic reloc, imported PLT */
R_PARISC_EPLT = 130 # /* Dynamic reloc, exported PLT */
R_PARISC_TPREL32 = 153 # /* 32 bits TP-rel. address.  */
R_PARISC_TPREL21L = 154 # /* TP-rel. address, left 21 bits.  */
R_PARISC_TPREL14R = 158 # /* TP-rel. address, right 14 bits.  */
R_PARISC_LTOFF_TP21L = 162 # /* LT-TP-rel. address, left 21 bits. */
R_PARISC_LTOFF_TP14R = 166 # /* LT-TP-rel. address, right 14 bits.*/
R_PARISC_LTOFF_TP14F = 167 # /* 14 bits LT-TP-rel. address.  */
R_PARISC_TPREL64 = 216 # /* 64 bits TP-rel. address.  */
R_PARISC_TPREL14WR = 219 # /* TP-rel. address, right 14 bits.  */
R_PARISC_TPREL14DR = 220 # /* TP-rel. address, right 14 bits.  */
R_PARISC_TPREL16F = 221 # /* 16 bits TP-rel. address.  */
R_PARISC_TPREL16WF = 222 # /* 16 bits TP-rel. address.  */
R_PARISC_TPREL16DF = 223 # /* 16 bits TP-rel. address.  */
R_PARISC_LTOFF_TP64 = 224 # /* 64 bits LT-TP-rel. address.  */
R_PARISC_LTOFF_TP14WR = 227 # /* LT-TP-rel. address, right 14 bits.*/
R_PARISC_LTOFF_TP14DR = 228 # /* LT-TP-rel. address, right 14 bits.*/
R_PARISC_LTOFF_TP16F = 229 # /* 16 bits LT-TP-rel. address.  */
R_PARISC_LTOFF_TP16WF = 230 # /* 16 bits LT-TP-rel. address.  */
R_PARISC_LTOFF_TP16DF = 231 # /* 16 bits LT-TP-rel. address.  */
R_PARISC_GNU_VTENTRY = 232
R_PARISC_GNU_VTINHERIT = 233
R_PARISC_TLS_GD21L = 234 # /* GD 21-bit left.  */
R_PARISC_TLS_GD14R = 235 # /* GD 14-bit right.  */
R_PARISC_TLS_GDCALL = 236 # /* GD call to __t_g_a.  */
R_PARISC_TLS_LDM21L = 237 # /* LD module 21-bit left.  */
R_PARISC_TLS_LDM14R = 238 # /* LD module 14-bit right.  */
R_PARISC_TLS_LDMCALL = 239 # /* LD module call to __t_g_a.  */
R_PARISC_TLS_LDO21L = 240 # /* LD offset 21-bit left.  */
R_PARISC_TLS_LDO14R = 241 # /* LD offset 14-bit right.  */
R_PARISC_TLS_DTPMOD32 = 242 # /* DTP module 32-bit.  */
R_PARISC_TLS_DTPMOD64 = 243 # /* DTP module 64-bit.  */
R_PARISC_TLS_DTPOFF32 = 244 # /* DTP offset 32-bit.  */
R_PARISC_TLS_DTPOFF64 = 245 # /* DTP offset 32-bit.  */
R_PARISC_TLS_LE21L = R_PARISC_TPREL21L
R_PARISC_TLS_LE14R = R_PARISC_TPREL14R
R_PARISC_TLS_IE21L = R_PARISC_LTOFF_TP21L
R_PARISC_TLS_IE14R = R_PARISC_LTOFF_TP14R
R_PARISC_TLS_TPREL32 = R_PARISC_TPREL32
R_PARISC_TLS_TPREL64 = R_PARISC_TPREL64
R_PARISC_HIRESERVE = 255

# /* Legal values for p_type field of Elf32_Phdr/Elf64_Phdr.  */
PT_HP_TLS = (PT_LOOS + 0x0)
PT_HP_CORE_NONE = (PT_LOOS + 0x1)
PT_HP_CORE_VERSION = (PT_LOOS + 0x2)
PT_HP_CORE_KERNEL = (PT_LOOS + 0x3)
PT_HP_CORE_COMM = (PT_LOOS + 0x4)
PT_HP_CORE_PROC = (PT_LOOS + 0x5)
PT_HP_CORE_LOADABLE = (PT_LOOS + 0x6)
PT_HP_CORE_STACK = (PT_LOOS + 0x7)
PT_HP_CORE_SHM = (PT_LOOS + 0x8)
PT_HP_CORE_MMF = (PT_LOOS + 0x9)
PT_HP_PARALLEL = (PT_LOOS + 0x10)
PT_HP_FASTBIND = (PT_LOOS + 0x11)
PT_HP_OPT_ANNOT = (PT_LOOS + 0x12)
PT_HP_HSL_ANNOT = (PT_LOOS + 0x13)
PT_HP_STACK = (PT_LOOS + 0x14)

PT_PARISC_ARCHEXT = 0x70000000
PT_PARISC_UNWIND = 0x70000001

# /* Legal values for p_flags field of Elf32_Phdr/Elf64_Phdr.  */
PF_PARISC_SBP = 0x08000000

PF_HP_PAGE_SIZE = 0x00100000
PF_HP_FAR_SHARED = 0x00200000
PF_HP_NEAR_SHARED = 0x00400000
PF_HP_CODE = 0x01000000
PF_HP_MODIFY = 0x02000000
PF_HP_LAZYSWAP = 0x04000000
PF_HP_SBP = 0x08000000

# /* Alpha specific definitions.  */
# /* Legal values for e_flags field of Elf64_Ehdr.  */ 
EF_ALPHA_32BIT = 1 # /* All addresses must be < 2GB.  */
EF_ALPHA_CANRELAX = 2 # /* Relocations for relaxing exist.  */

# /* Legal values for sh_type field of Elf64_Shdr.  */ 
# /* These two are primerily concerned with ECOFF debugging info.  */ 
SHT_ALPHA_DEBUG = 0x70000001
SHT_ALPHA_REGINFO = 0x70000002

# /* Legal values for sh_flags field of Elf64_Shdr.  */
SHF_ALPHA_GPREL = 0x10000000

# /* Legal values for st_other field of Elf64_Sym.  */
STO_ALPHA_NOPV = 0x80 # /* No PV required.  */
STO_ALPHA_STD_GPLOAD = 0x88 # /* PV only used for initial ldgp.  */

# /* Alpha relocs.  */ 
R_ALPHA_NONE = 0 # /* No reloc */
R_ALPHA_REFLONG = 1 # /* Direct 32 bit */
R_ALPHA_REFQUAD = 2 # /* Direct 64 bit */
R_ALPHA_GPREL32 = 3 # /* GP relative 32 bit */
R_ALPHA_LITERAL = 4 # /* GP relative 16 bit w/optimization */
R_ALPHA_LITUSE = 5 # /* Optimization hint for LITERAL */
R_ALPHA_GPDISP = 6 # /* Add displacement to GP */
R_ALPHA_BRADDR = 7 # /* PC+4 relative 23 bit shifted */
R_ALPHA_HINT = 8 # /* PC+4 relative 16 bit shifted */
R_ALPHA_SREL16 = 9 # /* PC relative 16 bit */
R_ALPHA_SREL32 = 10 # /* PC relative 32 bit */
R_ALPHA_SREL64 = 11 # /* PC relative 64 bit */
R_ALPHA_GPRELHIGH = 17 # /* GP relative 32 bit, high 16 bits */
R_ALPHA_GPRELLOW = 18 # /* GP relative 32 bit, low 16 bits */
R_ALPHA_GPREL16 = 19 # /* GP relative 16 bit */
R_ALPHA_COPY = 24 # /* Copy symbol at runtime */
R_ALPHA_GLOB_DAT = 25 # /* Create GOT entry */
R_ALPHA_JMP_SLOT = 26 # /* Create PLT entry */
R_ALPHA_RELATIVE = 27 # /* Adjust by program base */
R_ALPHA_TLS_GD_HI = 28
R_ALPHA_TLSGD = 29
R_ALPHA_TLS_LDM = 30
R_ALPHA_DTPMOD64 = 31
R_ALPHA_GOTDTPREL = 32
R_ALPHA_DTPREL64 = 33
R_ALPHA_DTPRELHI = 34
R_ALPHA_DTPRELLO = 35
R_ALPHA_DTPREL16 = 36
R_ALPHA_GOTTPREL = 37
R_ALPHA_TPREL64 = 38
R_ALPHA_TPRELHI = 39
R_ALPHA_TPRELLO = 40
R_ALPHA_TPREL16 = 41
# /* Keep this the last entry.  */
R_ALPHA_NUM = 46

# /* Magic values of the LITUSE relocation addend.  */
LITUSE_ALPHA_ADDR = 0
LITUSE_ALPHA_BASE = 1
LITUSE_ALPHA_BYTOFF = 2
LITUSE_ALPHA_JSR = 3
LITUSE_ALPHA_TLS_GD = 4
LITUSE_ALPHA_TLS_LDM = 5

# /* Legal values for d_tag of Elf64_Dyn.  */
DT_ALPHA_PLTRO = (DT_LOPROC + 0)
DT_ALPHA_NUM = 1

# /* PowerPC specific declarations */
# /* Values for Elf32/64_Ehdr.e_flags.  */ 
EF_PPC_EMB = 0x80000000 # /* PowerPC embedded flag */

# /* Cygnus local bits below */ 
EF_PPC_RELOCATABLE = 0x00010000 # /* PowerPC -mrelocatable flag*/
EF_PPC_RELOCATABLE_LIB = 0x00008000 # /* PowerPC -mrelocatable-lib
#                            flag */

# /* PowerPC relocations defined by the ABIs */ 
R_PPC_NONE = 0
R_PPC_ADDR32 = 1 # /* 32bit absolute address */
R_PPC_ADDR24 = 2 # /* 26bit address, 2 bits ignored.  */
R_PPC_ADDR16 = 3 # /* 16bit absolute address */
R_PPC_ADDR16_LO = 4 # /* lower 16bit of absolute address */
R_PPC_ADDR16_HI = 5 # /* high 16bit of absolute address */
R_PPC_ADDR16_HA = 6 # /* adjusted high 16bit */
R_PPC_ADDR14 = 7 # /* 16bit address, 2 bits ignored */
R_PPC_ADDR14_BRTAKEN = 8
R_PPC_ADDR14_BRNTAKEN = 9
R_PPC_REL24 = 10 # /* PC relative 26 bit */
R_PPC_REL14 = 11 # /* PC relative 16 bit */
R_PPC_REL14_BRTAKEN = 12
R_PPC_REL14_BRNTAKEN = 13
R_PPC_GOT16 = 14
R_PPC_GOT16_LO = 15
R_PPC_GOT16_HI = 16
R_PPC_GOT16_HA = 17
R_PPC_PLTREL24 = 18
R_PPC_COPY = 19
R_PPC_GLOB_DAT = 20
R_PPC_JMP_SLOT = 21
R_PPC_RELATIVE = 22
R_PPC_LOCAL24PC = 23
R_PPC_UADDR32 = 24
R_PPC_UADDR16 = 25
R_PPC_REL32 = 26
R_PPC_PLT32 = 27
R_PPC_PLTREL32 = 28
R_PPC_PLT16_LO = 29
R_PPC_PLT16_HI = 30
R_PPC_PLT16_HA = 31
R_PPC_SDAREL16 = 32
R_PPC_SECTOFF = 33
R_PPC_SECTOFF_LO = 34
R_PPC_SECTOFF_HI = 35
R_PPC_SECTOFF_HA = 36

# /* PowerPC relocations defined for the TLS access ABI.  */
R_PPC_TLS = 67 # /* none    (sym+add)@tls */
R_PPC_DTPMOD32 = 68 # /* word32 (sym+add)@dtpmod */
R_PPC_TPREL16 = 69 # /* half16* (sym+add)@tprel */
R_PPC_TPREL16_LO = 70 # /* half16   (sym+add)@tprel@l */
R_PPC_TPREL16_HI = 71 # /* half16   (sym+add)@tprel@h */
R_PPC_TPREL16_HA = 72 # /* half16   (sym+add)@tprel@ha */
R_PPC_TPREL32 = 73 # /* word32  (sym+add)@tprel */
R_PPC_DTPREL16 = 74 # /* half16*    (sym+add)@dtprel */
R_PPC_DTPREL16_LO = 75 # /* half16  (sym+add)@dtprel@l */
R_PPC_DTPREL16_HI = 76 # /* half16  (sym+add)@dtprel@h */
R_PPC_DTPREL16_HA = 77 # /* half16  (sym+add)@dtprel@ha */
R_PPC_DTPREL32 = 78 # /* word32 (sym+add)@dtprel */
R_PPC_GOT_TLSGD16 = 79 # /* half16* (sym+add)@got@tlsgd */
R_PPC_GOT_TLSGD16_LO = 80 # /* half16   (sym+add)@got@tlsgd@l */
R_PPC_GOT_TLSGD16_HI = 81 # /* half16   (sym+add)@got@tlsgd@h */
R_PPC_GOT_TLSGD16_HA = 82 # /* half16   (sym+add)@got@tlsgd@ha */
R_PPC_GOT_TLSLD16 = 83 # /* half16* (sym+add)@got@tlsld */
R_PPC_GOT_TLSLD16_LO = 84 # /* half16   (sym+add)@got@tlsld@l */
R_PPC_GOT_TLSLD16_HI = 85 # /* half16   (sym+add)@got@tlsld@h */
R_PPC_GOT_TLSLD16_HA = 86 # /* half16   (sym+add)@got@tlsld@ha */
R_PPC_GOT_TPREL16 = 87 # /* half16* (sym+add)@got@tprel */
R_PPC_GOT_TPREL16_LO = 88 # /* half16   (sym+add)@got@tprel@l */
R_PPC_GOT_TPREL16_HI = 89 # /* half16   (sym+add)@got@tprel@h */
R_PPC_GOT_TPREL16_HA = 90 # /* half16   (sym+add)@got@tprel@ha */
R_PPC_GOT_DTPREL16 = 91 # /* half16*    (sym+add)@got@dtprel */
R_PPC_GOT_DTPREL16_LO = 92 # /* half16* (sym+add)@got@dtprel@l */
R_PPC_GOT_DTPREL16_HI = 93 # /* half16* (sym+add)@got@dtprel@h */
R_PPC_GOT_DTPREL16_HA = 94 # /* half16* (sym+add)@got@dtprel@ha */
R_PPC_TLSGD = 95 # /* none  (sym+add)@tlsgd */
R_PPC_TLSLD = 96 # /* none  (sym+add)@tlsld */

# /* The remaining relocs are from the Embedded ELF ABI, and are not
#   in the SVR4 ELF ABI.  */ 
R_PPC_EMB_NADDR32 = 101
R_PPC_EMB_NADDR16 = 102
R_PPC_EMB_NADDR16_LO = 103
R_PPC_EMB_NADDR16_HI = 104
R_PPC_EMB_NADDR16_HA = 105
R_PPC_EMB_SDAI16 = 106
R_PPC_EMB_SDA2I16 = 107
R_PPC_EMB_SDA2REL = 108
R_PPC_EMB_SDA21 = 109 # /* 16 bit offset in SDA */
R_PPC_EMB_MRKREF = 110
R_PPC_EMB_RELSEC16 = 111
R_PPC_EMB_RELST_LO = 112
R_PPC_EMB_RELST_HI = 113
R_PPC_EMB_RELST_HA = 114
R_PPC_EMB_BIT_FLD = 115
R_PPC_EMB_RELSDA = 116 # /* 16 bit relative offset in SDA */

# /* Diab tool relocations.  */ 
R_PPC_DIAB_SDA21_LO = 180 # /* like EMB_SDA21, but lower 16 bit */
R_PPC_DIAB_SDA21_HI = 181 # /* like EMB_SDA21, but high 16 bit */
R_PPC_DIAB_SDA21_HA = 182 # /* like EMB_SDA21, adjusted high 16 */
R_PPC_DIAB_RELSDA_LO = 183 # /* like EMB_RELSDA, but lower 16 bit */
R_PPC_DIAB_RELSDA_HI = 184 # /* like EMB_RELSDA, but high 16 bit */
R_PPC_DIAB_RELSDA_HA = 185 # /* like EMB_RELSDA, adjusted high 16 */

# /* GNU extension to support local ifunc.  */ 
R_PPC_IRELATIVE = 248

# /* GNU relocs used in PIC code sequences.  */
R_PPC_REL16 = 249 # /* half16   (sym+add-.) */
R_PPC_REL16_LO = 250 # /* half16   (sym+add-.)@l */
R_PPC_REL16_HI = 251 # /* half16   (sym+add-.)@h */
R_PPC_REL16_HA = 252 # /* half16   (sym+add-.)@ha */

# /* This is a phony reloc to handle any old fashioned TOC16 references
#    that may still be in object files.  */ 
R_PPC_TOC16 = 255 # /* PowerPC specific values for the Dyn d_tag field.  */
DT_PPC_GOT = (DT_LOPROC + 0)
DT_PPC_OPT = (DT_LOPROC + 1)
DT_PPC_NUM = 2

# /* PowerPC specific values for the DT_PPC_OPT Dyn entry.  */
PPC_OPT_TLS = 1

# /* PowerPC64 relocations defined by the ABIs */
R_PPC64_NONE = R_PPC_NONE
R_PPC64_ADDR32 = R_PPC_ADDR32 # /* 32bit absolute address */
R_PPC64_ADDR24 = R_PPC_ADDR24 # /* 26bit address, word aligned */
R_PPC64_ADDR16 = R_PPC_ADDR16 # /* 16bit absolute address */
R_PPC64_ADDR16_LO = R_PPC_ADDR16_LO # /* lower 16bits of address */
R_PPC64_ADDR16_HI = R_PPC_ADDR16_HI # /* high 16bits of address. */
R_PPC64_ADDR16_HA = R_PPC_ADDR16_HA # /* adjusted high 16bits.  */
R_PPC64_ADDR14 = R_PPC_ADDR14 # /* 16bit address, word aligned */
R_PPC64_ADDR14_BRTAKEN = R_PPC_ADDR14_BRTAKEN
R_PPC64_ADDR14_BRNTAKEN = R_PPC_ADDR14_BRNTAKEN
R_PPC64_REL24 = R_PPC_REL24 # /* PC-rel. 26 bit, word aligned */
R_PPC64_REL14 = R_PPC_REL14 # /* PC relative 16 bit */
R_PPC64_REL14_BRTAKEN = R_PPC_REL14_BRTAKEN
R_PPC64_REL14_BRNTAKEN = R_PPC_REL14_BRNTAKEN
R_PPC64_GOT16 = R_PPC_GOT16
R_PPC64_GOT16_LO = R_PPC_GOT16_LO
R_PPC64_GOT16_HI = R_PPC_GOT16_HI
R_PPC64_GOT16_HA = R_PPC_GOT16_HA

R_PPC64_COPY = R_PPC_COPY
R_PPC64_GLOB_DAT = R_PPC_GLOB_DAT
R_PPC64_JMP_SLOT = R_PPC_JMP_SLOT
R_PPC64_RELATIVE = R_PPC_RELATIVE

R_PPC64_UADDR32 = R_PPC_UADDR32
R_PPC64_UADDR16 = R_PPC_UADDR16
R_PPC64_REL32 = R_PPC_REL32
R_PPC64_PLT32 = R_PPC_PLT32
R_PPC64_PLTREL32 = R_PPC_PLTREL32
R_PPC64_PLT16_LO = R_PPC_PLT16_LO
R_PPC64_PLT16_HI = R_PPC_PLT16_HI
R_PPC64_PLT16_HA = R_PPC_PLT16_HA

R_PPC64_SECTOFF = R_PPC_SECTOFF
R_PPC64_SECTOFF_LO = R_PPC_SECTOFF_LO
R_PPC64_SECTOFF_HI = R_PPC_SECTOFF_HI
R_PPC64_SECTOFF_HA = R_PPC_SECTOFF_HA
R_PPC64_ADDR30 = 37 # /* word30 (S + A - P) >> 2 */
R_PPC64_ADDR64 = 38 # /* doubleword64 S + A */
R_PPC64_ADDR16_HIGHER = 39 # /* half16 #higher(S + A) */
R_PPC64_ADDR16_HIGHERA = 40 # /* half16 #highera(S + A) */
R_PPC64_ADDR16_HIGHEST = 41 # /* half16 #highest(S + A) */
R_PPC64_ADDR16_HIGHESTA = 42 # /* half16 #highesta(S + A) */
R_PPC64_UADDR64 = 43 # /* doubleword64 S + A */
R_PPC64_REL64 = 44 # /* doubleword64 S + A - P */
R_PPC64_PLT64 = 45 # /* doubleword64 L + A */
R_PPC64_PLTREL64 = 46 # /* doubleword64 L + A - P */
R_PPC64_TOC16 = 47 # /* half16* S + A - .TOC */
R_PPC64_TOC16_LO = 48 # /* half16 #lo(S + A - .TOC.) */
R_PPC64_TOC16_HI = 49 # /* half16 #hi(S + A - .TOC.) */
R_PPC64_TOC16_HA = 50 # /* half16 #ha(S + A - .TOC.) */
R_PPC64_TOC = 51 # /* doubleword64 .TOC */
R_PPC64_PLTGOT16 = 52 # /* half16* M + A */
R_PPC64_PLTGOT16_LO = 53 # /* half16 #lo(M + A) */
R_PPC64_PLTGOT16_HI = 54 # /* half16 #hi(M + A) */
R_PPC64_PLTGOT16_HA = 55 # /* half16 #ha(M + A) */

R_PPC64_ADDR16_DS = 56 # /* half16ds* (S + A) >> 2 */
R_PPC64_ADDR16_LO_DS = 57 # /* half16ds  #lo(S + A) >> 2 */
R_PPC64_GOT16_DS = 58 # /* half16ds* (G + A) >> 2 */
R_PPC64_GOT16_LO_DS = 59 # /* half16ds  #lo(G + A) >> 2 */
R_PPC64_PLT16_LO_DS = 60 # /* half16ds  #lo(L + A) >> 2 */
R_PPC64_SECTOFF_DS = 61 # /* half16ds* (R + A) >> 2 */
R_PPC64_SECTOFF_LO_DS = 62 # /* half16ds  #lo(R + A) >> 2 */
R_PPC64_TOC16_DS = 63 # /* half16ds* (S + A - .TOC.) >> 2 */
R_PPC64_TOC16_LO_DS = 64 # /* half16ds  #lo(S + A - .TOC.) >> 2 */
R_PPC64_PLTGOT16_DS = 65 # /* half16ds* (M + A) >> 2 */
R_PPC64_PLTGOT16_LO_DS = 66 # /* half16ds  #lo(M + A) >> 2 */

# /* PowerPC64 relocations defined for the TLS access ABI.  */ 
R_PPC64_TLS = 67 # /* none  (sym+add)@tls */
R_PPC64_DTPMOD64 = 68 # /* doubleword64 (sym+add)@dtpmod */
R_PPC64_TPREL16 = 69 # /* half16*   (sym+add)@tprel */
R_PPC64_TPREL16_LO = 70 # /* half16 (sym+add)@tprel@l */
R_PPC64_TPREL16_HI = 71 # /* half16 (sym+add)@tprel@h */
R_PPC64_TPREL16_HA = 72 # /* half16 (sym+add)@tprel@ha */
R_PPC64_TPREL64 = 73 # /* doubleword64 (sym+add)@tprel */
R_PPC64_DTPREL16 = 74 # /* half16*  (sym+add)@dtprel */
R_PPC64_DTPREL16_LO = 75 # /* half16    (sym+add)@dtprel@l */
R_PPC64_DTPREL16_HI = 76 # /* half16    (sym+add)@dtprel@h */
R_PPC64_DTPREL16_HA = 77 # /* half16    (sym+add)@dtprel@ha */
R_PPC64_DTPREL64 = 78 # /* doubleword64 (sym+add)@dtprel */
R_PPC64_GOT_TLSGD16 = 79 # /* half16*   (sym+add)@got@tlsgd */
R_PPC64_GOT_TLSGD16_LO = 80 # /* half16 (sym+add)@got@tlsgd@l */
R_PPC64_GOT_TLSGD16_HI = 81 # /* half16 (sym+add)@got@tlsgd@h */
R_PPC64_GOT_TLSGD16_HA = 82 # /* half16 (sym+add)@got@tlsgd@ha */
R_PPC64_GOT_TLSLD16 = 83 # /* half16*   (sym+add)@got@tlsld */
R_PPC64_GOT_TLSLD16_LO = 84 # /* half16 (sym+add)@got@tlsld@l */
R_PPC64_GOT_TLSLD16_HI = 85 # /* half16 (sym+add)@got@tlsld@h */
R_PPC64_GOT_TLSLD16_HA = 86 # /* half16 (sym+add)@got@tlsld@ha */
R_PPC64_GOT_TPREL16_DS = 87 # /* half16ds*  (sym+add)@got@tprel */
R_PPC64_GOT_TPREL16_LO_DS = 88 # /* half16ds (sym+add)@got@tprel@l */
R_PPC64_GOT_TPREL16_HI = 89 # /* half16 (sym+add)@got@tprel@h */
R_PPC64_GOT_TPREL16_HA = 90 # /* half16 (sym+add)@got@tprel@ha */
R_PPC64_GOT_DTPREL16_DS = 91 # /* half16ds* (sym+add)@got@dtprel */
R_PPC64_GOT_DTPREL16_LO_DS = 92 # /* half16ds (sym+add)@got@dtprel@l */
R_PPC64_GOT_DTPREL16_HI = 93 # /* half16    (sym+add)@got@dtprel@h */
R_PPC64_GOT_DTPREL16_HA = 94 # /* half16    (sym+add)@got@dtprel@ha */
R_PPC64_TPREL16_DS = 95 # /* half16ds*  (sym+add)@tprel */
R_PPC64_TPREL16_LO_DS = 96 # /* half16ds    (sym+add)@tprel@l */
R_PPC64_TPREL16_HIGHER = 97 # /* half16 (sym+add)@tprel@higher */
R_PPC64_TPREL16_HIGHERA = 98 # /* half16    (sym+add)@tprel@highera */
R_PPC64_TPREL16_HIGHEST = 99 # /* half16    (sym+add)@tprel@highest */
R_PPC64_TPREL16_HIGHESTA = 100 # /* half16  (sym+add)@tprel@highesta */
R_PPC64_DTPREL16_DS = 101 # /* half16ds* (sym+add)@dtprel */
R_PPC64_DTPREL16_LO_DS = 102 # /* half16ds  (sym+add)@dtprel@l */
R_PPC64_DTPREL16_HIGHER = 103 # /* half16   (sym+add)@dtprel@higher */
R_PPC64_DTPREL16_HIGHERA = 104 # /* half16  (sym+add)@dtprel@highera */
R_PPC64_DTPREL16_HIGHEST = 105 # /* half16  (sym+add)@dtprel@highest */
R_PPC64_DTPREL16_HIGHESTA = 106 # /* half16 (sym+add)@dtprel@highesta */
R_PPC64_TLSGD = 107 # /* none   (sym+add)@tlsgd */
R_PPC64_TLSLD = 108 # /* none   (sym+add)@tlsld */
R_PPC64_TOCSAVE = 109 # /* none */

# /* Added when HA and HI relocs were changed to report overflows.  */ 
R_PPC64_ADDR16_HIGH = 110
R_PPC64_ADDR16_HIGHA = 111
R_PPC64_TPREL16_HIGH = 112
R_PPC64_TPREL16_HIGHA = 113
R_PPC64_DTPREL16_HIGH = 114
R_PPC64_DTPREL16_HIGHA = 115

# /* GNU extension to support local ifunc.  */
R_PPC64_JMP_IREL = 247
R_PPC64_IRELATIVE = 248
R_PPC64_REL16 = 249 # /* half16   (sym+add-.) */
R_PPC64_REL16_LO = 250 # /* half16   (sym+add-.)@l */
R_PPC64_REL16_HI = 251 # /* half16   (sym+add-.)@h */
R_PPC64_REL16_HA = 252 # /* half16   (sym+add-.)@ha */
# /* e_flags bits specifying ABI.
#    1 for original function descriptor using ABI,
#    2 for revised ABI without function descriptors,
#    0 for unspecified or not using any features affected by the differences.  */ 
EF_PPC64_ABI = 3

# /* PowerPC64 specific values for the Dyn d_tag field.  */
DT_PPC64_GLINK = (DT_LOPROC + 0)
DT_PPC64_OPD = (DT_LOPROC + 1)
DT_PPC64_OPDSZ = (DT_LOPROC + 2)
DT_PPC64_OPT = (DT_LOPROC + 3)
DT_PPC64_NUM = 4

# /* PowerPC64 specific bits in the DT_PPC64_OPT Dyn entry.  */
PPC64_OPT_TLS = 1
PPC64_OPT_MULTI_TOC = 2
PPC64_OPT_LOCALENTRY = 4

# /* PowerPC64 specific values for the Elf64_Sym st_other field.  */
STO_PPC64_LOCAL_BIT = 5
STO_PPC64_LOCAL_MASK = (7 << STO_PPC64_LOCAL_BIT)
#PPC64_LOCAL_ENTRY_OFFSET = 

# /* ARM specific declarations */ 

# /* Processor specific flags for the ELF header e_flags field.  */ 
EF_ARM_RELEXEC = 0x01
EF_ARM_HASENTRY = 0x02
EF_ARM_INTERWORK = 0x04
EF_ARM_APCS_26 = 0x08
EF_ARM_APCS_FLOAT = 0x10
EF_ARM_PIC = 0x20
EF_ARM_ALIGN8 = 0x40 # /* 8-bit structure alignment is in use */
EF_ARM_NEW_ABI = 0x80
EF_ARM_OLD_ABI = 0x100
EF_ARM_SOFT_FLOAT = 0x200
EF_ARM_VFP_FLOAT = 0x400
EF_ARM_MAVERICK_FLOAT = 0x800

EF_ARM_ABI_FLOAT_SOFT = 0x200 # /* NB conflicts with EF_ARM_SOFT_FLOAT */
EF_ARM_ABI_FLOAT_HARD = 0x400 # /* NB conflicts with EF_ARM_VFP_FLOAT */

# /* Other constants defined in the ARM ELF spec. version B-01.  */ 
# /* NB. These conflict with values defined above.  */ 
EF_ARM_SYMSARESORTED = 0x04
EF_ARM_DYNSYMSUSESEGIDX = 0x08
EF_ARM_MAPSYMSFIRST = 0x10
EF_ARM_EABIMASK = 0XFF000000

# /* Constants defined in AAELF.  */
EF_ARM_BE8 = 0x00800000
EF_ARM_LE8 = 0x00400000
EF_ARM_EABI_VERSION = lambda flags: ((flags) & EF_ARM_EABIMASK)
EF_ARM_EABI_UNKNOWN = 0x00000000
EF_ARM_EABI_VER1 = 0x01000000
EF_ARM_EABI_VER2 = 0x02000000
EF_ARM_EABI_VER3 = 0x03000000
EF_ARM_EABI_VER4 = 0x04000000
EF_ARM_EABI_VER5 = 0x05000000

# /* Additional symbol types for Thumb.  */
STT_ARM_TFUNC = STT_LOPROC # /* A Thumb function.  */
STT_ARM_16BIT = STT_HIPROC # /* A Thumb label.  */

# /* ARM-specific values for sh_flags */ 
SHF_ARM_ENTRYSECT = 0x10000000 # /* Section contains an entry point */
SHF_ARM_COMDEF = 0x80000000 # /* Section may be multiply defined
#                           in the input to a link step.  */
# /* ARM-specific program header flags */ 
PF_ARM_SB = 0x10000000 # /* Segment contains the location
#                           addressed by the static base. */
PF_ARM_PI = 0x20000000 # /* Position-independent segment.  */
PF_ARM_ABS = 0x40000000 # /* Absolute segment.  */

# /* Processor specific values for the Phdr p_type field.  */ 
PT_ARM_EXIDX = (PT_LOPROC + 1) # /* ARM unwind segment.  */ 

# /* Processor specific values for the Shdr sh_type field.  */ 
SHT_ARM_EXIDX = (SHT_LOPROC + 1) # /* ARM unwind section.  */ 
SHT_ARM_PREEMPTMAP = (SHT_LOPROC + 2) # /* Preemption details.  */ 
SHT_ARM_ATTRIBUTES = (SHT_LOPROC + 3) # /* ARM attributes section.  */ 

# /* AArch64 relocs.  */ 
R_AARCH64_NONE = 0 # /* No relocation.  */

# /* ILP32 AArch64 relocs.  */ 
R_AARCH64_P32_ABS32 = 1 # /* Direct 32 bit.  */
R_AARCH64_P32_COPY = 180 # /* Copy symbol at runtime.  */
R_AARCH64_P32_GLOB_DAT = 181 # /* Create GOT entry.  */
R_AARCH64_P32_JUMP_SLOT = 182 # /* Create PLT entry.  */
R_AARCH64_P32_RELATIVE = 183 # /* Adjust by program base.  */
R_AARCH64_P32_TLS_DTPMOD = 184 # /* Module number, 32 bit.  */
R_AARCH64_P32_TLS_DTPREL = 185 # /* Module-relative offset, 32 bit.  */
R_AARCH64_P32_TLS_TPREL = 186 # /* TP-relative offset, 32 bit.  */
R_AARCH64_P32_TLSDESC = 187 # /* TLS Descriptor.  */
R_AARCH64_P32_IRELATIVE = 188 # /* STT_GNU_IFUNC relocation. */

# /* LP64 AArch64 relocs.  */ 
R_AARCH64_ABS64 = 257 # /* Direct 64 bit. */
R_AARCH64_ABS32 = 258 # /* Direct 32 bit.  */
R_AARCH64_ABS16 = 259 # /* Direct 16-bit.  */
R_AARCH64_PREL64 = 260 # /* PC-relative 64-bit. */
R_AARCH64_PREL32 = 261 # /* PC-relative 32-bit. */
R_AARCH64_PREL16 = 262 # /* PC-relative 16-bit. */
R_AARCH64_MOVW_UABS_G0 = 263 # /* Dir. MOVZ imm. from bits 15:0.  */
R_AARCH64_MOVW_UABS_G0_NC = 264 # /* Likewise for MOVK; no check.  */
R_AARCH64_MOVW_UABS_G1 = 265 # /* Dir. MOVZ imm. from bits 31:16.  */
R_AARCH64_MOVW_UABS_G1_NC = 266 # /* Likewise for MOVK; no check.  */
R_AARCH64_MOVW_UABS_G2 = 267 # /* Dir. MOVZ imm. from bits 47:32.  */
R_AARCH64_MOVW_UABS_G2_NC = 268 # /* Likewise for MOVK; no check.  */
R_AARCH64_MOVW_UABS_G3 = 269 # /* Dir. MOV{K,Z} imm. from 63:48.  */
R_AARCH64_MOVW_SABS_G0 = 270 # /* Dir. MOV{N,Z} imm. from 15:0.  */
R_AARCH64_MOVW_SABS_G1 = 271 # /* Dir. MOV{N,Z} imm. from 31:16.  */
R_AARCH64_MOVW_SABS_G2 = 272 # /* Dir. MOV{N,Z} imm. from 47:32.  */
R_AARCH64_LD_PREL_LO19 = 273 # /* PC-rel. LD imm. from bits 20:2.  */
R_AARCH64_ADR_PREL_LO21 = 274 # /* PC-rel. ADR imm. from bits 20:0.  */
R_AARCH64_ADR_PREL_PG_HI21 = 275 # /* Page-rel. ADRP imm. from 32:12.  */
R_AARCH64_ADR_PREL_PG_HI21_NC = 276 # /* Likewise; no overflow check.  */
R_AARCH64_ADD_ABS_LO12_NC = 277 # /* Dir. ADD imm. from bits 11:0.  */
R_AARCH64_LDST8_ABS_LO12_NC = 278 # /* Likewise for LD/ST; no check. */
R_AARCH64_TSTBR14 = 279 # /* PC-rel. TBZ/TBNZ imm. from 15:2.  */
R_AARCH64_CONDBR19 = 280 # /* PC-rel. cond. br. imm. from 20:2. */
R_AARCH64_JUMP26 = 282 # /* PC-rel. B imm. from bits 27:2.  */
R_AARCH64_CALL26 = 283 # /* Likewise for CALL.  */
R_AARCH64_LDST16_ABS_LO12_NC = 284 # /* Dir. ADD imm. from bits 11:1.  */
R_AARCH64_LDST32_ABS_LO12_NC = 285 # /* Likewise for bits 11:2.  */
R_AARCH64_LDST64_ABS_LO12_NC = 286 # /* Likewise for bits 11:3.  */
R_AARCH64_MOVW_PREL_G0 = 287 # /* PC-rel. MOV{N,Z} imm. from 15:0.  */
R_AARCH64_MOVW_PREL_G0_NC = 288 # /* Likewise for MOVK; no check.  */
R_AARCH64_MOVW_PREL_G1 = 289 # /* PC-rel. MOV{N,Z} imm. from 31:16. */
R_AARCH64_MOVW_PREL_G1_NC = 290 # /* Likewise for MOVK; no check.  */
R_AARCH64_MOVW_PREL_G2 = 291 # /* PC-rel. MOV{N,Z} imm. from 47:32. */
R_AARCH64_MOVW_PREL_G2_NC = 292 # /* Likewise for MOVK; no check.  */
R_AARCH64_MOVW_PREL_G3 = 293 # /* PC-rel. MOV{N,Z} imm. from 63:48. */
R_AARCH64_LDST128_ABS_LO12_NC = 299 # /* Dir. ADD imm. from bits 11:4.  */
R_AARCH64_MOVW_GOTOFF_G0 = 300 # /* GOT-rel. off. MOV{N,Z} imm. 15:0. */
R_AARCH64_MOVW_GOTOFF_G0_NC = 301 # /* Likewise for MOVK; no check.  */
R_AARCH64_MOVW_GOTOFF_G1 = 302 # /* GOT-rel. o. MOV{N,Z} imm. 31:16.  */
R_AARCH64_MOVW_GOTOFF_G1_NC = 303 # /* Likewise for MOVK; no check.  */
R_AARCH64_MOVW_GOTOFF_G2 = 304 # /* GOT-rel. o. MOV{N,Z} imm. 47:32.  */
R_AARCH64_MOVW_GOTOFF_G2_NC = 305 # /* Likewise for MOVK; no check.  */
R_AARCH64_MOVW_GOTOFF_G3 = 306 # /* GOT-rel. o. MOV{N,Z} imm. 63:48.  */
R_AARCH64_GOTREL64 = 307 # /* GOT-relative 64-bit.  */
R_AARCH64_GOTREL32 = 308 # /* GOT-relative 32-bit.  */
R_AARCH64_GOT_LD_PREL19 = 309 # /* PC-rel. GOT off. load imm. 20:2.  */
R_AARCH64_LD64_GOTOFF_LO15 = 310 # /* GOT-rel. off. LD/ST imm. 14:3.  */
R_AARCH64_ADR_GOT_PAGE = 311 # /* P-page-rel. GOT off. ADRP 32:12.  */
R_AARCH64_LD64_GOT_LO12_NC = 312 # /* Dir. GOT off. LD/ST imm. 11:3.  */
R_AARCH64_LD64_GOTPAGE_LO15 = 313 # /* GOT-page-rel. GOT off. LD/ST 14:3 */
R_AARCH64_TLSGD_ADR_PREL21 = 512 # /* PC-relative ADR imm. 20:0.  */
R_AARCH64_TLSGD_ADR_PAGE21 = 513 # /* page-rel. ADRP imm. 32:12.  */
R_AARCH64_TLSGD_ADD_LO12_NC = 514 # /* direct ADD imm. from 11:0.  */
R_AARCH64_TLSGD_MOVW_G1 = 515 # /* GOT-rel. MOV{N,Z} 31:16.  */
R_AARCH64_TLSGD_MOVW_G0_NC = 516 # /* GOT-rel. MOVK imm. 15:0.  */
R_AARCH64_TLSLD_ADR_PREL21 = 517 # /* Like 512; local dynamic model.  */
R_AARCH64_TLSLD_ADR_PAGE21 = 518 # /* Like 513; local dynamic model.  */
R_AARCH64_TLSLD_ADD_LO12_NC = 519 # /* Like 514; local dynamic model.  */
R_AARCH64_TLSLD_MOVW_G1 = 520 # /* Like 515; local dynamic model.  */
R_AARCH64_TLSLD_MOVW_G0_NC = 521 # /* Like 516; local dynamic model.  */
R_AARCH64_TLSLD_LD_PREL19 = 522 # /* TLS PC-rel. load imm. 20:2.  */
R_AARCH64_TLSLD_MOVW_DTPREL_G2 = 523 # /* TLS DTP-rel. MOV{N,Z} 47:32.  */
R_AARCH64_TLSLD_MOVW_DTPREL_G1 = 524 # /* TLS DTP-rel. MOV{N,Z} 31:16.  */
R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC = 525 # /* Likewise; MOVK; no check.  */
R_AARCH64_TLSLD_MOVW_DTPREL_G0 = 526 # /* TLS DTP-rel. MOV{N,Z} 15:0.  */
R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC = 527 # /* Likewise; MOVK; no check.  */
R_AARCH64_TLSLD_ADD_DTPREL_HI12 = 528 # /* DTP-rel. ADD imm. from 23:12. */
R_AARCH64_TLSLD_ADD_DTPREL_LO12 = 529 # /* DTP-rel. ADD imm. from 11:0.  */
R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC = 530 # /* Likewise; no ovfl. check.  */
R_AARCH64_TLSLD_LDST8_DTPREL_LO12 = 531 # /* DTP-rel. LD/ST imm. 11:0.  */
R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC = 532 # /* Likewise; no check.  */
R_AARCH64_TLSLD_LDST16_DTPREL_LO12 = 533 # /* DTP-rel. LD/ST imm. 11:1.  */
R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC = 534 # /* Likewise; no check.  */
R_AARCH64_TLSLD_LDST32_DTPREL_LO12 = 535 # /* DTP-rel. LD/ST imm. 11:2.  */
R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC = 536 # /* Likewise; no check.  */
R_AARCH64_TLSLD_LDST64_DTPREL_LO12 = 537 # /* DTP-rel. LD/ST imm. 11:3.  */
R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC = 538 # /* Likewise; no check.  */
R_AARCH64_TLSIE_MOVW_GOTTPREL_G1 = 539 # /* GOT-rel. MOV{N,Z} 31:16.  */
R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC = 540 # /* GOT-rel. MOVK 15:0.  */
R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 = 541 # /* Page-rel. ADRP 32:12.  */
R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC = 542 # /* Direct LD off. 11:3.  */
R_AARCH64_TLSIE_LD_GOTTPREL_PREL19 = 543 # /* PC-rel. load imm. 20:2.  */
R_AARCH64_TLSLE_MOVW_TPREL_G2 = 544 # /* TLS TP-rel. MOV{N,Z} 47:32.  */
R_AARCH64_TLSLE_MOVW_TPREL_G1 = 545 # /* TLS TP-rel. MOV{N,Z} 31:16.  */
R_AARCH64_TLSLE_MOVW_TPREL_G1_NC = 546 # /* Likewise; MOVK; no check.  */
R_AARCH64_TLSLE_MOVW_TPREL_G0 = 547 # /* TLS TP-rel. MOV{N,Z} 15:0.  */
R_AARCH64_TLSLE_MOVW_TPREL_G0_NC = 548 # /* Likewise; MOVK; no check.  */
R_AARCH64_TLSLE_ADD_TPREL_HI12 = 549 # /* TP-rel. ADD imm. 23:12.  */
R_AARCH64_TLSLE_ADD_TPREL_LO12 = 550 # /* TP-rel. ADD imm. 11:0.  */
R_AARCH64_TLSLE_ADD_TPREL_LO12_NC = 551 # /* Likewise; no ovfl. check.  */
R_AARCH64_TLSLE_LDST8_TPREL_LO12 = 552 # /* TP-rel. LD/ST off. 11:0.  */
R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC = 553 # /* Likewise; no ovfl. check. */
R_AARCH64_TLSLE_LDST16_TPREL_LO12 = 554 # /* TP-rel. LD/ST off. 11:1.  */
R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC = 555 # /* Likewise; no check.  */
R_AARCH64_TLSLE_LDST32_TPREL_LO12 = 556 # /* TP-rel. LD/ST off. 11:2.  */
R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC = 557 # /* Likewise; no check.  */
R_AARCH64_TLSLE_LDST64_TPREL_LO12 = 558 # /* TP-rel. LD/ST off. 11:3.  */
R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC = 559 # /* Likewise; no check.  */
R_AARCH64_TLSDESC_LD_PREL19 = 560 # /* PC-rel. load immediate 20:2.  */
R_AARCH64_TLSDESC_ADR_PREL21 = 561 # /* PC-rel. ADR immediate 20:0.  */
R_AARCH64_TLSDESC_ADR_PAGE21 = 562 # /* Page-rel. ADRP imm. 32:12.  */
R_AARCH64_TLSDESC_LD64_LO12 = 563 # /* Direct LD off. from 11:3.  */
R_AARCH64_TLSDESC_ADD_LO12 = 564 # /* Direct ADD imm. from 11:0.  */
R_AARCH64_TLSDESC_OFF_G1 = 565 # /* GOT-rel. MOV{N,Z} imm. 31:16.  */
R_AARCH64_TLSDESC_OFF_G0_NC = 566 # /* GOT-rel. MOVK imm. 15:0; no ck.  */
R_AARCH64_TLSDESC_LDR = 567 # /* Relax LDR.  */
R_AARCH64_TLSDESC_ADD = 568 # /* Relax ADD.  */
R_AARCH64_TLSDESC_CALL = 569 # /* Relax BLR.  */
R_AARCH64_TLSLE_LDST128_TPREL_LO12 = 570 # /* TP-rel. LD/ST off. 11:4.  */
R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC = 571 # /* Likewise; no check.  */
R_AARCH64_TLSLD_LDST128_DTPREL_LO12 = 572 # /* DTP-rel. LD/ST imm. 11:4. */
R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC = 573 # /* Likewise; no check.  */
R_AARCH64_COPY = 1024 # /* Copy symbol at runtime.  */
R_AARCH64_GLOB_DAT = 1025 # /* Create GOT entry.  */
R_AARCH64_JUMP_SLOT = 1026 # /* Create PLT entry.  */
R_AARCH64_RELATIVE = 1027 # /* Adjust by program base.  */
R_AARCH64_TLS_DTPMOD = 1028 # /* Module number, 64 bit.  */
R_AARCH64_TLS_DTPREL = 1029 # /* Module-relative offset, 64 bit.  */
R_AARCH64_TLS_TPREL = 1030 # /* TP-relative offset, 64 bit.  */
R_AARCH64_TLSDESC = 1031 # /* TLS Descriptor.  */
R_AARCH64_IRELATIVE = 1032 # /* STT_GNU_IFUNC relocation.  */

# /* MTE memory tag segment type.  */ 
PT_AARCH64_MEMTAG_MTE = (PT_LOPROC + 2)

# /* AArch64 specific values for the Dyn d_tag field.  */ 
DT_AARCH64_BTI_PLT = (DT_LOPROC + 1)
DT_AARCH64_PAC_PLT = (DT_LOPROC + 3)
DT_AARCH64_VARIANT_PCS = (DT_LOPROC + 5)
DT_AARCH64_NUM = 6

# /* AArch64 specific values for the st_other field.  */
STO_AARCH64_VARIANT_PCS = 0x80

# /* ARM relocs.  */
R_ARM_NONE = 0 # /* No reloc */
R_ARM_PC24 = 1 # /* Deprecated PC relative 26
#                        bit branch.  */
R_ARM_ABS32 = 2 # /* Direct 32 bit  */
R_ARM_REL32 = 3 # /* PC relative 32 bit */
R_ARM_PC13 = 4
R_ARM_ABS16 = 5 # /* Direct 16 bit */
R_ARM_ABS12 = 6 # /* Direct 12 bit */
R_ARM_THM_ABS5 = 7 # /* Direct & 0x7C (LDR, STR).  */
R_ARM_ABS8 = 8 # /* Direct 8 bit */
R_ARM_SBREL32 = 9
R_ARM_THM_PC22 = 10 # /* PC relative 24 bit (Thumb32 BL).  */
R_ARM_THM_PC8 = 11 # /* PC relative & 0x3FC
#                        (Thumb16 LDR, ADD, ADR).  */
R_ARM_AMP_VCALL9 = 12
R_ARM_SWI24 = 13 # /* Obsolete static relocation.  */
R_ARM_TLS_DESC = 13 # /* Dynamic relocation.  */
R_ARM_THM_SWI8 = 14 # /* Reserved.  */
R_ARM_XPC25 = 15 # /* Reserved.  */
R_ARM_THM_XPC22 = 16 # /* Reserved.  */
R_ARM_TLS_DTPMOD32 = 17 # /* ID of module containing symbol */
R_ARM_TLS_DTPOFF32 = 18 # /* Offset in TLS block */
R_ARM_TLS_TPOFF32 = 19 # /* Offset in static TLS block */
R_ARM_COPY = 20 # /* Copy symbol at runtime */
R_ARM_GLOB_DAT = 21 # /* Create GOT entry */
R_ARM_JUMP_SLOT = 22 # /* Create PLT entry */
R_ARM_RELATIVE = 23 # /* Adjust by program base */
R_ARM_GOTOFF = 24 # /* 32 bit offset to GOT */
R_ARM_GOTPC = 25 # /* 32 bit PC relative offset to GOT */
R_ARM_GOT32 = 26 # /* 32 bit GOT entry */
R_ARM_PLT32 = 27 # /* Deprecated, 32 bit PLT address.  */
R_ARM_CALL = 28 # /* PC relative 24 bit (BL, BLX).  */
R_ARM_JUMP24 = 29 # /* PC relative 24 bit
#                        (B, BL<cond>).  */
R_ARM_THM_JUMP24 = 30 # /* PC relative 24 bit (Thumb32 B.W).  */
R_ARM_BASE_ABS = 31 # /* Adjust by program base.  */
R_ARM_ALU_PCREL_7_0 = 32 # /* Obsolete.  */
R_ARM_ALU_PCREL_15_8 = 33 # /* Obsolete.  */
R_ARM_ALU_PCREL_23_15 = 34 # /* Obsolete.  */
R_ARM_LDR_SBREL_11_0 = 35 # /* Deprecated, prog. base relative.  */
R_ARM_ALU_SBREL_19_12 = 36 # /* Deprecated, prog. base relative.  */
R_ARM_ALU_SBREL_27_20 = 37 # /* Deprecated, prog. base relative.  */
R_ARM_TARGET1 = 38
R_ARM_SBREL31 = 39 # /* Program base relative.  */
R_ARM_V4BX = 40
R_ARM_TARGET2 = 41
R_ARM_PREL31 = 42 # /* 32 bit PC relative.  */
R_ARM_MOVW_ABS_NC = 43 # /* Direct 16-bit (MOVW).  */
R_ARM_MOVT_ABS = 44 # /* Direct high 16-bit (MOVT).  */
R_ARM_MOVW_PREL_NC = 45 # /* PC relative 16-bit (MOVW).  */
R_ARM_MOVT_PREL = 46 # /* PC relative (MOVT).  */
R_ARM_THM_MOVW_ABS_NC = 47 # /* Direct 16 bit (Thumb32 MOVW).  */
R_ARM_THM_MOVT_ABS = 48 # /* Direct high 16 bit
#                        (Thumb32 MOVT).  */
R_ARM_THM_MOVW_PREL_NC = 49 # /* PC relative 16 bit
#                        (Thumb32 MOVW).  */
R_ARM_THM_MOVT_PREL = 50 # /* PC relative high 16 bit
#                        (Thumb32 MOVT).  */
R_ARM_THM_JUMP19 = 51 # /* PC relative 20 bit
#                        (Thumb32 B<cond>.W).  */
R_ARM_THM_JUMP6 = 52 # /* PC relative X & 0x7E
#                        (Thumb16 CBZ, CBNZ).  */
R_ARM_THM_ALU_PREL_11_0 = 53 # /* PC relative 12 bit
#                        (Thumb32 ADR.W).  */
R_ARM_THM_PC12 = 54 # /* PC relative 12 bit
#                        (Thumb32 LDR{D,SB,H,SH}).  */
R_ARM_ABS32_NOI = 55 # /* Direct 32-bit.  */
R_ARM_REL32_NOI = 56 # /* PC relative 32-bit.  */
R_ARM_ALU_PC_G0_NC = 57 # /* PC relative (ADD, SUB).  */
R_ARM_ALU_PC_G0 = 58 # /* PC relative (ADD, SUB).  */
R_ARM_ALU_PC_G1_NC = 59 # /* PC relative (ADD, SUB).  */
R_ARM_ALU_PC_G1 = 60 # /* PC relative (ADD, SUB).  */
R_ARM_ALU_PC_G2 = 61 # /* PC relative (ADD, SUB).  */
R_ARM_LDR_PC_G1 = 62 # /* PC relative (LDR,STR,LDRB,STRB).  */
R_ARM_LDR_PC_G2 = 63 # /* PC relative (LDR,STR,LDRB,STRB).  */
R_ARM_LDRS_PC_G0 = 64 # /* PC relative (STR{D,H},
#                        LDR{D,SB,H,SH}).  */
R_ARM_LDRS_PC_G1 = 65 # /* PC relative (STR{D,H},
#                        LDR{D,SB,H,SH}).  */
R_ARM_LDRS_PC_G2 = 66 # /* PC relative (STR{D,H},
#                        LDR{D,SB,H,SH}).  */
R_ARM_LDC_PC_G0 = 67 # /* PC relative (LDC, STC).  */
R_ARM_LDC_PC_G1 = 68 # /* PC relative (LDC, STC).  */
R_ARM_LDC_PC_G2 = 69 # /* PC relative (LDC, STC).  */
R_ARM_ALU_SB_G0_NC = 70 # /* Program base relative (ADD,SUB).  */
R_ARM_ALU_SB_G0 = 71 # /* Program base relative (ADD,SUB).  */
R_ARM_ALU_SB_G1_NC = 72 # /* Program base relative (ADD,SUB).  */
R_ARM_ALU_SB_G1 = 73 # /* Program base relative (ADD,SUB).  */
R_ARM_ALU_SB_G2 = 74 # /* Program base relative (ADD,SUB).  */
R_ARM_LDR_SB_G0 = 75 # /* Program base relative (LDR,
#                        STR, LDRB, STRB).  */
R_ARM_LDR_SB_G1 = 76 # /* Program base relative
#                        (LDR, STR, LDRB, STRB).  */
R_ARM_LDR_SB_G2 = 77 # /* Program base relative
#                        (LDR, STR, LDRB, STRB).  */
R_ARM_LDRS_SB_G0 = 78 # /* Program base relative
#                        (LDR, STR, LDRB, STRB).  */
R_ARM_LDRS_SB_G1 = 79 # /* Program base relative
#                        (LDR, STR, LDRB, STRB).  */
R_ARM_LDRS_SB_G2 = 80 # /* Program base relative
#                        (LDR, STR, LDRB, STRB).  */
R_ARM_LDC_SB_G0 = 81 # /* Program base relative (LDC,STC).  */
R_ARM_LDC_SB_G1 = 82 # /* Program base relative (LDC,STC).  */
R_ARM_LDC_SB_G2 = 83 # /* Program base relative (LDC,STC).  */
R_ARM_MOVW_BREL_NC = 84 # /* Program base relative 16
#                        bit (MOVW).  */
R_ARM_MOVT_BREL = 85 # /* Program base relative high
#                        16 bit (MOVT).  */
R_ARM_MOVW_BREL = 86 # /* Program base relative 16
#                        bit (MOVW).  */
R_ARM_THM_MOVW_BREL_NC = 87 # /* Program base relative 16
#                        bit (Thumb32 MOVW).  */
R_ARM_THM_MOVT_BREL = 88 # /* Program base relative high
#                        16 bit (Thumb32 MOVT).  */
R_ARM_THM_MOVW_BREL = 89 # /* Program base relative 16
#                        bit (Thumb32 MOVW).  */
R_ARM_TLS_GOTDESC = 90
R_ARM_TLS_CALL = 91
R_ARM_TLS_DESCSEQ = 92 # /* TLS relaxation.  */
R_ARM_THM_TLS_CALL = 93
R_ARM_PLT32_ABS = 94
R_ARM_GOT_ABS = 95 # /* GOT entry.  */
R_ARM_GOT_PREL = 96 # /* PC relative GOT entry.  */
R_ARM_GOT_BREL12 = 97 # /* GOT entry relative to GOT
#                        origin (LDR).  */
R_ARM_GOTOFF12 = 98 # /* 12 bit, GOT entry relative
#                        to GOT origin (LDR, STR).  */
R_ARM_GOTRELAX = 99
R_ARM_GNU_VTENTRY = 100
R_ARM_GNU_VTINHERIT = 101
R_ARM_THM_PC11 = 102 # /* PC relative & 0xFFE (Thumb16 B).  */
R_ARM_THM_PC9 = 103 # /* PC relative & 0x1FE
#                        (Thumb16 B/B<cond>).  */
R_ARM_TLS_GD32 = 104 # /* PC-rel 32 bit for global dynamic
#                        thread local data */
R_ARM_TLS_LDM32 = 105 # /* PC-rel 32 bit for local dynamic
#                        thread local data */
R_ARM_TLS_LDO32 = 106 # /* 32 bit offset relative to TLS
#                        block */
R_ARM_TLS_IE32 = 107 # /* PC-rel 32 bit for GOT entry of
#                        static TLS block offset */
R_ARM_TLS_LE32 = 108 # /* 32 bit offset relative to static
#                        TLS block */
R_ARM_TLS_LDO12 = 109 # /* 12 bit relative to TLS
#                        block (LDR, STR).  */
R_ARM_TLS_LE12 = 110 # /* 12 bit relative to static
#                        TLS block (LDR, STR).  */
R_ARM_TLS_IE12GP = 111 # /* 12 bit GOT entry relative
#                        to GOT origin (LDR).  */
R_ARM_ME_TOO = 128 # /* Obsolete.  */
R_ARM_THM_TLS_DESCSEQ = 129
R_ARM_THM_TLS_DESCSEQ16 = 129
R_ARM_THM_TLS_DESCSEQ32 = 130
R_ARM_THM_GOT_BREL12 = 131 # /* GOT entry relative to GOT
#                        origin, 12 bit (Thumb32 LDR).  */
R_ARM_IRELATIVE = 160
R_ARM_RXPC25 = 249
R_ARM_RSBREL32 = 250
R_ARM_THM_RPC22 = 251
R_ARM_RREL32 = 252
R_ARM_RABS22 = 253
R_ARM_RPC24 = 254
R_ARM_RBASE = 255
# /* Keep this the last entry.  */
R_ARM_NUM = 256

# /* C-SKY */
R_CKCORE_NONE = 0 # /* no reloc */
R_CKCORE_ADDR32 = 1 # /* direct 32 bit (S + A) */
R_CKCORE_PCRELIMM8BY4 = 2 # /* disp ((S + A - P) >> 2) & 0xff   */
R_CKCORE_PCRELIMM11BY2 = 3 # /* disp ((S + A - P) >> 1) & 0x7ff  */
R_CKCORE_PCREL32 = 5 # /* 32-bit rel (S + A - P)           */
R_CKCORE_PCRELJSR_IMM11BY2 = 6 # /* disp ((S + A - P) >>1) & 0x7ff   */
R_CKCORE_RELATIVE = 9 # /* 32 bit adjust program base(B + A)*/
R_CKCORE_COPY = 10 # /* 32 bit adjust by program base    */
R_CKCORE_GLOB_DAT = 11 # /* off between got and sym (S)      */
R_CKCORE_JUMP_SLOT = 12 # /* PLT entry (S) */
R_CKCORE_GOTOFF = 13 # /* offset to GOT (S + A - GOT)      */
R_CKCORE_GOTPC = 14 # /* PC offset to GOT (GOT + A - P)   */
R_CKCORE_GOT32 = 15 # /* 32 bit GOT entry (G) */
R_CKCORE_PLT32 = 16 # /* 32 bit PLT entry (G) */
R_CKCORE_ADDRGOT = 17 # /* GOT entry in GLOB_DAT (GOT + G)  */
R_CKCORE_ADDRPLT = 18 # /* PLT entry in GLOB_DAT (GOT + G)  */
R_CKCORE_PCREL_IMM26BY2 = 19 # /* ((S + A - P) >> 1) & 0x3ffffff   */
R_CKCORE_PCREL_IMM16BY2 = 20 # /* disp ((S + A - P) >> 1) & 0xffff */
R_CKCORE_PCREL_IMM16BY4 = 21 # /* disp ((S + A - P) >> 2) & 0xffff */
R_CKCORE_PCREL_IMM10BY2 = 22 # /* disp ((S + A - P) >> 1) & 0x3ff  */
R_CKCORE_PCREL_IMM10BY4 = 23 # /* disp ((S + A - P) >> 2) & 0x3ff  */
R_CKCORE_ADDR_HI16 = 24 # /* high & low 16 bit ADDR */
# /* ((S + A) >> 16) & 0xffff */ 
R_CKCORE_ADDR_LO16 = 25 # /* (S + A) & 0xffff */
R_CKCORE_GOTPC_HI16 = 26 # /* high & low 16 bit GOTPC */
# /* ((GOT + A - P) >> 16) & 0xffff */ 
R_CKCORE_GOTPC_LO16 = 27 # /* (GOT + A - P) & 0xffff */
R_CKCORE_GOTOFF_HI16 = 28 # /* high & low 16 bit GOTOFF */
# /* ((S + A - GOT) >> 16) & 0xffff */ 
R_CKCORE_GOTOFF_LO16 = 29 # /* (S + A - GOT) & 0xffff */
R_CKCORE_GOT12 = 30 # /* 12 bit disp GOT entry (G) */
R_CKCORE_GOT_HI16 = 31 # /* high & low 16 bit GOT */
# /* (G >> 16) & 0xffff */ 
R_CKCORE_GOT_LO16 = 32 # /* (G & 0xffff) */
R_CKCORE_PLT12 = 33 # /* 12 bit disp PLT entry (G) */
R_CKCORE_PLT_HI16 = 34 # /* high & low 16 bit PLT */
# /* (G >> 16) & 0xffff */ 
R_CKCORE_PLT_LO16 = 35 # /* G & 0xffff */
R_CKCORE_ADDRGOT_HI16 = 36 # /* high & low 16 bit ADDRGOT */
# /* (GOT + G * 4) & 0xffff */ 
R_CKCORE_ADDRGOT_LO16 = 37 # /* (GOT + G * 4) & 0xffff */
R_CKCORE_ADDRPLT_HI16 = 38 # /* high & low 16 bit ADDRPLT */
# /* ((GOT + G * 4) >> 16) & 0xFFFF */ 
R_CKCORE_ADDRPLT_LO16 = 39 # /* (GOT+G*4) & 0xffff */
R_CKCORE_PCREL_JSR_IMM26BY2 = 40 # /* disp ((S+A-P) >>1) & x3ffffff */
R_CKCORE_TOFFSET_LO16 = 41 # /* (S+A-BTEXT) & 0xffff */
R_CKCORE_DOFFSET_LO16 = 42 # /* (S+A-BTEXT) & 0xffff */
R_CKCORE_PCREL_IMM18BY2 = 43 # /* disp ((S+A-P) >>1) & 0x3ffff */
R_CKCORE_DOFFSET_IMM18 = 44 # /* disp (S+A-BDATA) & 0x3ffff */
R_CKCORE_DOFFSET_IMM18BY2 = 45 # /* disp ((S+A-BDATA)>>1) & 0x3ffff */
R_CKCORE_DOFFSET_IMM18BY4 = 46 # /* disp ((S+A-BDATA)>>2) & 0x3ffff */
R_CKCORE_GOT_IMM18BY4 = 48 # /* disp (G >> 2) */
R_CKCORE_PLT_IMM18BY4 = 49 # /* disp (G >> 2) */
R_CKCORE_PCREL_IMM7BY4 = 50 # /* disp ((S+A-P) >>2) & 0x7f */
R_CKCORE_TLS_LE32 = 51 # /* 32 bit offset to TLS block */
R_CKCORE_TLS_IE32 = 52
R_CKCORE_TLS_GD32 = 53
R_CKCORE_TLS_LDM32 = 54
R_CKCORE_TLS_LDO32 = 55
R_CKCORE_TLS_DTPMOD32 = 56
R_CKCORE_TLS_DTPOFF32 = 57
R_CKCORE_TLS_TPOFF32 = 58

# /* C-SKY elf header definition.  */
EF_CSKY_ABIMASK = 0XF0000000
EF_CSKY_OTHER = 0X0FFF0000
EF_CSKY_PROCESSOR = 0X0000FFFF
EF_CSKY_ABIV1 = 0X10000000
EF_CSKY_ABIV2 = 0X20000000

# /* C-SKY attributes section.  */
SHT_CSKY_ATTRIBUTES = (SHT_LOPROC + 1)

# /* IA-64 specific declarations.  */ 

# /* Processor specific flags for the Ehdr e_flags field.  */ 
EF_IA_64_MASKOS = 0x0000000f # /* os-specific flags */
EF_IA_64_ABI64 = 0x00000010 # /* 64-bit ABI */
EF_IA_64_ARCH = 0xff000000 # /* arch. version mask */

# /* Processor specific values for the Phdr p_type field.  */ 
PT_IA_64_ARCHEXT = (PT_LOPROC + 0) # /* arch extension bits */ 
PT_IA_64_UNWIND = (PT_LOPROC + 1) # /* ia64 unwind bits */ 
PT_IA_64_HP_OPT_ANOT = (PT_LOOS + 0x12)
PT_IA_64_HP_HSL_ANOT = (PT_LOOS + 0x13)
PT_IA_64_HP_STACK = (PT_LOOS + 0x14)

# /* Processor specific flags for the Phdr p_flags field.  */ 
PF_IA_64_NORECOV = 0x80000000 # /* spec insns w/o recovery */

# /* Processor specific values for the Shdr sh_type field.  */ 
SHT_IA_64_EXT = (SHT_LOPROC + 0) # /* extension bits */ 
SHT_IA_64_UNWIND = (SHT_LOPROC + 1) # /* unwind bits */ 

# /* Processor specific flags for the Shdr sh_flags field.  */ 
SHF_IA_64_SHORT = 0x10000000 # /* section near gp */
SHF_IA_64_NORECOV = 0x20000000 # /* spec insns w/o recovery */

# /* Processor specific values for the Dyn d_tag field.  */ 
DT_IA_64_PLT_RESERVE = (DT_LOPROC + 0)
DT_IA_64_NUM = 1

# /* IA-64 relocations.  */
R_IA64_NONE = 0x00 # /* none */
R_IA64_IMM14 = 0x21 # /* symbol + addend, add imm14 */
R_IA64_IMM22 = 0x22 # /* symbol + addend, add imm22 */
R_IA64_IMM64 = 0x23 # /* symbol + addend, mov imm64 */
R_IA64_DIR32MSB = 0x24 # /* symbol + addend, data4 MSB */
R_IA64_DIR32LSB = 0x25 # /* symbol + addend, data4 LSB */
R_IA64_DIR64MSB = 0x26 # /* symbol + addend, data8 MSB */
R_IA64_DIR64LSB = 0x27 # /* symbol + addend, data8 LSB */
R_IA64_GPREL22 = 0x2a # /* @gprel(sym + add), add imm22 */
R_IA64_GPREL64I = 0x2b # /* @gprel(sym + add), mov imm64 */
R_IA64_GPREL32MSB = 0x2c # /* @gprel(sym + add), data4 MSB */
R_IA64_GPREL32LSB = 0x2d # /* @gprel(sym + add), data4 LSB */
R_IA64_GPREL64MSB = 0x2e # /* @gprel(sym + add), data8 MSB */
R_IA64_GPREL64LSB = 0x2f # /* @gprel(sym + add), data8 LSB */
R_IA64_LTOFF22 = 0x32 # /* @ltoff(sym + add), add imm22 */
R_IA64_LTOFF64I = 0x33 # /* @ltoff(sym + add), mov imm64 */
R_IA64_PLTOFF22 = 0x3a # /* @pltoff(sym + add), add imm22 */
R_IA64_PLTOFF64I = 0x3b # /* @pltoff(sym + add), mov imm64 */
R_IA64_PLTOFF64MSB = 0x3e # /* @pltoff(sym + add), data8 MSB */
R_IA64_PLTOFF64LSB = 0x3f # /* @pltoff(sym + add), data8 LSB */
R_IA64_FPTR64I = 0x43 # /* @fptr(sym + add), mov imm64 */
R_IA64_FPTR32MSB = 0x44 # /* @fptr(sym + add), data4 MSB */
R_IA64_FPTR32LSB = 0x45 # /* @fptr(sym + add), data4 LSB */
R_IA64_FPTR64MSB = 0x46 # /* @fptr(sym + add), data8 MSB */
R_IA64_FPTR64LSB = 0x47 # /* @fptr(sym + add), data8 LSB */
R_IA64_PCREL60B = 0x48 # /* @pcrel(sym + add), brl */
R_IA64_PCREL21B = 0x49 # /* @pcrel(sym + add), ptb, call */
R_IA64_PCREL21M = 0x4a # /* @pcrel(sym + add), chk.s */
R_IA64_PCREL21F = 0x4b # /* @pcrel(sym + add), fchkf */
R_IA64_PCREL32MSB = 0x4c # /* @pcrel(sym + add), data4 MSB */
R_IA64_PCREL32LSB = 0x4d # /* @pcrel(sym + add), data4 LSB */
R_IA64_PCREL64MSB = 0x4e # /* @pcrel(sym + add), data8 MSB */
R_IA64_PCREL64LSB = 0x4f # /* @pcrel(sym + add), data8 LSB */
R_IA64_LTOFF_FPTR22 = 0x52 # /* @ltoff(@fptr(s+a)), imm22 */
R_IA64_LTOFF_FPTR64I = 0x53 # /* @ltoff(@fptr(s+a)), imm64 */
R_IA64_LTOFF_FPTR32MSB = 0x54 # /* @ltoff(@fptr(s+a)), data4 MSB */
R_IA64_LTOFF_FPTR32LSB = 0x55 # /* @ltoff(@fptr(s+a)), data4 LSB */
R_IA64_LTOFF_FPTR64MSB = 0x56 # /* @ltoff(@fptr(s+a)), data8 MSB */
R_IA64_LTOFF_FPTR64LSB = 0x57 # /* @ltoff(@fptr(s+a)), data8 LSB */
R_IA64_SEGREL32MSB = 0x5c # /* @segrel(sym + add), data4 MSB */
R_IA64_SEGREL32LSB = 0x5d # /* @segrel(sym + add), data4 LSB */
R_IA64_SEGREL64MSB = 0x5e # /* @segrel(sym + add), data8 MSB */
R_IA64_SEGREL64LSB = 0x5f # /* @segrel(sym + add), data8 LSB */
R_IA64_SECREL32MSB = 0x64 # /* @secrel(sym + add), data4 MSB */
R_IA64_SECREL32LSB = 0x65 # /* @secrel(sym + add), data4 LSB */
R_IA64_SECREL64MSB = 0x66 # /* @secrel(sym + add), data8 MSB */
R_IA64_SECREL64LSB = 0x67 # /* @secrel(sym + add), data8 LSB */
R_IA64_REL32MSB = 0x6c # /* data 4 + REL */
R_IA64_REL32LSB = 0x6d # /* data 4 + REL */
R_IA64_REL64MSB = 0x6e # /* data 8 + REL */
R_IA64_REL64LSB = 0x6f # /* data 8 + REL */
R_IA64_LTV32MSB = 0x74 # /* symbol + addend, data4 MSB */
R_IA64_LTV32LSB = 0x75 # /* symbol + addend, data4 LSB */
R_IA64_LTV64MSB = 0x76 # /* symbol + addend, data8 MSB */
R_IA64_LTV64LSB = 0x77 # /* symbol + addend, data8 LSB */
R_IA64_PCREL21BI = 0x79 # /* @pcrel(sym + add), 21bit inst */
R_IA64_PCREL22 = 0x7a # /* @pcrel(sym + add), 22bit inst */
R_IA64_PCREL64I = 0x7b # /* @pcrel(sym + add), 64bit inst */
R_IA64_IPLTMSB = 0x80 # /* dynamic reloc, imported PLT, MSB */
R_IA64_IPLTLSB = 0x81 # /* dynamic reloc, imported PLT, LSB */
R_IA64_COPY = 0x84 # /* copy relocation */
R_IA64_SUB = 0x85 # /* Addend and symbol difference */
R_IA64_LTOFF22X = 0x86 # /* LTOFF22, relaxable.  */
R_IA64_LDXMOV = 0x87 # /* Use of LTOFF22X.  */
R_IA64_TPREL14 = 0x91 # /* @tprel(sym + add), imm14 */
R_IA64_TPREL22 = 0x92 # /* @tprel(sym + add), imm22 */
R_IA64_TPREL64I = 0x93 # /* @tprel(sym + add), imm64 */
R_IA64_TPREL64MSB = 0x96 # /* @tprel(sym + add), data8 MSB */
R_IA64_TPREL64LSB = 0x97 # /* @tprel(sym + add), data8 LSB */
R_IA64_LTOFF_TPREL22 = 0x9a # /* @ltoff(@tprel(s+a)), imm2 */
R_IA64_DTPMOD64MSB = 0xa6 # /* @dtpmod(sym + add), data8 MSB */
R_IA64_DTPMOD64LSB = 0xa7 # /* @dtpmod(sym + add), data8 LSB */
R_IA64_LTOFF_DTPMOD22 = 0xaa # /* @ltoff(@dtpmod(sym + add)), imm22 */
R_IA64_DTPREL14 = 0xb1 # /* @dtprel(sym + add), imm14 */
R_IA64_DTPREL22 = 0xb2 # /* @dtprel(sym + add), imm22 */
R_IA64_DTPREL64I = 0xb3 # /* @dtprel(sym + add), imm64 */
R_IA64_DTPREL32MSB = 0xb4 # /* @dtprel(sym + add), data4 MSB */
R_IA64_DTPREL32LSB = 0xb5 # /* @dtprel(sym + add), data4 LSB */
R_IA64_DTPREL64MSB = 0xb6 # /* @dtprel(sym + add), data8 MSB */
R_IA64_DTPREL64LSB = 0xb7 # /* @dtprel(sym + add), data8 LSB */
R_IA64_LTOFF_DTPREL22 = 0xba # /* @ltoff(@dtprel(s+a)), imm22 */

# /* SH specific declarations */ 
# /* Processor specific flags for the ELF header e_flags field.  */ 
EF_SH_MACH_MASK = 0x1f
EF_SH_UNKNOWN = 0x0
EF_SH1 = 0x1
EF_SH2 = 0x2
EF_SH3 = 0x3
EF_SH_DSP = 0x4
EF_SH3_DSP = 0x5
EF_SH4AL_DSP = 0x6
EF_SH3E = 0x8
EF_SH4 = 0x9
EF_SH2E = 0xb
EF_SH4A = 0xc
EF_SH2A = 0xd
EF_SH4_NOFPU = 0x10
EF_SH4A_NOFPU = 0x11
EF_SH4_NOMMU_NOFPU = 0x12
EF_SH2A_NOFPU = 0x13
EF_SH3_NOMMU = 0x14
EF_SH2A_SH4_NOFPU = 0x15
EF_SH2A_SH3_NOFPU = 0x16
EF_SH2A_SH4 = 0x17
EF_SH2A_SH3E = 0x18

# /* SH relocs.  */
R_SH_NONE = 0
R_SH_DIR32 = 1
R_SH_REL32 = 2
R_SH_DIR8WPN = 3
R_SH_IND12W = 4
R_SH_DIR8WPL = 5
R_SH_DIR8WPZ = 6
R_SH_DIR8BP = 7
R_SH_DIR8W = 8
R_SH_DIR8L = 9
R_SH_SWITCH16 = 25
R_SH_SWITCH32 = 26
R_SH_USES = 27
R_SH_COUNT = 28
R_SH_ALIGN = 29
R_SH_CODE = 30
R_SH_DATA = 31
R_SH_LABEL = 32
R_SH_SWITCH8 = 33
R_SH_GNU_VTINHERIT = 34
R_SH_GNU_VTENTRY = 35
R_SH_TLS_GD_32 = 144
R_SH_TLS_LD_32 = 145
R_SH_TLS_LDO_32 = 146
R_SH_TLS_IE_32 = 147
R_SH_TLS_LE_32 = 148
R_SH_TLS_DTPMOD32 = 149
R_SH_TLS_DTPOFF32 = 150
R_SH_TLS_TPOFF32 = 151
R_SH_GOT32 = 160
R_SH_PLT32 = 161
R_SH_COPY = 162
R_SH_GLOB_DAT = 163
R_SH_JMP_SLOT = 164
R_SH_RELATIVE = 165
R_SH_GOTOFF = 166
R_SH_GOTPC = 167
# /* Keep this the last entry.  */
R_SH_NUM = 256

# /* S/390 specific definitions.  */
# /* Valid values for the e_flags field.  */ 
EF_S390_HIGH_GPRS = 0x00000001 # /* High GPRs kernel facility needed.  */

# /* Additional s390 relocs */ 
R_390_NONE = 0 # /* No reloc.  */
R_390_8 = 1 # /* Direct 8 bit.  */
R_390_12 = 2 # /* Direct 12 bit.  */
R_390_16 = 3 # /* Direct 16 bit.  */
R_390_32 = 4 # /* Direct 32 bit.  */
R_390_PC32 = 5 # /* PC relative 32 bit. */
R_390_GOT12 = 6 # /* 12 bit GOT offset.  */
R_390_GOT32 = 7 # /* 32 bit GOT offset.  */
R_390_PLT32 = 8 # /* 32 bit PC relative PLT address.  */
R_390_COPY = 9 # /* Copy symbol at runtime.  */
R_390_GLOB_DAT = 10 # /* Create GOT entry.  */
R_390_JMP_SLOT = 11 # /* Create PLT entry.  */
R_390_RELATIVE = 12 # /* Adjust by program base.  */
R_390_GOTOFF32 = 13 # /* 32 bit offset to GOT.   */
R_390_GOTPC = 14 # /* 32 bit PC relative offset to GOT.  */
R_390_GOT16 = 15 # /* 16 bit GOT offset.  */
R_390_PC16 = 16 # /* PC relative 16 bit.    */
R_390_PC16DBL = 17 # /* PC relative 16 bit shifted by 1.  */
R_390_PLT16DBL = 18 # /* 16 bit PC rel. PLT shifted by 1.  */
R_390_PC32DBL = 19 # /* PC relative 32 bit shifted by 1.  */
R_390_PLT32DBL = 20 # /* 32 bit PC rel. PLT shifted by 1.  */
R_390_GOTPCDBL = 21 # /* 32 bit PC rel. GOT shifted by 1.  */
R_390_64 = 22 # /* Direct 64 bit.  */
R_390_PC64 = 23 # /* PC relative 64 bit.    */
R_390_GOT64 = 24 # /* 64 bit GOT offset.  */
R_390_PLT64 = 25 # /* 64 bit PC relative PLT address.  */
R_390_GOTENT = 26 # /* 32 bit PC rel. to GOT entry >> 1. */
R_390_GOTOFF16 = 27 # /* 16 bit offset to GOT. */
R_390_GOTOFF64 = 28 # /* 64 bit offset to GOT. */
R_390_GOTPLT12 = 29 # /* 12 bit offset to jump slot.    */
R_390_GOTPLT16 = 30 # /* 16 bit offset to jump slot.    */
R_390_GOTPLT32 = 31 # /* 32 bit offset to jump slot.    */
R_390_GOTPLT64 = 32 # /* 64 bit offset to jump slot.    */
R_390_GOTPLTENT = 33 # /* 32 bit rel. offset to jump slot.  */
R_390_PLTOFF16 = 34 # /* 16 bit offset from GOT to PLT. */
R_390_PLTOFF32 = 35 # /* 32 bit offset from GOT to PLT. */
R_390_PLTOFF64 = 36 # /* 16 bit offset from GOT to PLT. */
R_390_TLS_LOAD = 37 # /* Tag for load insn in TLS code.  */
R_390_TLS_GDCALL = 38 # /* Tag for function call in general
#                        dynamic TLS code. */
R_390_TLS_LDCALL = 39 # /* Tag for function call in local
#                        dynamic TLS code. */
R_390_TLS_GD32 = 40 # /* Direct 32 bit for general dynamic
#                        thread local data.  */
R_390_TLS_GD64 = 41 # /* Direct 64 bit for general dynamic
#                       thread local data.  */
R_390_TLS_GOTIE12 = 42 # /* 12 bit GOT offset for static TLS
#                        block offset.  */
R_390_TLS_GOTIE32 = 43 # /* 32 bit GOT offset for static TLS
#                        block offset.  */
R_390_TLS_GOTIE64 = 44 # /* 64 bit GOT offset for static TLS
#                        block offset. */
R_390_TLS_LDM32 = 45 # /* Direct 32 bit for local dynamic
#                        thread local data in LE code.  */
R_390_TLS_LDM64 = 46 # /* Direct 64 bit for local dynamic
#                        thread local data in LE code.  */
R_390_TLS_IE32 = 47 # /* 32 bit address of GOT entry for
#                        negated static TLS block offset.  */
R_390_TLS_IE64 = 48 # /* 64 bit address of GOT entry for
#                        negated static TLS block offset.  */
R_390_TLS_IEENT = 49 # /* 32 bit rel. offset to GOT entry for
#                        negated static TLS block offset.  */
R_390_TLS_LE32 = 50 # /* 32 bit negated offset relative to
#                        static TLS block.  */
R_390_TLS_LE64 = 51 # /* 64 bit negated offset relative to
#                        static TLS block.  */
R_390_TLS_LDO32 = 52 # /* 32 bit offset relative to TLS
#                        block.  */
R_390_TLS_LDO64 = 53 # /* 64 bit offset relative to TLS
#                        block.  */
R_390_TLS_DTPMOD = 54 # /* ID of module containing symbol.  */
R_390_TLS_DTPOFF = 55 # /* Offset in TLS block.  */
R_390_TLS_TPOFF = 56 # /* Negated offset in static TLS
#                        block.  */
R_390_20 = 57 # /* Direct 20 bit.  */
R_390_GOT20 = 58 # /* 20 bit GOT offset.  */
R_390_GOTPLT20 = 59 # /* 20 bit offset to jump slot.  */
R_390_TLS_GOTIE20 = 60 # /* 20 bit GOT offset for static TLS
#                        block offset.  */
R_390_IRELATIVE = 61 # /* STT_GNU_IFUNC relocation.  */
# /* Keep this the last entry.  */ 
R_390_NUM = 62

# /* CRIS relocations.  */
R_CRIS_NONE = 0
R_CRIS_8 = 1
R_CRIS_16 = 2
R_CRIS_32 = 3
R_CRIS_8_PCREL = 4
R_CRIS_16_PCREL = 5
R_CRIS_32_PCREL = 6
R_CRIS_GNU_VTINHERIT = 7
R_CRIS_GNU_VTENTRY = 8
R_CRIS_COPY = 9
R_CRIS_GLOB_DAT = 10
R_CRIS_JUMP_SLOT = 11
R_CRIS_RELATIVE = 12
R_CRIS_16_GOT = 13
R_CRIS_32_GOT = 14
R_CRIS_16_GOTPLT = 15
R_CRIS_32_GOTPLT = 16
R_CRIS_32_GOTREL = 17
R_CRIS_32_PLT_GOTREL = 18
R_CRIS_32_PLT_PCREL = 19

R_CRIS_NUM = 20

# /* AMD x86-64 relocations.  */
R_X86_64_NONE = 0 # /* No reloc */
R_X86_64_64 = 1 # /* Direct 64 bit  */
R_X86_64_PC32 = 2 # /* PC relative 32 bit signed */
R_X86_64_GOT32 = 3 # /* 32 bit GOT entry */
R_X86_64_PLT32 = 4 # /* 32 bit PLT address */
R_X86_64_COPY = 5 # /* Copy symbol at runtime */
R_X86_64_GLOB_DAT = 6 # /* Create GOT entry */
R_X86_64_JUMP_SLOT = 7 # /* Create PLT entry */
R_X86_64_RELATIVE = 8 # /* Adjust by program base */
R_X86_64_GOTPCREL = 9 # /* 32 bit signed PC relative
#                        offset to GOT */
R_X86_64_32 = 10 # /* Direct 32 bit zero extended */
R_X86_64_32S = 11 # /* Direct 32 bit sign extended */
R_X86_64_16 = 12 # /* Direct 16 bit zero extended */
R_X86_64_PC16 = 13 # /* 16 bit sign extended pc relative */
R_X86_64_8 = 14 # /* Direct 8 bit sign extended  */
R_X86_64_PC8 = 15 # /* 8 bit sign extended pc relative */
R_X86_64_DTPMOD64 = 16 # /* ID of module containing symbol */
R_X86_64_DTPOFF64 = 17 # /* Offset in module's TLS block */
R_X86_64_TPOFF64 = 18 # /* Offset in initial TLS block */
R_X86_64_TLSGD = 19 # /* 32 bit signed PC relative offset
#                        to two GOT entries for GD symbol */
R_X86_64_TLSLD = 20 # /* 32 bit signed PC relative offset
#                        to two GOT entries for LD symbol */
R_X86_64_DTPOFF32 = 21 # /* Offset in TLS block */
R_X86_64_GOTTPOFF = 22 # /* 32 bit signed PC relative offset
#                        to GOT entry for IE symbol */
R_X86_64_TPOFF32 = 23 # /* Offset in initial TLS block */
R_X86_64_PC64 = 24 # /* PC relative 64 bit */
R_X86_64_GOTOFF64 = 25 # /* 64 bit offset to GOT */
R_X86_64_GOTPC32 = 26 # /* 32 bit signed pc relative
#                        offset to GOT */
R_X86_64_GOT64 = 27 # /* 64-bit GOT entry offset */
R_X86_64_GOTPCREL64 = 28 # /* 64-bit PC relative offset
#                        to GOT entry */
R_X86_64_GOTPC64 = 29 # /* 64-bit PC relative offset to GOT */
R_X86_64_GOTPLT64 = 30 # /* like GOT64, says PLT entry needed */
R_X86_64_PLTOFF64 = 31 # /* 64-bit GOT relative offset
#                        to PLT entry */
R_X86_64_SIZE32 = 32 # /* Size of symbol plus 32-bit addend */
R_X86_64_SIZE64 = 33 # /* Size of symbol plus 64-bit addend */
R_X86_64_GOTPC32_TLSDESC = 34 # /* GOT offset for TLS descriptor.  */
R_X86_64_TLSDESC_CALL = 35 # /* Marker for call through TLS
#                        descriptor.  */
R_X86_64_TLSDESC = 36 # /* TLS descriptor.  */
R_X86_64_IRELATIVE = 37 # /* Adjust indirectly by program base */
R_X86_64_RELATIVE64 = 38 # /* 64-bit adjust by program base */
# /* 39 Reserved was R_X86_64_PC32_BND */ 
# /* 40 Reserved was R_X86_64_PLT32_BND */ 
R_X86_64_GOTPCRELX = 41 # /* Load from 32 bit signed pc relative
#                        offset to GOT entry without REX
#                        prefix, relaxable.  */
R_X86_64_REX_GOTPCRELX = 42 # /* Load from 32 bit signed pc relative
#                       offset to GOT entry with REX prefix,
#                       relaxable.  */
R_X86_64_NUM = 43

# /* x86-64 sh_type values.  */
SHT_X86_64_UNWIND = 0x70000001 # /* Unwind information.  */


# /* AM33 relocations.  */ 
R_MN10300_NONE = 0 # /* No reloc.  */
R_MN10300_32 = 1 # /* Direct 32 bit.  */
R_MN10300_16 = 2 # /* Direct 16 bit.  */
R_MN10300_8 = 3 # /* Direct 8 bit.  */
R_MN10300_PCREL32 = 4 # /* PC-relative 32-bit.  */
R_MN10300_PCREL16 = 5 # /* PC-relative 16-bit signed.  */
R_MN10300_PCREL8 = 6 # /* PC-relative 8-bit signed.  */
R_MN10300_GNU_VTINHERIT = 7 # /* Ancient C++ vtable garbage... */
R_MN10300_GNU_VTENTRY = 8 # /* ... collection annotation.  */
R_MN10300_24 = 9 # /* Direct 24 bit.  */
R_MN10300_GOTPC32 = 10 # /* 32-bit PCrel offset to GOT.  */
R_MN10300_GOTPC16 = 11 # /* 16-bit PCrel offset to GOT.  */
R_MN10300_GOTOFF32 = 12 # /* 32-bit offset from GOT.  */
R_MN10300_GOTOFF24 = 13 # /* 24-bit offset from GOT.  */
R_MN10300_GOTOFF16 = 14 # /* 16-bit offset from GOT.  */
R_MN10300_PLT32 = 15 # /* 32-bit PCrel to PLT entry.  */
R_MN10300_PLT16 = 16 # /* 16-bit PCrel to PLT entry.  */
R_MN10300_GOT32 = 17 # /* 32-bit offset to GOT entry.  */
R_MN10300_GOT24 = 18 # /* 24-bit offset to GOT entry.  */
R_MN10300_GOT16 = 19 # /* 16-bit offset to GOT entry.  */
R_MN10300_COPY = 20 # /* Copy symbol at runtime.  */
R_MN10300_GLOB_DAT = 21 # /* Create GOT entry.  */
R_MN10300_JMP_SLOT = 22 # /* Create PLT entry.  */
R_MN10300_RELATIVE = 23 # /* Adjust by program base.  */
R_MN10300_TLS_GD = 24 # /* 32-bit offset for global dynamic.  */
R_MN10300_TLS_LD = 25 # /* 32-bit offset for local dynamic.  */
R_MN10300_TLS_LDO = 26 # /* Module-relative offset.  */
R_MN10300_TLS_GOTIE = 27 # /* GOT offset for static TLS block
#                        offset.  */
R_MN10300_TLS_IE = 28 # /* GOT address for static TLS block
#                        offset.  */
R_MN10300_TLS_LE = 29 # /* Offset relative to static TLS
#                        block.  */
R_MN10300_TLS_DTPMOD = 30 # /* ID of module containing symbol.  */
R_MN10300_TLS_DTPOFF = 31 # /* Offset in module TLS block.  */
R_MN10300_TLS_TPOFF = 32 # /* Offset in static TLS block.  */
R_MN10300_SYM_DIFF = 33 # /* Adjustment for next reloc as needed
#                        by linker relaxation.  */
R_MN10300_ALIGN = 34 # /* Alignment requirement for linker
#                        relaxation.  */
R_MN10300_NUM = 35

# /* M32R relocs.  */
R_M32R_NONE = 0 # /* No reloc. */
R_M32R_16 = 1 # /* Direct 16 bit. */
R_M32R_32 = 2 # /* Direct 32 bit. */
R_M32R_24 = 3 # /* Direct 24 bit. */
R_M32R_10_PCREL = 4 # /* PC relative 10 bit shifted. */
R_M32R_18_PCREL = 5 # /* PC relative 18 bit shifted. */
R_M32R_26_PCREL = 6 # /* PC relative 26 bit shifted. */
R_M32R_HI16_ULO = 7 # /* High 16 bit with unsigned low. */
R_M32R_HI16_SLO = 8 # /* High 16 bit with signed low. */
R_M32R_LO16 = 9 # /* Low 16 bit. */
R_M32R_SDA16 = 10 # /* 16 bit offset in SDA. */
R_M32R_GNU_VTINHERIT = 11
R_M32R_GNU_VTENTRY = 12
# /* M32R relocs use SHT_RELA.  */
R_M32R_16_RELA = 33 # /* Direct 16 bit. */
R_M32R_32_RELA = 34 # /* Direct 32 bit. */
R_M32R_24_RELA = 35 # /* Direct 24 bit. */
R_M32R_10_PCREL_RELA = 36 # /* PC relative 10 bit shifted. */
R_M32R_18_PCREL_RELA = 37 # /* PC relative 18 bit shifted. */
R_M32R_26_PCREL_RELA = 38 # /* PC relative 26 bit shifted. */
R_M32R_HI16_ULO_RELA = 39 # /* High 16 bit with unsigned low */
R_M32R_HI16_SLO_RELA = 40 # /* High 16 bit with signed low */
R_M32R_LO16_RELA = 41 # /* Low 16 bit */
R_M32R_SDA16_RELA = 42 # /* 16 bit offset in SDA */
R_M32R_RELA_GNU_VTINHERIT = 43
R_M32R_RELA_GNU_VTENTRY = 44
R_M32R_REL32 = 45 # /* PC relative 32 bit.  */

R_M32R_GOT24 = 48 # /* 24 bit GOT entry */
R_M32R_26_PLTREL = 49 # /* 26 bit PC relative to PLT shifted */
R_M32R_COPY = 50 # /* Copy symbol at runtime */
R_M32R_GLOB_DAT = 51 # /* Create GOT entry */
R_M32R_JMP_SLOT = 52 # /* Create PLT entry */
R_M32R_RELATIVE = 53 # /* Adjust by program base */
R_M32R_GOTOFF = 54 # /* 24 bit offset to GOT */
R_M32R_GOTPC24 = 55 # /* 24 bit PC relative offset to GOT */
R_M32R_GOT16_HI_ULO = 56 # /* High 16 bit GOT entry with unsigned
#                        low */
R_M32R_GOT16_HI_SLO = 57 # /* High 16 bit GOT entry with signed
#                        low */
R_M32R_GOT16_LO = 58 # /* Low 16 bit GOT entry */
R_M32R_GOTPC_HI_ULO = 59 # /* High 16 bit PC relative offset to
#                        GOT with unsigned low */
R_M32R_GOTPC_HI_SLO = 60 # /* High 16 bit PC relative offset to
#                        GOT with signed low */
R_M32R_GOTPC_LO = 61 # /* Low 16 bit PC relative offset to
#                        GOT */
R_M32R_GOTOFF_HI_ULO = 62 # /* High 16 bit offset to GOT
#                        with unsigned low */
R_M32R_GOTOFF_HI_SLO = 63 # /* High 16 bit offset to GOT
#                        with signed low */
R_M32R_GOTOFF_LO = 64 # /* Low 16 bit offset to GOT */
R_M32R_NUM = 256 # /* Keep this the last entry. */

# /* MicroBlaze relocations */ 
R_MICROBLAZE_NONE = 0 # /* No reloc. */
R_MICROBLAZE_32 = 1 # /* Direct 32 bit. */
R_MICROBLAZE_32_PCREL = 2 # /* PC relative 32 bit. */
R_MICROBLAZE_64_PCREL = 3 # /* PC relative 64 bit. */
R_MICROBLAZE_32_PCREL_LO = 4 # /* Low 16 bits of PCREL32. */
R_MICROBLAZE_64 = 5 # /* Direct 64 bit. */
R_MICROBLAZE_32_LO = 6 # /* Low 16 bit. */
R_MICROBLAZE_SRO32 = 7 # /* Read-only small data area. */
R_MICROBLAZE_SRW32 = 8 # /* Read-write small data area. */
R_MICROBLAZE_64_NONE = 9 # /* No reloc. */
R_MICROBLAZE_32_SYM_OP_SYM = 10 # /* Symbol Op Symbol relocation. */
R_MICROBLAZE_GNU_VTINHERIT = 11 # /* GNU C++ vtable hierarchy. */
R_MICROBLAZE_GNU_VTENTRY = 12 # /* GNU C++ vtable member usage. */
R_MICROBLAZE_GOTPC_64 = 13 # /* PC-relative GOT offset.  */
R_MICROBLAZE_GOT_64 = 14 # /* GOT entry offset.  */
R_MICROBLAZE_PLT_64 = 15 # /* PLT offset (PC-relative).  */
R_MICROBLAZE_REL = 16 # /* Adjust by program base.  */
R_MICROBLAZE_JUMP_SLOT = 17 # /* Create PLT entry.  */
R_MICROBLAZE_GLOB_DAT = 18 # /* Create GOT entry.  */
R_MICROBLAZE_GOTOFF_64 = 19 # /* 64 bit offset to GOT. */
R_MICROBLAZE_GOTOFF_32 = 20 # /* 32 bit offset to GOT. */
R_MICROBLAZE_COPY = 21 # /* Runtime copy.  */
R_MICROBLAZE_TLS = 22 # /* TLS Reloc. */
R_MICROBLAZE_TLSGD = 23 # /* TLS General Dynamic. */
R_MICROBLAZE_TLSLD = 24 # /* TLS Local Dynamic. */
R_MICROBLAZE_TLSDTPMOD32 = 25 # /* TLS Module ID. */
R_MICROBLAZE_TLSDTPREL32 = 26 # /* TLS Offset Within TLS Block. */
R_MICROBLAZE_TLSDTPREL64 = 27 # /* TLS Offset Within TLS Block. */
R_MICROBLAZE_TLSGOTTPREL32 = 28 # /* TLS Offset From Thread Pointer. */
R_MICROBLAZE_TLSTPREL32 = 29 # /* TLS Offset From Thread Pointer. */

# /* Legal values for d_tag (dynamic entry type).  */ 
DT_NIOS2_GP = 0x70000002 # /* Address of _gp.  */

# /* Nios II relocations.  */ 
R_NIOS2_NONE = 0 # /* No reloc.  */
R_NIOS2_S16 = 1 # /* Direct signed 16 bit.  */
R_NIOS2_U16 = 2 # /* Direct unsigned 16 bit.  */
R_NIOS2_PCREL16 = 3 # /* PC relative 16 bit.  */
R_NIOS2_CALL26 = 4 # /* Direct call.  */
R_NIOS2_IMM5 = 5 # /* 5 bit constant expression.  */
R_NIOS2_CACHE_OPX = 6 # /* 5 bit expression, shift 22.  */
R_NIOS2_IMM6 = 7 # /* 6 bit constant expression.  */
R_NIOS2_IMM8 = 8 # /* 8 bit constant expression.  */
R_NIOS2_HI16 = 9 # /* High 16 bit.  */
R_NIOS2_LO16 = 10 # /* Low 16 bit.  */
R_NIOS2_HIADJ16 = 11 # /* High 16 bit, adjusted.  */
R_NIOS2_BFD_RELOC_32 = 12 # /* 32 bit symbol value + addend.  */
R_NIOS2_BFD_RELOC_16 = 13 # /* 16 bit symbol value + addend.  */
R_NIOS2_BFD_RELOC_8 = 14 # /* 8 bit symbol value + addend.  */
R_NIOS2_GPREL = 15 # /* 16 bit GP pointer offset.  */
R_NIOS2_GNU_VTINHERIT = 16 # /* GNU C++ vtable hierarchy.  */
R_NIOS2_GNU_VTENTRY = 17 # /* GNU C++ vtable member usage.  */
R_NIOS2_UJMP = 18 # /* Unconditional branch.  */
R_NIOS2_CJMP = 19 # /* Conditional branch.  */
R_NIOS2_CALLR = 20 # /* Indirect call through register.  */
R_NIOS2_ALIGN = 21 # /* Alignment requirement for
#                        linker relaxation.  */
R_NIOS2_GOT16 = 22 # /* 16 bit GOT entry.  */
R_NIOS2_CALL16 = 23 # /* 16 bit GOT entry for function.  */
R_NIOS2_GOTOFF_LO = 24 # /* %lo of offset to GOT pointer.  */
R_NIOS2_GOTOFF_HA = 25 # /* %hiadj of offset to GOT pointer.  */
R_NIOS2_PCREL_LO = 26 # /* %lo of PC relative offset.  */
R_NIOS2_PCREL_HA = 27 # /* %hiadj of PC relative offset.  */
R_NIOS2_TLS_GD16 = 28 # /* 16 bit GOT offset for TLS GD.  */
R_NIOS2_TLS_LDM16 = 29 # /* 16 bit GOT offset for TLS LDM.  */
R_NIOS2_TLS_LDO16 = 30 # /* 16 bit module relative offset.  */
R_NIOS2_TLS_IE16 = 31 # /* 16 bit GOT offset for TLS IE.  */
R_NIOS2_TLS_LE16 = 32 # /* 16 bit LE TP-relative offset.  */
R_NIOS2_TLS_DTPMOD = 33 # /* Module number.  */
R_NIOS2_TLS_DTPREL = 34 # /* Module-relative offset.  */
R_NIOS2_TLS_TPREL = 35 # /* TP-relative offset.  */
R_NIOS2_COPY = 36 # /* Copy symbol at runtime.  */
R_NIOS2_GLOB_DAT = 37 # /* Create GOT entry.  */
R_NIOS2_JUMP_SLOT = 38 # /* Create PLT entry.  */
R_NIOS2_RELATIVE = 39 # /* Adjust by program base.  */
R_NIOS2_GOTOFF = 40 # /* 16 bit offset to GOT pointer.  */
R_NIOS2_CALL26_NOAT = 41 # /* Direct call in .noat section.  */
R_NIOS2_GOT_LO = 42 # /* %lo() of GOT entry.  */
R_NIOS2_GOT_HA = 43 # /* %hiadj() of GOT entry.  */
R_NIOS2_CALL_LO = 44 # /* %lo() of function GOT entry.  */
R_NIOS2_CALL_HA = 45 # /* %hiadj() of function GOT entry.  */

# /* TILEPro relocations.  */ 
R_TILEPRO_NONE = 0 # /* No reloc */
R_TILEPRO_32 = 1 # /* Direct 32 bit */
R_TILEPRO_16 = 2 # /* Direct 16 bit */
R_TILEPRO_8 = 3 # /* Direct 8 bit */
R_TILEPRO_32_PCREL = 4 # /* PC relative 32 bit */
R_TILEPRO_16_PCREL = 5 # /* PC relative 16 bit */
R_TILEPRO_8_PCREL = 6 # /* PC relative 8 bit */
R_TILEPRO_LO16 = 7 # /* Low 16 bit */
R_TILEPRO_HI16 = 8 # /* High 16 bit */
R_TILEPRO_HA16 = 9 # /* High 16 bit, adjusted */
R_TILEPRO_COPY = 10 # /* Copy relocation */
R_TILEPRO_GLOB_DAT = 11 # /* Create GOT entry */
R_TILEPRO_JMP_SLOT = 12 # /* Create PLT entry */
R_TILEPRO_RELATIVE = 13 # /* Adjust by program base */
R_TILEPRO_BROFF_X1 = 14 # /* X1 pipe branch offset */
R_TILEPRO_JOFFLONG_X1 = 15 # /* X1 pipe jump offset */
R_TILEPRO_JOFFLONG_X1_PLT = 16 # /* X1 pipe jump offset to PLT */
R_TILEPRO_IMM8_X0 = 17 # /* X0 pipe 8-bit */
R_TILEPRO_IMM8_Y0 = 18 # /* Y0 pipe 8-bit */
R_TILEPRO_IMM8_X1 = 19 # /* X1 pipe 8-bit */
R_TILEPRO_IMM8_Y1 = 20 # /* Y1 pipe 8-bit */
R_TILEPRO_MT_IMM15_X1 = 21 # /* X1 pipe mtspr */
R_TILEPRO_MF_IMM15_X1 = 22 # /* X1 pipe mfspr */
R_TILEPRO_IMM16_X0 = 23 # /* X0 pipe 16-bit */
R_TILEPRO_IMM16_X1 = 24 # /* X1 pipe 16-bit */
R_TILEPRO_IMM16_X0_LO = 25 # /* X0 pipe low 16-bit */
R_TILEPRO_IMM16_X1_LO = 26 # /* X1 pipe low 16-bit */
R_TILEPRO_IMM16_X0_HI = 27 # /* X0 pipe high 16-bit */
R_TILEPRO_IMM16_X1_HI = 28 # /* X1 pipe high 16-bit */
R_TILEPRO_IMM16_X0_HA = 29 # /* X0 pipe high 16-bit, adjusted */
R_TILEPRO_IMM16_X1_HA = 30 # /* X1 pipe high 16-bit, adjusted */
R_TILEPRO_IMM16_X0_PCREL = 31 # /* X0 pipe PC relative 16 bit */
R_TILEPRO_IMM16_X1_PCREL = 32 # /* X1 pipe PC relative 16 bit */
R_TILEPRO_IMM16_X0_LO_PCREL = 33 # /* X0 pipe PC relative low 16 bit */
R_TILEPRO_IMM16_X1_LO_PCREL = 34 # /* X1 pipe PC relative low 16 bit */
R_TILEPRO_IMM16_X0_HI_PCREL = 35 # /* X0 pipe PC relative high 16 bit */
R_TILEPRO_IMM16_X1_HI_PCREL = 36 # /* X1 pipe PC relative high 16 bit */
R_TILEPRO_IMM16_X0_HA_PCREL = 37 # /* X0 pipe PC relative ha() 16 bit */
R_TILEPRO_IMM16_X1_HA_PCREL = 38 # /* X1 pipe PC relative ha() 16 bit */
R_TILEPRO_IMM16_X0_GOT = 39 # /* X0 pipe 16-bit GOT offset */
R_TILEPRO_IMM16_X1_GOT = 40 # /* X1 pipe 16-bit GOT offset */
R_TILEPRO_IMM16_X0_GOT_LO = 41 # /* X0 pipe low 16-bit GOT offset */
R_TILEPRO_IMM16_X1_GOT_LO = 42 # /* X1 pipe low 16-bit GOT offset */
R_TILEPRO_IMM16_X0_GOT_HI = 43 # /* X0 pipe high 16-bit GOT offset */
R_TILEPRO_IMM16_X1_GOT_HI = 44 # /* X1 pipe high 16-bit GOT offset */
R_TILEPRO_IMM16_X0_GOT_HA = 45 # /* X0 pipe ha() 16-bit GOT offset */
R_TILEPRO_IMM16_X1_GOT_HA = 46 # /* X1 pipe ha() 16-bit GOT offset */
R_TILEPRO_MMSTART_X0 = 47 # /* X0 pipe mm "start" */
R_TILEPRO_MMEND_X0 = 48 # /* X0 pipe mm "end" */
R_TILEPRO_MMSTART_X1 = 49 # /* X1 pipe mm "start" */
R_TILEPRO_MMEND_X1 = 50 # /* X1 pipe mm "end" */
R_TILEPRO_SHAMT_X0 = 51 # /* X0 pipe shift amount */
R_TILEPRO_SHAMT_X1 = 52 # /* X1 pipe shift amount */
R_TILEPRO_SHAMT_Y0 = 53 # /* Y0 pipe shift amount */
R_TILEPRO_SHAMT_Y1 = 54 # /* Y1 pipe shift amount */
R_TILEPRO_DEST_IMM8_X1 = 55 # /* X1 pipe destination 8-bit */
# /* Relocs 56-59 are currently not defined.  */ 
R_TILEPRO_TLS_GD_CALL = 60 # /* "jal" for TLS GD */
R_TILEPRO_IMM8_X0_TLS_GD_ADD = 61 # /* X0 pipe "addi" for TLS GD */
R_TILEPRO_IMM8_X1_TLS_GD_ADD = 62 # /* X1 pipe "addi" for TLS GD */
R_TILEPRO_IMM8_Y0_TLS_GD_ADD = 63 # /* Y0 pipe "addi" for TLS GD */
R_TILEPRO_IMM8_Y1_TLS_GD_ADD = 64 # /* Y1 pipe "addi" for TLS GD */
R_TILEPRO_TLS_IE_LOAD = 65 # /* "lw_tls" for TLS IE */
R_TILEPRO_IMM16_X0_TLS_GD = 66 # /* X0 pipe 16-bit TLS GD offset */
R_TILEPRO_IMM16_X1_TLS_GD = 67 # /* X1 pipe 16-bit TLS GD offset */
R_TILEPRO_IMM16_X0_TLS_GD_LO = 68 # /* X0 pipe low 16-bit TLS GD offset */
R_TILEPRO_IMM16_X1_TLS_GD_LO = 69 # /* X1 pipe low 16-bit TLS GD offset */
R_TILEPRO_IMM16_X0_TLS_GD_HI = 70 # /* X0 pipe high 16-bit TLS GD offset */
R_TILEPRO_IMM16_X1_TLS_GD_HI = 71 # /* X1 pipe high 16-bit TLS GD offset */
R_TILEPRO_IMM16_X0_TLS_GD_HA = 72 # /* X0 pipe ha() 16-bit TLS GD offset */
R_TILEPRO_IMM16_X1_TLS_GD_HA = 73 # /* X1 pipe ha() 16-bit TLS GD offset */
R_TILEPRO_IMM16_X0_TLS_IE = 74 # /* X0 pipe 16-bit TLS IE offset */
R_TILEPRO_IMM16_X1_TLS_IE = 75 # /* X1 pipe 16-bit TLS IE offset */
R_TILEPRO_IMM16_X0_TLS_IE_LO = 76 # /* X0 pipe low 16-bit TLS IE offset */
R_TILEPRO_IMM16_X1_TLS_IE_LO = 77 # /* X1 pipe low 16-bit TLS IE offset */
R_TILEPRO_IMM16_X0_TLS_IE_HI = 78 # /* X0 pipe high 16-bit TLS IE offset */
R_TILEPRO_IMM16_X1_TLS_IE_HI = 79 # /* X1 pipe high 16-bit TLS IE offset */
R_TILEPRO_IMM16_X0_TLS_IE_HA = 80 # /* X0 pipe ha() 16-bit TLS IE offset */
R_TILEPRO_IMM16_X1_TLS_IE_HA = 81 # /* X1 pipe ha() 16-bit TLS IE offset */
R_TILEPRO_TLS_DTPMOD32 = 82 # /* ID of module containing symbol */
R_TILEPRO_TLS_DTPOFF32 = 83 # /* Offset in TLS block */
R_TILEPRO_TLS_TPOFF32 = 84 # /* Offset in static TLS block */
R_TILEPRO_IMM16_X0_TLS_LE = 85 # /* X0 pipe 16-bit TLS LE offset */
R_TILEPRO_IMM16_X1_TLS_LE = 86 # /* X1 pipe 16-bit TLS LE offset */
R_TILEPRO_IMM16_X0_TLS_LE_LO = 87 # /* X0 pipe low 16-bit TLS LE offset */
R_TILEPRO_IMM16_X1_TLS_LE_LO = 88 # /* X1 pipe low 16-bit TLS LE offset */
R_TILEPRO_IMM16_X0_TLS_LE_HI = 89 # /* X0 pipe high 16-bit TLS LE offset */
R_TILEPRO_IMM16_X1_TLS_LE_HI = 90 # /* X1 pipe high 16-bit TLS LE offset */
R_TILEPRO_IMM16_X0_TLS_LE_HA = 91 # /* X0 pipe ha() 16-bit TLS LE offset */
R_TILEPRO_IMM16_X1_TLS_LE_HA = 92 # /* X1 pipe ha() 16-bit TLS LE offset */

R_TILEPRO_GNU_VTINHERIT = 128 # /* GNU C++ vtable hierarchy */
R_TILEPRO_GNU_VTENTRY = 129 # /* GNU C++ vtable member usage */

R_TILEPRO_NUM = 130

# /* TILE-Gx relocations.  */
R_TILEGX_NONE = 0 # /* No reloc */
R_TILEGX_64 = 1 # /* Direct 64 bit */
R_TILEGX_32 = 2 # /* Direct 32 bit */
R_TILEGX_16 = 3 # /* Direct 16 bit */
R_TILEGX_8 = 4 # /* Direct 8 bit */
R_TILEGX_64_PCREL = 5 # /* PC relative 64 bit */
R_TILEGX_32_PCREL = 6 # /* PC relative 32 bit */
R_TILEGX_16_PCREL = 7 # /* PC relative 16 bit */
R_TILEGX_8_PCREL = 8 # /* PC relative 8 bit */
R_TILEGX_HW0 = 9 # /* hword 0 16-bit */
R_TILEGX_HW1 = 10 # /* hword 1 16-bit */
R_TILEGX_HW2 = 11 # /* hword 2 16-bit */
R_TILEGX_HW3 = 12 # /* hword 3 16-bit */
R_TILEGX_HW0_LAST = 13 # /* last hword 0 16-bit */
R_TILEGX_HW1_LAST = 14 # /* last hword 1 16-bit */
R_TILEGX_HW2_LAST = 15 # /* last hword 2 16-bit */
R_TILEGX_COPY = 16 # /* Copy relocation */
R_TILEGX_GLOB_DAT = 17 # /* Create GOT entry */
R_TILEGX_JMP_SLOT = 18 # /* Create PLT entry */
R_TILEGX_RELATIVE = 19 # /* Adjust by program base */
R_TILEGX_BROFF_X1 = 20 # /* X1 pipe branch offset */
R_TILEGX_JUMPOFF_X1 = 21 # /* X1 pipe jump offset */
R_TILEGX_JUMPOFF_X1_PLT = 22 # /* X1 pipe jump offset to PLT */
R_TILEGX_IMM8_X0 = 23 # /* X0 pipe 8-bit */
R_TILEGX_IMM8_Y0 = 24 # /* Y0 pipe 8-bit */
R_TILEGX_IMM8_X1 = 25 # /* X1 pipe 8-bit */
R_TILEGX_IMM8_Y1 = 26 # /* Y1 pipe 8-bit */
R_TILEGX_DEST_IMM8_X1 = 27 # /* X1 pipe destination 8-bit */
R_TILEGX_MT_IMM14_X1 = 28 # /* X1 pipe mtspr */
R_TILEGX_MF_IMM14_X1 = 29 # /* X1 pipe mfspr */
R_TILEGX_MMSTART_X0 = 30 # /* X0 pipe mm "start" */
R_TILEGX_MMEND_X0 = 31 # /* X0 pipe mm "end" */
R_TILEGX_SHAMT_X0 = 32 # /* X0 pipe shift amount */
R_TILEGX_SHAMT_X1 = 33 # /* X1 pipe shift amount */
R_TILEGX_SHAMT_Y0 = 34 # /* Y0 pipe shift amount */
R_TILEGX_SHAMT_Y1 = 35 # /* Y1 pipe shift amount */
R_TILEGX_IMM16_X0_HW0 = 36 # /* X0 pipe hword 0 */
R_TILEGX_IMM16_X1_HW0 = 37 # /* X1 pipe hword 0 */
R_TILEGX_IMM16_X0_HW1 = 38 # /* X0 pipe hword 1 */
R_TILEGX_IMM16_X1_HW1 = 39 # /* X1 pipe hword 1 */
R_TILEGX_IMM16_X0_HW2 = 40 # /* X0 pipe hword 2 */
R_TILEGX_IMM16_X1_HW2 = 41 # /* X1 pipe hword 2 */
R_TILEGX_IMM16_X0_HW3 = 42 # /* X0 pipe hword 3 */
R_TILEGX_IMM16_X1_HW3 = 43 # /* X1 pipe hword 3 */
R_TILEGX_IMM16_X0_HW0_LAST = 44 # /* X0 pipe last hword 0 */
R_TILEGX_IMM16_X1_HW0_LAST = 45 # /* X1 pipe last hword 0 */
R_TILEGX_IMM16_X0_HW1_LAST = 46 # /* X0 pipe last hword 1 */
R_TILEGX_IMM16_X1_HW1_LAST = 47 # /* X1 pipe last hword 1 */
R_TILEGX_IMM16_X0_HW2_LAST = 48 # /* X0 pipe last hword 2 */
R_TILEGX_IMM16_X1_HW2_LAST = 49 # /* X1 pipe last hword 2 */
R_TILEGX_IMM16_X0_HW0_PCREL = 50 # /* X0 pipe PC relative hword 0 */
R_TILEGX_IMM16_X1_HW0_PCREL = 51 # /* X1 pipe PC relative hword 0 */
R_TILEGX_IMM16_X0_HW1_PCREL = 52 # /* X0 pipe PC relative hword 1 */
R_TILEGX_IMM16_X1_HW1_PCREL = 53 # /* X1 pipe PC relative hword 1 */
R_TILEGX_IMM16_X0_HW2_PCREL = 54 # /* X0 pipe PC relative hword 2 */
R_TILEGX_IMM16_X1_HW2_PCREL = 55 # /* X1 pipe PC relative hword 2 */
R_TILEGX_IMM16_X0_HW3_PCREL = 56 # /* X0 pipe PC relative hword 3 */
R_TILEGX_IMM16_X1_HW3_PCREL = 57 # /* X1 pipe PC relative hword 3 */
R_TILEGX_IMM16_X0_HW0_LAST_PCREL = 58 # /* X0 pipe PC-rel last hword 0 */
R_TILEGX_IMM16_X1_HW0_LAST_PCREL = 59 # /* X1 pipe PC-rel last hword 0 */
R_TILEGX_IMM16_X0_HW1_LAST_PCREL = 60 # /* X0 pipe PC-rel last hword 1 */
R_TILEGX_IMM16_X1_HW1_LAST_PCREL = 61 # /* X1 pipe PC-rel last hword 1 */
R_TILEGX_IMM16_X0_HW2_LAST_PCREL = 62 # /* X0 pipe PC-rel last hword 2 */
R_TILEGX_IMM16_X1_HW2_LAST_PCREL = 63 # /* X1 pipe PC-rel last hword 2 */
R_TILEGX_IMM16_X0_HW0_GOT = 64 # /* X0 pipe hword 0 GOT offset */
R_TILEGX_IMM16_X1_HW0_GOT = 65 # /* X1 pipe hword 0 GOT offset */
R_TILEGX_IMM16_X0_HW0_PLT_PCREL = 66 # /* X0 pipe PC-rel PLT hword 0 */
R_TILEGX_IMM16_X1_HW0_PLT_PCREL = 67 # /* X1 pipe PC-rel PLT hword 0 */
R_TILEGX_IMM16_X0_HW1_PLT_PCREL = 68 # /* X0 pipe PC-rel PLT hword 1 */
R_TILEGX_IMM16_X1_HW1_PLT_PCREL = 69 # /* X1 pipe PC-rel PLT hword 1 */
R_TILEGX_IMM16_X0_HW2_PLT_PCREL = 70 # /* X0 pipe PC-rel PLT hword 2 */
R_TILEGX_IMM16_X1_HW2_PLT_PCREL = 71 # /* X1 pipe PC-rel PLT hword 2 */
R_TILEGX_IMM16_X0_HW0_LAST_GOT = 72 # /* X0 pipe last hword 0 GOT offset */
R_TILEGX_IMM16_X1_HW0_LAST_GOT = 73 # /* X1 pipe last hword 0 GOT offset */
R_TILEGX_IMM16_X0_HW1_LAST_GOT = 74 # /* X0 pipe last hword 1 GOT offset */
R_TILEGX_IMM16_X1_HW1_LAST_GOT = 75 # /* X1 pipe last hword 1 GOT offset */
R_TILEGX_IMM16_X0_HW3_PLT_PCREL = 76 # /* X0 pipe PC-rel PLT hword 3 */
R_TILEGX_IMM16_X1_HW3_PLT_PCREL = 77 # /* X1 pipe PC-rel PLT hword 3 */
R_TILEGX_IMM16_X0_HW0_TLS_GD = 78 # /* X0 pipe hword 0 TLS GD offset */
R_TILEGX_IMM16_X1_HW0_TLS_GD = 79 # /* X1 pipe hword 0 TLS GD offset */
R_TILEGX_IMM16_X0_HW0_TLS_LE = 80 # /* X0 pipe hword 0 TLS LE offset */
R_TILEGX_IMM16_X1_HW0_TLS_LE = 81 # /* X1 pipe hword 0 TLS LE offset */
R_TILEGX_IMM16_X0_HW0_LAST_TLS_LE = 82 # /* X0 pipe last hword 0 LE off */
R_TILEGX_IMM16_X1_HW0_LAST_TLS_LE = 83 # /* X1 pipe last hword 0 LE off */
R_TILEGX_IMM16_X0_HW1_LAST_TLS_LE = 84 # /* X0 pipe last hword 1 LE off */
R_TILEGX_IMM16_X1_HW1_LAST_TLS_LE = 85 # /* X1 pipe last hword 1 LE off */
R_TILEGX_IMM16_X0_HW0_LAST_TLS_GD = 86 # /* X0 pipe last hword 0 GD off */
R_TILEGX_IMM16_X1_HW0_LAST_TLS_GD = 87 # /* X1 pipe last hword 0 GD off */
R_TILEGX_IMM16_X0_HW1_LAST_TLS_GD = 88 # /* X0 pipe last hword 1 GD off */
R_TILEGX_IMM16_X1_HW1_LAST_TLS_GD = 89 # /* X1 pipe last hword 1 GD off */
# /* Relocs 90-91 are currently not defined.  */ 
R_TILEGX_IMM16_X0_HW0_TLS_IE = 92 # /* X0 pipe hword 0 TLS IE offset */
R_TILEGX_IMM16_X1_HW0_TLS_IE = 93 # /* X1 pipe hword 0 TLS IE offset */
R_TILEGX_IMM16_X0_HW0_LAST_PLT_PCREL = 94 # /* X0 pipe PC-rel PLT last hword 0 */
R_TILEGX_IMM16_X1_HW0_LAST_PLT_PCREL = 95 # /* X1 pipe PC-rel PLT last hword 0 */
R_TILEGX_IMM16_X0_HW1_LAST_PLT_PCREL = 96 # /* X0 pipe PC-rel PLT last hword 1 */
R_TILEGX_IMM16_X1_HW1_LAST_PLT_PCREL = 97 # /* X1 pipe PC-rel PLT last hword 1 */
R_TILEGX_IMM16_X0_HW2_LAST_PLT_PCREL = 98 # /* X0 pipe PC-rel PLT last hword 2 */
R_TILEGX_IMM16_X1_HW2_LAST_PLT_PCREL = 99 # /* X1 pipe PC-rel PLT last hword 2 */
R_TILEGX_IMM16_X0_HW0_LAST_TLS_IE = 100 # /* X0 pipe last hword 0 IE off */
R_TILEGX_IMM16_X1_HW0_LAST_TLS_IE = 101 # /* X1 pipe last hword 0 IE off */
R_TILEGX_IMM16_X0_HW1_LAST_TLS_IE = 102 # /* X0 pipe last hword 1 IE off */
R_TILEGX_IMM16_X1_HW1_LAST_TLS_IE = 103 # /* X1 pipe last hword 1 IE off */
# /* Relocs 104-105 are currently not defined.  */ 
R_TILEGX_TLS_DTPMOD64 = 106 # /* 64-bit ID of symbol's module */
R_TILEGX_TLS_DTPOFF64 = 107 # /* 64-bit offset in TLS block */
R_TILEGX_TLS_TPOFF64 = 108 # /* 64-bit offset in static TLS block */
R_TILEGX_TLS_DTPMOD32 = 109 # /* 32-bit ID of symbol's module */
R_TILEGX_TLS_DTPOFF32 = 110 # /* 32-bit offset in TLS block */
R_TILEGX_TLS_TPOFF32 = 111 # /* 32-bit offset in static TLS block */
R_TILEGX_TLS_GD_CALL = 112 # /* "jal" for TLS GD */
R_TILEGX_IMM8_X0_TLS_GD_ADD = 113 # /* X0 pipe "addi" for TLS GD */
R_TILEGX_IMM8_X1_TLS_GD_ADD = 114 # /* X1 pipe "addi" for TLS GD */
R_TILEGX_IMM8_Y0_TLS_GD_ADD = 115 # /* Y0 pipe "addi" for TLS GD */
R_TILEGX_IMM8_Y1_TLS_GD_ADD = 116 # /* Y1 pipe "addi" for TLS GD */
R_TILEGX_TLS_IE_LOAD = 117 # /* "ld_tls" for TLS IE */
R_TILEGX_IMM8_X0_TLS_ADD = 118 # /* X0 pipe "addi" for TLS GD/IE */
R_TILEGX_IMM8_X1_TLS_ADD = 119 # /* X1 pipe "addi" for TLS GD/IE */
R_TILEGX_IMM8_Y0_TLS_ADD = 120 # /* Y0 pipe "addi" for TLS GD/IE */
R_TILEGX_IMM8_Y1_TLS_ADD = 121 # /* Y1 pipe "addi" for TLS GD/IE */

R_TILEGX_GNU_VTINHERIT = 128 # /* GNU C++ vtable hierarchy */
R_TILEGX_GNU_VTENTRY = 129 # /* GNU C++ vtable member usage */

R_TILEGX_NUM = 130

# /* RISC-V ELF Flags */
EF_RISCV_RVC = 0x0001
EF_RISCV_FLOAT_ABI = 0x0006
EF_RISCV_FLOAT_ABI_SOFT = 0x0000
EF_RISCV_FLOAT_ABI_SINGLE = 0x0002
EF_RISCV_FLOAT_ABI_DOUBLE = 0x0004
EF_RISCV_FLOAT_ABI_QUAD = 0x0006
EF_RISCV_RVE = 0x0008
EF_RISCV_TSO = 0x0010

# /* RISC-V relocations.  */
R_RISCV_NONE = 0
R_RISCV_32 = 1
R_RISCV_64 = 2
R_RISCV_RELATIVE = 3
R_RISCV_COPY = 4
R_RISCV_JUMP_SLOT = 5
R_RISCV_TLS_DTPMOD32 = 6
R_RISCV_TLS_DTPMOD64 = 7
R_RISCV_TLS_DTPREL32 = 8
R_RISCV_TLS_DTPREL64 = 9
R_RISCV_TLS_TPREL32 = 10
R_RISCV_TLS_TPREL64 = 11
R_RISCV_BRANCH = 16
R_RISCV_JAL = 17
R_RISCV_CALL = 18
R_RISCV_CALL_PLT = 19
R_RISCV_GOT_HI20 = 20
R_RISCV_TLS_GOT_HI20 = 21
R_RISCV_TLS_GD_HI20 = 22
R_RISCV_PCREL_HI20 = 23
R_RISCV_PCREL_LO12_I = 24
R_RISCV_PCREL_LO12_S = 25
R_RISCV_HI20 = 26
R_RISCV_LO12_I = 27
R_RISCV_LO12_S = 28
R_RISCV_TPREL_HI20 = 29
R_RISCV_TPREL_LO12_I = 30
R_RISCV_TPREL_LO12_S = 31
R_RISCV_TPREL_ADD = 32
R_RISCV_ADD8 = 33
R_RISCV_ADD16 = 34
R_RISCV_ADD32 = 35
R_RISCV_ADD64 = 36
R_RISCV_SUB8 = 37
R_RISCV_SUB16 = 38
R_RISCV_SUB32 = 39
R_RISCV_SUB64 = 40
R_RISCV_GNU_VTINHERIT = 41
R_RISCV_GNU_VTENTRY = 42
R_RISCV_ALIGN = 43
R_RISCV_RVC_BRANCH = 44
R_RISCV_RVC_JUMP = 45
R_RISCV_RVC_LUI = 46
R_RISCV_GPREL_I = 47
R_RISCV_GPREL_S = 48
R_RISCV_TPREL_I = 49
R_RISCV_TPREL_S = 50
R_RISCV_RELAX = 51
R_RISCV_SUB6 = 52
R_RISCV_SET6 = 53
R_RISCV_SET8 = 54
R_RISCV_SET16 = 55
R_RISCV_SET32 = 56
R_RISCV_32_PCREL = 57
R_RISCV_IRELATIVE = 58
R_RISCV_NUM = 59

# /* RISC-V specific values for the st_other field.  */
STO_RISCV_VARIANT_CC = 0x80 # /* Function uses variant calling
#                        convention */
# /* RISC-V specific values for the sh_type field.  */ 
SHT_RISCV_ATTRIBUTES = (SHT_LOPROC + 3)

# /* RISC-V specific values for the p_type field.  */ 
PT_RISCV_ATTRIBUTES = (PT_LOPROC + 3)

# /* RISC-V specific values for the d_tag field.  */ 
DT_RISCV_VARIANT_CC = (DT_LOPROC + 1)

# /* BPF specific declarations.  */ 
R_BPF_NONE = 0 # /* No reloc */
R_BPF_64_64 = 1
R_BPF_64_32 = 10

# /* Imagination Meta specific relocations. */
R_METAG_HIADDR16 = 0
R_METAG_LOADDR16 = 1
R_METAG_ADDR32 = 2 # /* 32bit absolute address */
R_METAG_NONE = 3 # /* No reloc */
R_METAG_RELBRANCH = 4
R_METAG_GETSETOFF = 5

# /* Backward compatibility */
R_METAG_REG32OP1 = 6
R_METAG_REG32OP2 = 7
R_METAG_REG32OP3 = 8
R_METAG_REG16OP1 = 9
R_METAG_REG16OP2 = 10
R_METAG_REG16OP3 = 11
R_METAG_REG32OP4 = 12
R_METAG_HIOG = 13
R_METAG_LOOG = 14
R_METAG_REL8 = 15
R_METAG_REL16 = 16

# /* GNU */
R_METAG_GNU_VTINHERIT = 30
R_METAG_GNU_VTENTRY = 31

# /* PIC relocations */
R_METAG_HI16_GOTOFF = 32
R_METAG_LO16_GOTOFF = 33
R_METAG_GETSET_GOTOFF = 34
R_METAG_GETSET_GOT = 35
R_METAG_HI16_GOTPC = 36
R_METAG_LO16_GOTPC = 37
R_METAG_HI16_PLT = 38
R_METAG_LO16_PLT = 39
R_METAG_RELBRANCH_PLT = 40
R_METAG_GOTOFF = 41
R_METAG_PLT = 42
R_METAG_COPY = 43
R_METAG_JMP_SLOT = 44
R_METAG_RELATIVE = 45
R_METAG_GLOB_DAT = 46

# /* TLS relocations */
R_METAG_TLS_GD = 47
R_METAG_TLS_LDM = 48
R_METAG_TLS_LDO_HI16 = 49
R_METAG_TLS_LDO_LO16 = 50
R_METAG_TLS_LDO = 51
R_METAG_TLS_IE = 52
R_METAG_TLS_IENONPIC = 53
R_METAG_TLS_IENONPIC_HI16 = 54
R_METAG_TLS_IENONPIC_LO16 = 55
R_METAG_TLS_TPOFF = 56
R_METAG_TLS_DTPMOD = 57
R_METAG_TLS_DTPOFF = 58
R_METAG_TLS_LE = 59
R_METAG_TLS_LE_HI16 = 60
R_METAG_TLS_LE_LO16 = 61

# /* NDS32 relocations.  */
R_NDS32_NONE = 0
R_NDS32_32_RELA = 20
R_NDS32_COPY = 39
R_NDS32_GLOB_DAT = 40
R_NDS32_JMP_SLOT = 41
R_NDS32_RELATIVE = 42
R_NDS32_TLS_TPOFF = 102
R_NDS32_TLS_DESC = 119

# /* LoongArch ELF Flags */
EF_LARCH_ABI_MODIFIER_MASK = 0x07
EF_LARCH_ABI_SOFT_FLOAT = 0x01
EF_LARCH_ABI_SINGLE_FLOAT = 0x02
EF_LARCH_ABI_DOUBLE_FLOAT = 0x03
EF_LARCH_OBJABI_V1 = 0x40

# /* LoongArch specific dynamic relocations */
R_LARCH_NONE = 0
R_LARCH_32 = 1
R_LARCH_64 = 2
R_LARCH_RELATIVE = 3
R_LARCH_COPY = 4
R_LARCH_JUMP_SLOT = 5
R_LARCH_TLS_DTPMOD32 = 6
R_LARCH_TLS_DTPMOD64 = 7
R_LARCH_TLS_DTPREL32 = 8
R_LARCH_TLS_DTPREL64 = 9
R_LARCH_TLS_TPREL32 = 10
R_LARCH_TLS_TPREL64 = 11
R_LARCH_IRELATIVE = 12

# /* Reserved for future relocs that the dynamic linker must understand.  */

# /* used by the static linker for relocating .text.  */ 
R_LARCH_MARK_LA = 20
R_LARCH_MARK_PCREL = 21
R_LARCH_SOP_PUSH_PCREL = 22
R_LARCH_SOP_PUSH_ABSOLUTE = 23
R_LARCH_SOP_PUSH_DUP = 24
R_LARCH_SOP_PUSH_GPREL = 25
R_LARCH_SOP_PUSH_TLS_TPREL = 26
R_LARCH_SOP_PUSH_TLS_GOT = 27
R_LARCH_SOP_PUSH_TLS_GD = 28
R_LARCH_SOP_PUSH_PLT_PCREL = 29
R_LARCH_SOP_ASSERT = 30
R_LARCH_SOP_NOT = 31
R_LARCH_SOP_SUB = 32
R_LARCH_SOP_SL = 33
R_LARCH_SOP_SR = 34
R_LARCH_SOP_ADD = 35
R_LARCH_SOP_AND = 36
R_LARCH_SOP_IF_ELSE = 37
R_LARCH_SOP_POP_32_S_10_5 = 38
R_LARCH_SOP_POP_32_U_10_12 = 39
R_LARCH_SOP_POP_32_S_10_12 = 40
R_LARCH_SOP_POP_32_S_10_16 = 41
R_LARCH_SOP_POP_32_S_10_16_S2 = 42
R_LARCH_SOP_POP_32_S_5_20 = 43
R_LARCH_SOP_POP_32_S_0_5_10_16_S2 = 44
R_LARCH_SOP_POP_32_S_0_10_10_16_S2 = 45
R_LARCH_SOP_POP_32_U = 46

# /* used by the static linker for relocating non .text.  */
R_LARCH_ADD8 = 47
R_LARCH_ADD16 = 48
R_LARCH_ADD24 = 49
R_LARCH_ADD32 = 50
R_LARCH_ADD64 = 51
R_LARCH_SUB8 = 52
R_LARCH_SUB16 = 53
R_LARCH_SUB24 = 54
R_LARCH_SUB32 = 55
R_LARCH_SUB64 = 56
R_LARCH_GNU_VTINHERIT = 57
R_LARCH_GNU_VTENTRY = 58

# /* ARCompact/ARCv2 specific relocs.  */
R_ARC_NONE = 0x0
R_ARC_8 = 0x1
R_ARC_16 = 0x2
R_ARC_24 = 0x3
R_ARC_32 = 0x4
R_ARC_B26 = 0x5
R_ARC_B22_PCREL = 0x6
R_ARC_H30 = 0x7
R_ARC_N8 = 0x8
R_ARC_N16 = 0x9
R_ARC_N24 = 0xA
R_ARC_N32 = 0xB
R_ARC_SDA = 0xC
R_ARC_SECTOFF = 0xD
R_ARC_S21H_PCREL = 0xE
R_ARC_S21W_PCREL = 0xF
R_ARC_S25H_PCREL = 0x10
R_ARC_S25W_PCREL = 0x11
R_ARC_SDA32 = 0x12
R_ARC_SDA_LDST = 0x13
R_ARC_SDA_LDST1 = 0x14
R_ARC_SDA_LDST2 = 0x15
R_ARC_SDA16_LD = 0x16
R_ARC_SDA16_LD1 = 0x17
R_ARC_SDA16_LD2 = 0x18
R_ARC_S13_PCREL = 0x19
R_ARC_W = 0x1A
R_ARC_32_ME = 0x1B
R_ARC_N32_ME = 0x1C
R_ARC_SECTOFF_ME = 0x1D
R_ARC_SDA32_ME = 0x1E
R_ARC_W_ME = 0x1F
R_ARC_H30_ME = 0x20
R_ARC_SECTOFF_U8 = 0x21
R_ARC_SECTOFF_S9 = 0x22
R_AC_SECTOFF_U8 = 0x23
R_AC_SECTOFF_U8_1 = 0x24
R_AC_SECTOFF_U8_2 = 0x25
R_AC_SECTOFF_S9 = 0x26
R_AC_SECTOFF_S9_1 = 0x27
R_AC_SECTOFF_S9_2 = 0x28
R_ARC_SECTOFF_ME_1 = 0x29
R_ARC_SECTOFF_ME_2 = 0x2A
R_ARC_SECTOFF_1 = 0x2B
R_ARC_SECTOFF_2 = 0x2C
R_ARC_PC32 = 0x32
R_ARC_GOTPC32 = 0x33
R_ARC_PLT32 = 0x34
R_ARC_COPY = 0x35
R_ARC_GLOB_DAT = 0x36
R_ARC_JUMP_SLOT = 0x37
R_ARC_RELATIVE = 0x38
R_ARC_GOTOFF = 0x39
R_ARC_GOTPC = 0x3A
R_ARC_GOT32 = 0x3B

R_ARC_TLS_DTPMOD = 0x42
R_ARC_TLS_DTPOFF = 0x43
R_ARC_TLS_TPOFF = 0x44
R_ARC_TLS_GD_GOT = 0x45
R_ARC_TLS_GD_LD = 0x46
R_ARC_TLS_GD_CALL = 0x47
R_ARC_TLS_IE_GOT = 0x48
R_ARC_TLS_DTPOFF_S9 = 0x4a
R_ARC_TLS_LE_S9 = 0x4a
R_ARC_TLS_LE_32 = 0x4b

# /* OpenRISC 1000 specific relocs.  */
R_OR1K_NONE = 0
R_OR1K_32 = 1
R_OR1K_16 = 2
R_OR1K_8 = 3
R_OR1K_LO_16_IN_INSN = 4
R_OR1K_HI_16_IN_INSN = 5
R_OR1K_INSN_REL_26 = 6
R_OR1K_GNU_VTENTRY = 7
R_OR1K_GNU_VTINHERIT = 8
R_OR1K_32_PCREL = 9
R_OR1K_16_PCREL = 10
R_OR1K_8_PCREL = 11
R_OR1K_GOTPC_HI16 = 12
R_OR1K_GOTPC_LO16 = 13
R_OR1K_GOT16 = 14
R_OR1K_PLT26 = 15
R_OR1K_GOTOFF_HI16 = 16
R_OR1K_GOTOFF_LO16 = 17
R_OR1K_COPY = 18
R_OR1K_GLOB_DAT = 19
R_OR1K_JMP_SLOT = 20
R_OR1K_RELATIVE = 21
R_OR1K_TLS_GD_HI16 = 22
R_OR1K_TLS_GD_LO16 = 23
R_OR1K_TLS_LDM_HI16 = 24
R_OR1K_TLS_LDM_LO16 = 25
R_OR1K_TLS_LDO_HI16 = 26
R_OR1K_TLS_LDO_LO16 = 27
R_OR1K_TLS_IE_HI16 = 28
R_OR1K_TLS_IE_LO16 = 29
R_OR1K_TLS_LE_HI16 = 30
R_OR1K_TLS_LE_LO16 = 31
R_OR1K_TLS_TPOFF = 32
R_OR1K_TLS_DTPOFF = 33
R_OR1K_TLS_DTPMOD = 34
