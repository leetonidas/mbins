from capstone import *
import elf
import sys
from ctypes import memmove, pointer, sizeof, Union, Structure, c_ubyte, c_ushort, c_uint, c_ulong, c_byte, c_short, c_int, c_long
from itertools import takewhile
from enum import Enum
from inspect import isclass

elf.Elf64_Sym.st_bind = lambda s: elf.ELF64_ST_BIND(s.st_info)
elf.Elf64_Sym.st_type = lambda s: elf.ELF64_ST_TYPE(s.st_info)
elf.Elf32_Sym.st_bind = lambda s: elf.ELF32_ST_BIND(s.st_info)
elf.Elf32_Sym.st_type = lambda s: elf.ELF32_ST_TYPE(s.st_info)

elf.Elf64_Rela.r_sym  = lambda s: elf.ELF64_R_SYM(s.r_info)
elf.Elf64_Rela.r_type = lambda s: elf.ELF64_R_TYPE(s.r_info)
elf.Elf32_Rela.r_sym  = lambda s: elf.ELF32_R_SYM(s.r_info)
elf.Elf32_Rela.r_type = lambda s: elf.ELF32_R_TYPE(s.r_info)

elf.Elf64_Rel.r_sym  = lambda s: elf.ELF64_R_SYM(s.r_info)
elf.Elf64_Rel.r_type = lambda s: elf.ELF64_R_TYPE(s.r_info)
elf.Elf32_Rel.r_sym  = lambda s: elf.ELF32_R_SYM(s.r_info)
elf.Elf32_Rel.r_type = lambda s: elf.ELF32_R_TYPE(s.r_info)

def shortSwap(val):
    return (val >> 8 | val << 8) & 0xffff
def intSwap(val):
    return (shortSwap(val & 0xffff) << 16) | (shortSwap(val >> 16) & 0xffff)
def longSwap(val):
    return (intSwap(val & 0xffffffff) << 32) | (intSwap(val >> 32) & 0xffffffff)

revFuns = { c_short: shortSwap
            , c_ushort: shortSwap
            , c_int: intSwap
            , c_uint: intSwap
            , c_long: longSwap
            , c_ulong: longSwap}

def byteReverse(struct):
    for fn, tp in struct._fields_:
        val = getattr(struct, fn)
        print(f"{fn}, {tp}, {val}, {type(val)}")
        if tp in [c_byte, c_ubyte]:
            print("bytes cannot be reversed")
            pass
        elif tp in revFuns:
            val = revFuns[tp](val)
        elif isclass(type(val)) and issubclass(type(val), Union):
            raise RuntimeError("unable to reverse bytes of union!")
        else:
            print(f"not reversing field {fn} of type {tp}")
        setattr(struct, fn, val)

def byteReverseDyn(dyn):
    tp = dyn._fields_[0][1]
    dyn.d_tag = revFuns[tp](dyn.d_tag)
    dyn.d_un.d_val = revFuns[tp](dyn.d_un.d_val)

machineMap = {getattr(elf, em): em[3:] for em in filter(lambda x: x.startswith("EM_"), dir(elf))}

ElfStructKinds = Enum("ElfStructKinds", [*map(lambda x: x[6:], filter(lambda x: x.startswith("Elf64_"), dir(elf)))])
ElfStructTypes64 = {kind: getattr(elf, f"Elf64_{kind.name}") for kind in ElfStructKinds}
ElfStructTypes32 = {kind: getattr(elf, f"Elf32_{kind.name}") for kind in ElfStructKinds}

class Section():
    def __init__(self, shdr):
        self.shdr = shdr

class Stringtab(Section):
    def __init__(self, shdr, data):
        super().__init__(shdr)
        self.data = data

    def __getitem__(self, off):
        tmp = self.data[off:]
        if b"\x00" in tmp:
            return tmp[:tmp.index(b"\x00")]
        return tmp

class Symbol():
    def __init__(self, sym, name):
        self.name = name
        self.sym = sym

class Symtab(Section):
    def __init__(self, shdr, symbols):
        self.symbols = symbols

    def __getitem__(self, off):
        return self.symbols[i]

class Elffile():
    def __init__(self, file):
        with open(file, "rb") as f:
            self.rawdata = f.read()

        hdr = elf.Elf64_Ehdr()
        memmove(pointer(hdr), self.rawdata, sizeof(hdr))
        if bytes(hdr.e_ident[:4]) != elf.ELFMAG.encode():
            raise Exception("elf header magic")

        if hdr.e_ident[elf.EI_CLASS] == elf.ELFCLASS64:
            self.StructTypes = ElfStructTypes64
        else:
            self.StructTypes = ElfStructTypes32

        data = hdr.e_ident[elf.EI_DATA]
        if (data == elf.ELFDATA2LSB and sys.byteorder == "big") \
                or (data == elf.ELFDATA2MSB and sys.byteorder == "little"):
            self.reverse = True
        else:
            self.reverse = False

        self.hdr = self.loadStruct(ElfStructKinds.Ehdr, self.rawdata)
        self.machine = self.hdr.e_machine
        #print(f"parsing elf, machine: {machineMap[self.machine]}, translate endianess: {self.reverse}")

        self.rnames = {getattr(elf, e): e for e in filter(lambda x: x.startswith(f"R_{machineMap[self.machine]}"), dir(elf))}
        
        self.segtypes = {getattr(elf, e): e for e in filter(lambda x: x.startswith(f"PT_") and getattr(elf, x) < elf.PT_LOPROC, dir(elf))}
        self.segtypes |= {getattr(elf, e): e for e in filter(lambda x: x.startswith(f"PT_{machineMap[self.machine]}_"), dir(elf))}

        self.sectype = {getattr(elf, e): e for e in filter(lambda x: x.startswith(f"SHT_") and getattr(elf, x) < elf.SHT_LOPROC, dir(elf))}
        self.segtypes |= {getattr(elf, e): e for e in filter(lambda x: x.startswith(f"SHT_{machineMap[self.machine]}_"), dir(elf))}

        self._load_sections()
        self._load_segments()

    def _load_sections(self):
        self.shdr = []
        for i in range(self.hdr.e_shnum):
            self.shdr.append(self.loadStruct(ElfStructKinds.Shdr, self.rawdata[self.hdr.e_shoff + self.hdr.e_shentsize * i:]))

        self.sections = []

        self.strsecs = {}
        for secnum, strsec in filter(lambda x: x[1].sh_type == elf.SHT_STRTAB, enumerate(self.shdr)):
            sec = Stringtab(strsec, self.rawdata[strsec.sh_offset:][:strsec.sh_size])
            self.strsecs[secnum] = sec

        self.symsecs = {}
        for secnum, symsec in filter(lambda x: x[1].sh_type == elf.SHT_SYMTAB, enumerate(self.shdr)):
            lnk = symsec.sh_link
#            print(f"symbol section: {self.strsecs[self.hdr.e_shstrndx][symsec.sh_name]}")
#            print(f"offset:         {symsec.sh_offset:#x}")
#            print(f"size:           {symsec.sh_size:#x}")
            rawsyms = []
            for i in range(0, symsec.sh_size, sizeof(self.StructTypes[ElfStructKinds.Sym])):
                rawsyms.append(self.loadStruct(ElfStructKinds.Sym, self.rawdata[symsec.sh_offset + i:]))

            syms = [Symbol(raw, self.strsecs[lnk][raw.st_name]) for raw in rawsyms]
            self.symsecs[secnum] = syms

        self.relas = {}
        for secnum, relasec in filter(lambda x: x[1].sh_type == elf.SHT_RELA, enumerate(self.shdr)):
            lnk = relasec.sh_link
            tar = relasec.sh_info
            rawrelas = []
            for i in range(0, relasec.sh_size, sizeof(self.StructTypes[ElfStructKinds.Rela])):
                rawrelas.append(self.loadStruct(ElfStructKinds.Rela, self.rawdata[relasec.sh_offset + i:]))
            self.relas[secnum] = (lnk, tar, rawrelas)

        self.rels = {}
        for secnum, relsec in filter(lambda x: x[1].sh_type == elf.SHT_REL, enumerate(self.shdr)):
            lnk = relsec.sh_link
            tar = relsec.sh_info
            rawrela = []
            for i in range(0, relsec.sh_size, sizeof(self.StructTypes[ElfStructKinds.Rel])):
                rawrela.append(self.loadStruct(ElfStructKinds.Rel, self.rawdata[relsec.sh_offset + i:]))
            self.rels[secnum] = (lnk, tar, rawrela)

    def _load_segments(self):
        self.phdr = []
        for i in range(self.hdr.e_phnum):
            self.phdr.append(self.loadStruct(ElfStructKinds.Phdr, self.rawdata[self.hdr.e_phoff + self.hdr.e_phentsize * i:]))
        self.load = []
        self.dyn = {}

        self.rela = None

        for phdr in self.phdr:
            match phdr.p_type:
                case elf.PT_LOAD:
                    data = self.rawdata[phdr.p_offset:][:phdr.p_filesz].ljust(phdr.p_memsz, b"\x00")
                    self.load.append((phdr.p_vaddr, phdr.p_align, phdr.p_flags, data))
                case elf.PT_INTERP:
                    self.interp = self.rawdata[phdr.p_offset:][:phdr.p_filesz].decode()
                case elf.PT_NOTE:
                    self.note = self.rawdata[phdr.p_offset:][:phdr.p_filesz]
                case elf.PT_DYNAMIC:
                    dd = self.rawdata[phdr.p_offset:][:phdr.p_filesz]
                    for i in range(0, phdr.p_filesz, sizeof(self.StructTypes[ElfStructKinds.Dyn])):
                        dyn = self.loadStruct(ElfStructKinds.Dyn, dd[i:])
                        if dyn.d_tag in self.dyn:
                            self.dyn[dyn.d_tag].append(dyn.d_un)
                        else:
                            self.dyn[dyn.d_tag] = [dyn.d_un]
                case _:
                    pass
                    #print(f"unhandled segment: {self.segtypes[phdr.p_type]}")

        if elf.DT_STRTAB in self.dyn:
            stab = self.uniqueDyn(elf.DT_STRTAB)
            strsz = self.uniqueDyn(elf.DT_STRSZ)
            self.strs = self.getVirtData(stab.d_ptr, strsz.d_val)

        if elf.DT_SYMTAB in self.dyn:
            sytab = self.uniqueDyn(elf.DT_SYMTAB)
            syent = self.uniqueDyn(elf.DT_SYMENT)
            assert syent.d_val == sizeof(self.StructTypes[ElfStructKinds.Sym])
            self.symtab = sytab.d_ptr

        if elf.DT_RELA in self.dyn:
            relaent = self.uniqueDyn(elf.DT_RELAENT).d_val
            relasz = self.uniqueDyn(elf.DT_RELASZ).d_val
            rela = self.uniqueDyn(elf.DT_RELA).d_ptr
            assert relaent == sizeof(self.StructTypes[ElfStructKinds.Rela])
            self.rela = []
            relasz = relasz
            relas = self.getVirtData(rela, relasz)
            for i in range(0, relasz, sizeof(self.StructTypes[ElfStructKinds.Rela])):
                self.rela.append(self.loadStruct(ElfStructKinds.Rela, relas[i:]))

        if elf.DT_REL in self.dyn:
            relent = self.uniqueDyn(elf.DT_RELENT).d_val
            relsz = self.uniqueDyn(elf.DT_RELSZ).d_val
            rel = self.uniqueDyn(elf.DT_REL).d_ptr
            assert relent == sizeof(self.StructTypes[ElfStructKinds.Rel])
            self.rel = []
            relsz = relsz
            rels = self.getVirtData(rel, relsz)
            for i in range(0, relsz, sizeof(self.StructTypes[ElfStructKinds.Rel])):
                self.rel.append(self.loadStruct(ElfStructKinds.Rela, rels[i:]))

        if elf.DT_RELR in self.dyn:
            relrent = self.uniqueDyn(elf.DT_RELRENT).d_val
            relrsz = self.uniqueDyn(elf.DT_RELRSZ).d_val
            relr = self.uniqueDyn(elf.DT_RELR).d_ptr
            assert relrent == sizeof(self.StructTypes[ElfStructKinds.Rela])
            self.relr = []
            relrsz = relrsz
            relrs = self.getVirtData(relr, relrsz)
            for i in range(0, relrsz, sizeof(self.StructTypes[ElfStructKinds.Rela])):
                self.relr.append(self.loadStruct(ElfStructKinds.Rela, relrs[i:]))

        if elf.DT_JMPREL in self.dyn:
            assert self.uniqueDyn(elf.DT_PLTREL).d_val == elf.DT_RELA
            pltrelsz = self.uniqueDyn(elf.DT_PLTRELSZ).d_val
            pltrel = self.uniqueDyn(elf.DT_JMPREL).d_ptr
            self.pltrel = []
            pltrelsz = pltrelsz
            pltrels = self.getVirtData(pltrel, pltrelsz)
            for i in range(0, pltrelsz, sizeof(self.StructTypes[ElfStructKinds.Rela])):
                self.pltrel.append(self.loadStruct(ElfStructKinds.Rela, pltrels[i:]))

    def uniqueDyn(self, dyn):
        dent = self.dyn[dyn]
        assert len(dent) == 1
        return dent[0]

    def getVirtData(self, start, length):
        res = bytes()
        for base, _, _, data in self.load:
            if base < start:
                data = data[start - base:]
            part = data[:length]
            res += part
            length -= len(part)
            if length == 0:
                break
        return res

    def loadStruct(self, sk, bt):
        ret = self.StructTypes[sk]()
        memmove(pointer(ret), bt, sizeof(ret))
        if self.reverse and sk == ElfStructKinds.Dyn:
            byteReverseDyn(ret)
        elif self.reverse:
            byteReverse(ret)
        return ret

    def get_sym(self, idx):
        assert self.symtab is not None
        symsz = sizeof(self.StructTypes[ElfStructKinds.Sym])
        return self.loadStruct(ElfStructKinds.Sym, self.getVirtData(self.symtab + idx * symsz, symsz))

    def get_str(self, idx):
        assert self.strs is not None
        return bytes(takewhile(lambda x: x != 0, self.strs[idx:])).decode()
