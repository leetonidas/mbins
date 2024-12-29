from elffile import Elffile
import elffile
import elf
import leg
from disassamble import InstructionGroup
from disassamble import JmpKind
import disassamble
from random import SystemRandom
import struct

def get_relocations(e, mapping):
    defs = dict()
    for (lsec, tsec, relas) in e.relas.values():
        syms = e.symsecs[lsec]
        for rela in relas:
            sym = syms[rela.r_sym()]
            stsec = sym.sym.st_shndx
            toff = sym.sym.st_value
            stp  = sym.sym.st_type()
            rtp =  rela.r_type()

            assert rtp == 1
            if stp == elf.STT_SECTION:
                #print(f"relocation: LDI @ SECTION {tsec} + {rela.r_offset} -> SYMBOL - SECTION {stsec} + {toff}")
                defs[mapping[tsec] + rela.r_offset] = mapping[stsec] + toff + rela.r_addend
                #stmt = f"*(uint64_t *)&vm.data[{mapping[tsec] + rela.r_offset + 4}] = (uint64_t) &vm.data[{mapping[stsec] + toff + rela.r_addend}];"
                #stmts.append(stmt)

            elif sym.sym.st_shndx == 0:
                nm = sym.name.decode()
                defs[mapping[tsec] + rela.r_offset] = nm
                #defs.append(nm)
                #stmt = stmt = f"*(uint64_t *)&vm.data[{mapping[tsec] + rela.r_offset + 4}] = (uint64_t) {nm};"
                #stmts.append(stmt)
    return defs

def get_functions(e, mapping):
    for symsec in e.symsecs.values():
        for sym in symsec:
            if sym.sym.st_type() != elf.STT_FUNC or sym.sym.st_shndx not in mapping:
                #print(f"skippin {sym.name}")
                continue
            yield (mapping[sym.sym.st_shndx] + sym.sym.st_value, sym.sym.st_size, sym.name)

def lfsr(init):
    while True:
        init = (init ^ (init << 13)) & 0xffffffff
        init = init ^ (init >> 17)
        init = (init ^ (init << 5)) & 0xffffffff
        yield init

def reencodeElf(e, mapping, data, endian):
    rnd = SystemRandom()
    data = bytearray(data)

    relocs = get_relocations(e, mapping)
    funs = list(get_functions(e, mapping))
#    print(relocs)
#    print(funs)
    ctx = disassamble.Disassembler(0x1000, data, leg.Context(endian, False))
    for start, size, name in funs:
        disassamble.Function.getFunction(ctx, 0x1000 + start)
    #ins = ctx.ctx.disasm_single(ctx.dat[ctx.offset_from_addr(0x1000):], 0x1000)
    ctx.recursive_decode()
    for start, size, name in funs:
        enc = "<I" if endian == "little" else ">I"
        fun = ctx.functions[0x1000 + start]
#        print(f"{name.decode()} @ {0x1000 + start:#06x}:")

        sps = set(fun.blocks.keys())
        for baddr, block in fun.blocks.items():
            grps = ctx.ctx.ins_groups(block.insns[-1])
            if InstructionGroup.RETURN in grps:
#                print(f"block @ {baddr:#x} returns")
                continue
            if InstructionGroup.JMP not in grps or InstructionGroup.CONDITIONAL in grps:
                ftb = block.insns[-1].address + block.insns[-1].size
                print(f"block @ {ftb:#x} is a fallthrough block")
                assert ftb in fun.blocks
                sps.discard(ftb)
        print(f"encryption starting points: {sps}")

        sps = {sa: rnd.randint(1, 1 << 32) for sa in sps}

        blocklfsr = dict(sps)

        for baddr, lfsr_init in sps.items():
#            print(f"encoding instruction stream for block starting from {baddr:#x} - inital state: {lfsr_init:#x}")
            block = fun.blocks[baddr]
            saddr = block.insns[0].address

            while True:
                grps = ctx.ctx.ins_groups(block.insns[-1])
                if InstructionGroup.RETURN in grps:
                    break
                if InstructionGroup.JMP in grps and InstructionGroup.CONDITIONAL not in grps:
                    break
                block = fun.blocks[block.insns[-1].address + block.insns[-1].size]
            endaddr = block.insns[-1].address + block.insns[-1].size
            if InstructionGroup.JMP in block.insns[-1].grps:
                endaddr = endaddr + 4

            if saddr == fun.addr:
                struct.pack_into(enc, data, saddr - 0x1000, lfsr_init)
                saddr = saddr + 4

            for lfsr_val, addr in zip(lfsr(lfsr_init), range(saddr, endaddr, 4)):
                if addr + 4 in fun.blocks and addr + 4 not in blocklfsr:
                    blocklfsr[addr + 4] = lfsr_val
                val = struct.unpack_from(enc, data, addr - 0x1000)[0]
                val ^= lfsr_val
                struct.pack_into(enc, data, addr - 0x1000, val)

        print(f"blocks:")
        for addr, _lfsr in blocklfsr.items():
            print(f"  {addr:#06x}: {_lfsr:08x}")

        for ins in sum((b.insns for b in fun.blocks.values()), []):
            grps = ctx.ctx.ins_groups(ins)
            if InstructionGroup.JMP not in grps:
                continue
            if ins.jmp_kind != JmpKind.DIRECT:
                continue
            jtar = ins.jmp_targets[0]
            tlfsr = blocklfsr[jtar]
            print(f"inserting lfs correction in {ins.address:#x} {ins} - {tlfsr:#08x}")

            val = struct.unpack_from(enc, data, ins.address + 4 - 0x1000)[0]
            val ^= tlfsr
            struct.pack_into(enc, data, ins.address + 4 - 0x1000, val)

    return (data, ctx)

def reencode(file, endian):
    elffile.machineMap[0x200] = "LEG"
    e = Elffile(file)

    addr = 0
    align = 0x4
    data = bytes()
    mapping = {}
    for (secnum, sec) in filter(lambda x: x[1].sh_flags & elf.SHF_ALLOC == elf.SHF_ALLOC, enumerate(e.shdr)):
        secdata = e.rawdata[sec.sh_offset:sec.sh_offset + sec.sh_size]
        data = data + secdata
        mapping[secnum] = addr
        addr = addr + sec.sh_size

    data, ctx = reencodeElf(e, mapping, data, endian)

    funs = list(get_functions(e, mapping))
    #for start, size, name in funs:
    #    fun = ctx.functions[0x1000 + start]
    #    print(f"{name.decode()} @ {0x1000 + start:#06x}:")
    #    for addr, block in sorted(fun.blocks.items()):
    #        print(f"loc_{addr:04x}:")
    #        for ins in block.insns:
    #            print(f"\t{ins}")

    return data, ctx, funs

if __name__ == "__main__":
    import sys
    fn = sys.argv[1]
    end = sys.argv[2] if len(sys.argv) > 2 else "little"
    data, ctx, funs = reencode(fn, end)
