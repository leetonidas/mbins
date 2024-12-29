from elftools.elf.elffile import ELFFile
from numpy import uint64 as u64
import z3
import itertools

from disassamble import *
import leg

def lcg(ini, mul, add):
    ini = u64(ini)
    mul = u64(mul)
    add = u64(add)
    while True:
        yield ini
        ini = (ini * mul + add) & u64(0xffffffff)

def solve_perm(d, dis):
    ctx = ConcreteContext()
    ctx.mem.map(0x1000, len(d) - 0x10, d[0x10:])
    ctx.mem.map(0x7fff0000, 0x10000, None)
    ctx.regs[31] = u64(0x1000)
    ctx.regs[30] = u64(0x7fff0f00)

    inp = bytes(range(0x12))
    ctx.mem.write(0x7fff0f00, inp)
    ctx.regs[0] = u64(0x7fff0f00)
    ctx.regs[1] = u64(0x12)

    _, tb = sorted(dis.functions[0x1000].blocks.items())[-3]
    while True:
        b = dis.functions[0x1000].blocks[ctx.regs[31]]
        if b == tb:
            break
        for ins in b.insns:
            ctx.emulate(ins)
    
    data = ctx.mem.read(ctx.regs[30], 0x100)
    assert(data == bytes(range(0x100)))
    
    for ins in tb.insns:
        ctx.emulate(ins)

    data = ctx.mem.read(ctx.regs[30], 0x100)
    for i in range(0x10):
        print(" ".join(f"{j:02x}" for j in data[i * 0x10: (i + 1) * 0x10]))

    _, checker = sorted(dis.functions[0x1000].blocks.items())[-2]
    lds = []
    xors = []
    ld = None
    xor = None
    first = True
    for ins in checker.insns:
        if ins.mnemonic == "XORI":
            assert(xor is None)
            xor = ins.arg2
            print(f"xor: {xor:#x}")
        elif ins.mnemonic == "LD" and ctx.regs[ins.base] + ins.disp >= ctx.regs[30] and ctx.regs[ins.base] + ins.disp < ctx.regs[30] + 0x100:
            if ld is not None and first:
                if xor is None:
                    xor = u64(0)
                lds = [ld]
                xors = [xor]
                xor = None
                first = False
            else:
                assert(ld is None)
            ld = ctx.regs[ins.base] + ins.disp - ctx.regs[30]
            print(f"ld: {ld:#x}")
        elif ins.mnemonic == "OR":
            assert(ld is not None)
            lds.append(ld)
            if xor is None:
                xor = u64(0)
            xors.append(xor)
            xor = None
            ld = None
        ctx.emulate(ins)

    print(f"lds({len(lds)}: {lds}")
    print(f"xors({len(xors)}: {xors}")

    vals = [data[x] for _, x in sorted(zip(lds, xors))]
    print(bytes(vals).hex())
    return bytes(vals)

def solve_tree(d, dis):
    # highly sophisitcated detection
    _, fun = sorted(dis.functions.items())[-1]
    _, block = sorted(fun.blocks.items())[-1]
    last_ins = block.insns[-1]
    past_addr = last_ins.address + last_ins.size

    while past_addr + 0x20 < len(d) + 0x1000:
        dis.disassemble_function(past_addr)
        dis.recursive_decode()
        _, fun = sorted(dis.functions.items())[-1]
        _, block = sorted(fun.blocks.items())[-1]
        last_ins = block.insns[-1]
        past_addr = last_ins.address + last_ins.size

    fun = None
    tb = None
    for faddr, f in sorted(dis.functions.items()):
        for addr, b in sorted(f.blocks.items()):
            for ins in b.insns:
                if ins.mnemonic == "CALL":
                    fun = f
                    tb = b

    ctx = ConcreteContext()
    ctx.mem.map(0x1000, len(d) - 0x10, d[0x10:])
    ctx.mem.map(0x7fff0000, 0x10000, None)
    ctx.regs[31] = u64(faddr)
    ctx.regs[30] = u64(0x7fff0f00)

    inp = bytes(range(0x12))
    ctx.mem.write(0x7fff0f00, inp)
    ctx.regs[0] = u64(0x7fff0f00)
    ctx.regs[1] = u64(0x12)

    heap = 0x13370000
    ctx.mem.map(heap, 0x10000, None)

    while True:
        b = fun.blocks[ctx.regs[31]]
        if b == tb:
            break
        for ins in b.insns:
            if ins.mnemonic[:2] == "ST" and ctx.regs[ins.base] == 0:
                continue
            ctx.emulate(ins)

    for ins in tb.insns:
        if ins.mnemonic == "CALL" and ctx.regs[0] > 0x13370000:
            tree = ctx.regs[0]
            break
        elif ins.mnemonic == "CALL":
            size = ctx.regs[0]
            ctx.regs[0] = heap
            heap = heap + size
            continue
        ctx.emulate(ins)

    print(f"heap: {heap:#x}")
    print(f"tree: {tree:#x}")

    flag = z3.BitVec("flag", 8 * 0x12)

    solver = z3.Solver()
    def build_exp(addr):
        kind = int.from_bytes(ctx.mem.read(addr, 4), 'little')
        match kind:
            case 0:
                print("(", end="")
                left  = build_exp(int.from_bytes(ctx.mem.read(addr +  8, 8), 'little'))
                print(" == ", end="")
                right = build_exp(int.from_bytes(ctx.mem.read(addr + 16, 8), 'little'))
                print(")", end="")
                return z3.If(left == right, 1, 0)
            case 1:
                print("(", end="")
                left  = build_exp(int.from_bytes(ctx.mem.read(addr +  8, 8), 'little'))
                print(" + ", end="")
                right = build_exp(int.from_bytes(ctx.mem.read(addr + 16, 8), 'little'))
                print(")", end="")
                return left + right
            case 3:
                val = int.from_bytes(ctx.mem.read(addr +  8, 8), 'little')
                print(f"{val:#x}", end="")
                return val
            case 4:
                off = int.from_bytes(ctx.mem.read(addr +  8, 8), 'little')
                print(f"inp[{off}]", end="")
                return z3.Extract(8 * (0x11 - off) + 7, 8 * (0x11 - off), flag)
    solver.add(build_exp(tree) != 0)
    print("")
    if solver.check() == z3.sat:
        m = solver.model()
        print(m)
        flag = m[flag].as_long().to_bytes(18, 'big')
        print(flag.hex())
        return flag
    else:
        print("unsat")

def solve_symblic(d, dis):
    simctx = SymbolicContext()
    simctx.mem.map(0x1000, len(d) - 0x10, d[0x10:])
    simctx.mem.map(0x7fff0000, 0x10000, None)
    simctx.regs[31] = u64(0x1000)
    simctx.regs[30] = u64(0x7fff0f00)

    flag = z3.BitVec("flag", 8 * 0x12)
    inp = z3.Concat(z3.BitVecVal(0, 8 * 7), flag)
    for i in range(0x12):
        simctx.mem.write(0x7fff0f00 + i, z3.Extract(8 * (i + 7) + 7, 8 * i, inp))
    simctx.regs[0] = u64(0x7fff0f00)
    simctx.regs[1] = u64(0x12)

    fin = False
    while not fin:
        for ins in dis.functions[0x1000].blocks[simctx.regs[31]].insns:
            simctx.emulate(ins)
            if ins.mnemonic == "RET":
                print(fin)
                fin = True
                break

    if simctx.solver.check() == z3.sat:
        m = simctx.solver.model()
        print(m)
        flag = m[flag].as_long().to_bytes(18, 'little')
        print(flag.hex())
        return flag
    else:
        print("unsat")

def analyze(file):
    e = ELFFile(file)
    data = e.get_section_by_name(".data")
    print(data.header)
    d = data.data()
    dis = None
    for end, enc in itertools.product(["little", "big"][::-1], [True, False]):
        try:
            dis = Disassembler(0x1000, d[0x10:], leg.Context(end, enc))
            dis.disassemble_function(0x1000)
            dis.recursive_decode()
            break
        except:
            pass

    for _, f in sorted(dis.functions.items()):
        for addr, b in sorted(f.blocks.items()):
            print(f"loc_{addr:04x}:")
            for ins in b.insns:
                print(f"\t[{ins.address:#06x}]: {ins}")

    # highly sophisitcated detection
    _, fun = sorted(dis.functions.items())[-1]
    _, block = sorted(fun.blocks.items())[-1]
    last_ins = block.insns[-1]
    past_addr = last_ins.address + last_ins.size

    print(f"last address: {past_addr:#x}, {len(d) + 0x1000:#x}")

    if past_addr + 0x20 < len(d) + 0x1000:
        return solve_tree(d, dis)

    hasbackbr = False
    for block in fun.blocks.values():
        last_ins = block.insns[-1]
        if InstructionGroup.JMP not in last_ins.grps:
            continue
        print(f"{last_ins}")
        if last_ins.jmp_targets[0] < last_ins.address:
            hasbackbr = True
            break
    else:
        return solve_symblic(d, dis)

    return solve_perm(d, dis)
    
#    emuctx = leg.EmuContext()
#    emuctx.mem.map(0x1000, len(d) - 0x10, d[0x10:])
#    emuctx.mem.map(0x7fff0000, 0x10000, None)
#    emuctx.regs[31] = 0x1000
#    emuctx.regs[30] = 0x7fff0f00
#    inp = bytes.fromhex("00010001bb03ba2f50ead84c4d13abe73c3c")
#    emuctx.mem.write(0x7fff0f00, len(inp), inp)
#    emuctx.regs[0] = u64(0x7fff0f00)
#    emuctx.regs[1] = u64(0x12)
#    for i in range(100):
#        emuctx.step()
#    print(emuctx.regs)
#    print(emuctx.mem.read(0x7fff0f00, len(inp)).hex())

class SymboilcMemory:
    def __init__(self):
        self.mappings = []
        self.symbolic = {}

    def map(self, addr, size, data=None):
        for (mb, ms, _) in self.mappings:
            if (addr + size) <= mb:
                continue
            if (mb + ms) <= addr:
                continue
            raise RuntimeError("overlapping mappings")
        if data is not None:
            data = data[:size].ljust(size, b"\x00")
        else:
            data = bytes([0] * size)
        self.mappings.append((addr, size, bytearray(data)))

    def read(self, addr, size):
        if addr in self.symbolic:
            res = self.symbolic[addr]
            #assert(size * 8 == res.size())
            #print(f"read symbolic value {res}")
            return res

        for (mb, ms, data) in self.mappings:
            if mb <= addr and addr + size <= mb + ms:
                return data[addr - mb:addr - mb + size]

    def toregval(self, data):
        issym = False
        for d in data:
            if type(d) != int:
                issym = True
                break

        if len(data) < 8:
            data = data.rjust(8, b"\x00")

        if not issym:
            return int.from_bytes(data, 'little')

        return z3.Concat([z3.BitVecVal(b, 8) if type(b) == int else b for b in data[::-1]])

    def writeb(self, address, b):
        if type(d) == int:
            self.symbolic.pop(address, None)



    def write(self, address, data):
        print(f"write to {address:#x}")
        self.symbolic[address] = data

class ConcreteContext:
    def __init__(self):
        self.mem = leg.VirtualMemory()
        self.regs = [u64(0) for _ in range(32)]

    def emulate(self, ins):
        print(f"{ins.address:#06x}: {ins}")
        self.regs[31] = ins.address + ins.size
        if isinstance(ins,leg.BinOp) or isinstance(ins,leg.SetCC):
            arg1 = self.regs[ins.arg1]
            arg2 = None
            mnemonic = None

            if not ins.imm:
                arg2 = self.regs[ins.arg2]
                mnemonic = ins.mnemonic
            else:
                arg2 = u64(ins.arg2)
                mnemonic = ins.mnemonic[:-1]

            res = None
            match mnemonic:
                case "OR":
                    res = arg1 | arg2
                case "XOR":
                    res = arg1 ^ arg2
                case "AND":
                    res = arg1 & arg2
                case "ADD":
                    res = arg1 + arg2
                case "SUB":
                    res = arg1 - arg2
                case "MUL":
                    res = arg1 * arg2
                case "DIV":
                    res = arg1 // arg2
                case "SDIV":
                    res = u64(i64(arg1) // i64(arg2))
                case "REM":
                    res = arg1 % arg2
                case "SREM":
                    res = u64(i64(arg1) % i64(arg2))
                case "SLL":
                    res = arg1 << (arg2 & u64(0x3f))
                case "SAR":
                    res = u64(i64(arg1) >> i64(arg2 & u64(0x3f)))
                case "SLR":
                    res = arg1 >> arg2
                case "SETEQ":
                    res = u64(1) if arg1 == arg2 else u64(0)
                case "SETNE":
                    res = u64(1) if arg1 != arg2 else u64(0)
                case "SETLE":
                    res = u64(1) if i64(arg1) <= i64(arg2) else u64(0)
                case "SETLT":
                    res = u64(1) if i64(arg1) < i64(arg2) else u64(0)
                case "SETULE":
                    res = u64(1) if arg1 <= arg2 else u64(0)
                case "SETULT":
                    res = u64(1) if arg1 < arg2 else u64(0)
                case _:
                    raise RuntimeError(f"{mnemonic} not implemented")
            self.regs[ins.rr] = res
        elif isinstance(ins, leg.LoadStoreOp):
            if ins.mnemonic == "LDI":
                self.regs[ins.rr] = u64(ins.imm)
            elif ins.mnemonic[:2] == "ST":
                addr = self.regs[ins.base] + ins.disp
                val = int(self.regs[ins.reg])
                match ins.width:
                    case 0:
                        self.mem.write(addr, bytes([val & 0xff]))
                    case 1:
                        self.mem.write(addr, (val & 0xffff).to_bytes(2, 'little'))
                    case 2:
                        self.mem.write(addr, (val & 0xffffffff).to_bytes(4, 'little'))
                    case 3:
                        self.mem.write(addr, val.to_bytes(8, 'little'))
            elif ins.mnemonic == "LD":
                val = self.mem.read(self.regs[ins.base] + ins.disp, 8)
                self.regs[ins.reg] = u64(int.from_bytes(val, 'little'))
            else:
                raise RuntimeError(f"{ins.mnemonic} not implemented")
        elif isinstance(ins, leg.Branch):
            if ins.mnemonic == "BRCC":
                if self.regs[ins.creg] != u64(0):
                    self.regs[31] = u64(ins.imm)
            elif ins.mnemonic == "BR":
                self.regs[31] = u64(ins.imm)
            elif ins.mnemonic == "RET":
                print(f"return value: {self.regs[0]}")
            else:
                raise RuntimeError(f"{ins.mnemonic} not implemented")
        elif ins.mnemonic == "ENTRY":
            return
        else:
            raise RuntimeError(f"{ins.mnemonic} not implemented")

class SymbolicContext:
    def __init__(self):
        self.mem = SymboilcMemory()
        self.regs = [u64(0) for _ in range(32)]
        self.solver = z3.Solver()

    def emulate(self, ins):
        print(f"{ins.address:#06x}: {ins}")
        self.regs[31] = ins.address + ins.size
        if isinstance(ins,leg.BinOp) or isinstance(ins,leg.SetCC):
            arg1 = self.regs[ins.arg1]
            arg2 = None
            mnemonic = None

            if not ins.imm:
                arg2 = self.regs[ins.arg2]
                mnemonic = ins.mnemonic
            else:
                arg2 = u64(ins.arg2)
                mnemonic = ins.mnemonic[:-1]

            res = None
            match mnemonic:
                case "OR":
                    res = arg1 | arg2
                case "XOR":
                    res = arg1 ^ arg2
                case "AND":
                    res = arg1 & arg2
                case "ADD":
                    res = arg1 + arg2
                case "SUB":
                    res = arg1 - arg2
                case "MUL":
                    res = arg1 * arg2
                case "DIV":
                    if not isinstance(arg1,u64) or not isinstance(arg2,u64):
                        res = z3.UDiv(arg1, arg2)
                    else:
                        res = arg1 // arg2
                case "SDIV":
                    if not isinstance(arg1,u64) or not isinstance(arg2,u64):
                        res = arg1 // arg2
                    else:
                        res = u64(i64(arg1) // i64(arg2))
                case "REM":
                    if not isinstance(arg1,u64) or not isinstance(arg2,u64):
                        res = z3.URem(arg1, arg2)
                    else:
                        res = arg1 % arg2
                case "SREM":
                    if not isinstance(arg1,u64) or not isinstance(arg2,u64):
                        res = arg1 % arg2
                    else:
                        res = u64(i64(arg1) % i64(arg2))
                case "SLL":
                    res = arg1 << (arg2 & u64(0x3f))
                case "SAR":
                    if not isinstance(arg1,u64) or not isinstance(arg2,u64):
                        res = arg1 >> (arg2 & u64(0x3f))
                    else:
                        res = u64(i64(arg1) >> i64(arg2 & u64(0x3f)))
                case "SLR":
                    if not isinstance(arg1,u64) or not isinstance(arg2,u64):
                        res = z3.LShr(arg1, arg2 & u64(0x3f))
                    else:
                        res = arg1 >> arg2
                case "SETEQ":
                    if not isinstance(arg1,u64) or not isinstance(arg2,u64):
                        res = z3.If(arg1 == arg2, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    else:
                        res = u64(1) if arg1 == arg2 else u64(0)
                case "SETNE":
                    if not isinstance(arg1,u64) or not isinstance(arg2,u64):
                        res = z3.If(arg1 != arg2, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    else:
                        res = u64(1) if arg1 != arg2 else u64(0)
                case "SETLE":
                    if not isinstance(arg1,u64) or not isinstance(arg2,u64):
                        res = z3.If(arg1 <= arg2, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    else:
                        res = u64(1) if i64(arg1) <= i64(arg2) else u64(0)
                case "SETLT":
                    if not isinstance(arg1,u64) or not isinstance(arg2,u64):
                        res = z3.If(arg1 < arg2, z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    else:
                        res = u64(1) if i64(arg1) < i64(arg2) else u64(0)
                case "SETULE":
                    if not isinstance(arg1,u64) or not isinstance(arg2,u64):
                        res = z3.If(z3.ULE(arg1, arg2), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    else:
                        res = u64(1) if arg1 <= arg2 else u64(0)
                case "SETULT":
                    if not isinstance(arg1,u64) or not isinstance(arg2,u64):
                        res = z3.If(z3.ULT(arg1, arg2), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64))
                    else:
                        res = u64(1) if arg1 < arg2 else u64(0)
                case _:
                    raise RuntimeError(f"{mnemonic} not implemented")
            self.regs[ins.rr] = res
        elif isinstance(ins, leg.LoadStoreOp):
            if ins.mnemonic == "LDI":
                self.regs[ins.rr] = u64(ins.imm)
            elif ins.mnemonic[:2] == "ST":
                self.mem.write(self.regs[ins.base] + ins.disp, self.regs[ins.reg])
            elif ins.mnemonic == "LD":
                val = self.mem.read(self.regs[ins.base] + ins.disp, 8)
                self.regs[ins.reg] = val
            else:
                raise RuntimeError(f"{ins.mnemonic} not implemented")
        elif isinstance(ins, leg.SetCC):
            raise RuntimeError(f"{ins.mnemonic} not implemented")
        elif isinstance(ins, leg.Branch):
            if ins.mnemonic == "BRCC":
                if isinstance(self.regs[ins.creg], u64):
                    if self.regs[ins.creg] != u64(0):
                        self.regs[31] = u64(ins.imm)
                else:
                    var = self.regs[ins.creg] == u64(0)
                    #print(f"adding:\n{var}\n")
                    self.solver.add(var)
            elif ins.mnemonic == "BR":
                self.regs[31] = u64(ins.imm)
            elif ins.mnemonic == "RET":
                if isinstance(self.regs[0], u64):
                    print(f"return value: {self.regs[0]}")
                else:
                    var = self.regs[0] == u64(1)
                    #print(f"adding:\n{var}\n")
                    self.solver.add(var)
            else:
                raise RuntimeError(f"{ins.mnemonic} not implemented")
        elif ins.mnemonic == "ENTRY":
            return
        else:
            raise RuntimeError(f"{ins.mnemonic} not implemented")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        analyze(f)
