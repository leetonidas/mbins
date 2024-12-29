from disassamble import InstructionGroup, JmpKind
from numpy import (uint64 as u64, int64 as i64)
import struct

regnames = [f"r{i}" for i in range(29)] + ["bp", "sp", "pc"]

class Instruciton:
    def __init__(self, ip, data):
        self.address = ip
        self.bytes = data[:4]
        self.size = 4
        self.grps = []
        self.jmp_targets = []

    def __repr__(self):
        return f"[ {self.address:#x}: {self.mnemonic} {self.op_str} ]"

    def __str__(self):
        return f"{self.mnemonic} {self.op_str}"

class BinOp(Instruciton):
    def __init__(self, ip, data, opcode):
        super().__init__(ip, data[:4])
        binop = (opcode >> 25) & 0xf
        self.mnemonic = ["OR", "XOR", "AND", "ADD", "SUB", "MUL", "DIV", "SDIV", "REM", "SREM", "SLL", "SAR", "SLR", "ROTL", "ROTR"][binop]
        
        self.imm = (opcode >> 24) & 1 == 0
        if self.imm:
            self.mnemonic = self.mnemonic + "I"
        self.rr = (opcode >> 19) & 0x1f
        self.arg1 = (opcode >> 14) & 0x1f
        if self.imm:
            self.arg2 = opcode & 0x3fff
            self.op_str = f"{regnames[self.rr]}, {regnames[self.arg1]}, {self.arg2:#x}"
        else:
            self.arg2 = (opcode >> 9) & 0x1f
            self.op_str = f"{regnames[self.rr]}, {regnames[self.arg1]}, {regnames[self.arg2]}"
#        print(self.__repr__())

    def emulate(self, ctx):
        arg1 = ctx.regs[self.arg1]
        arg2 = None 
        mnemonic = None
        if not self.imm:
            arg2 = ctx.regs[self.arg2]
            mnemonic = self.mnemonic
        else:
            arg2 = u64(self.arg2)
            mnemonic = self.mnemonic[:-1]

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
                res = arg1 / arg2
            case "SDIV":
                res = u64(i64(arg1) / i64(arg2))
            case "REM":
                res = arg1 % arg2
            case "SREM":
                res = u64(i64(arg1) % i64(arg2))
            case "SLL":
                res = arg1 << (arg2 & u64(0x3f))
            case "SAR":
                res = u64(i64(arg1) >> i64(arg2 & u64(0x3f)))
            case "SLR":
                res = arg1 >> (arg2 & 0x3f)
            case "ROTL":
                ra = arg2 & u64(0x3f)
                rn = (64 - ra) & u64(0x3f)
                res = (arg1 << ra) | (arg1 >> rn)
            case "ROTR":
                ra = arg2 & u64(0x3f)
                rn = (64 - ra) & u64(0x3f)
                res = (arg1 >> ra) | (arg1 << rn)
        ctx.regs[self.rr] = res

class LoadStoreOp(Instruciton):
    def __init__(self, ip, data, opcode, endian, lfsr):
        super().__init__(ip, data[:4])
        binop = (opcode >> 27) & 0x3
        self.mnemonic = ["LDI", "LD", "ST", "ST"][binop]
        if binop == 0:
            self.bytes = data[:12]
            self.size = 12
            self.rr = (opcode >> 16) & 0x1f
            self.imm = struct.unpack_from("<Q" if endian == 'little' else ">Q", data, 4)[0]
            if lfsr is not None:
                cor = 0
                a = get_next_lfsr(lfsr)
                b = get_next_lfsr(a)
                if endian == 'little':
                    cor = a | (b << 32)
                else:
                    cor = b | (a << 32)
                self.imm = self.imm ^ cor
            self.op_str = f"{regnames[self.rr]} {self.imm:#x}"
#            print(self.__repr__())
            #self.arg1 = struct.unpack_from(">Q", data, 4)
            return

        self.reg = (opcode >> 21) & 0x1f
        self.base = (opcode >> 16) & 0x1f
        self.disp = opcode & 0xff
        if (opcode >> 7) & 1:
            self.off = (opcode & 0x7f) - 0x80
        if binop == 1:
            self.op_str = f"{regnames[self.reg]}, [{regnames[self.base]} + {self.disp:#x}]"
        else:
            self.width = (opcode >> 26) & 3
            self.mnemonic = self.mnemonic + "BQHW"[self.width]
            self.op_str = f"[{regnames[self.base]} + {self.disp:#x}], {regnames[self.reg]}"
#        print(self.__repr__())

    def emulate(self, ctx):
        match self.mnemonic:
            case "LDI":
                ctx.regs[self.rr] = u64(self.imm)
            case "LD":
                addr = ctx.regs[self.base] + self.disp
                val = ctx.mem[addr]
#                print(f"loaded: {val:#x} from {addr:#x}")
                ctx.regs[self.reg] = val
            case "ST":
                val = ctx.regs[self.reg]
                addr = ctx.regs[self.base] + self.disp
#                print(f"storing: {val:#x} to {addr:#x}")
                ctx.mem.write(addr, 1 << self.size)
                ctx.mem[addr] = ctx.regs[self.reg]

class SetCC(Instruciton):
    def __init__(self, ip, data, opcode):
        super().__init__(ip, data[:4])
        binop = (opcode >> 25) & 0x7
        self.mnemonic = ["SETEQ", "SETNE", "SETLE", "SETLT", "SETULE", "SETULT"][binop]
        
        self.imm = (opcode >> 24) & 1 == 1
        if self.imm:
            self.mnemonic = self.mnemonic + "I"
        self.rr = (opcode >> 19) & 0x1f
        self.arg1 = (opcode >> 14) & 0x1f
        if self.imm:
            self.arg2 = opcode & 0x3fff
            self.op_str = f"{regnames[self.rr]}, {regnames[self.arg1]}, {self.arg2:#x}"
        else:
            self.arg2 = (opcode >> 9) & 0x1f
            self.op_str = f"{regnames[self.rr]}, {regnames[self.arg1]}, {regnames[self.arg2]}"
#        print(self.__repr__())

    def emulate(self, ctx):
        arg1 = ctx.regs[self.arg1]
        arg2 = None 
        mnemonic = None
        if not self.imm:
            arg2 = ctx.regs[self.arg2]
            mnemonic = self.mnemonic
        else:
            arg2 = u64(self.arg2)
            mnemonic = self.mnemonic[:-1]

        self.res = None
        match mnemonic:
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
        ctx.regs[self.rr] = res

class Branch(Instruciton):
    def __init__(self, ip, data, opcode):
        super().__init__(ip, data[:4])
        binop = (opcode >> 26) & 0x3
        self.mnemonic = ["RET", "BR", "CALL"][binop]

        match binop:
            case 0:
                self.grps.extend([InstructionGroup.TERMINATOR, InstructionGroup.RETURN])
                self.op_str = ""
            case 1:
                self.jmp_kind = JmpKind.DIRECT
                self.grps.extend([InstructionGroup.TERMINATOR, InstructionGroup.JMP])
                if (opcode >> 25) & 1 == 0:
                    self.mnemonic = self.mnemonic + "CC"
                    self.grps.append(InstructionGroup.CONDITIONAL)
                    self.creg = (opcode >> 20) & 0x1f
                    if (opcode >> 19) & 1:
                        self.off = (opcode & 0x3ffff) - 0x40000
                    else:
                        self.off = opcode & 0x3ffff
                    self.off *= 4
                    self.imm = self.address + self.off
                    self.op_str = f"{regnames[self.creg]} {self.imm:#x}"
                else:
                    if (opcode >> 24) & 1:
                        self.off = (opcode & 0xffffff) - 0x1000000
                    else:
                        self.off = opcode & 0xffffff
                    self.off *= 4
                    self.imm = self.address + self.off
                    self.op_str = f"{self.imm:#x}"
                self.jmp_targets = [self.imm]
            case 2:
                self.jmp_kind = JmpKind.INDIRECT
                self.tar = (opcode >> 20) & 0x1f
                self.numargs = opcode & 0xfffff
                self.op_str = f"{regnames[self.tar]} ({self.numargs} arguments)"
#        print(self.__repr__())

    def emulate(self, ctx):
        match self.mnemonic:
            case "RET":
                ctx.regs[31] = ctx.mem[ctx.regs[30]]
                ctx.regs[30] = ctx.regs[30] + 8
            case "BR":
                ctx.regs[31] = self.imm
            case "BRCC":
                rv = ctx.regs[self.creg]
                if ctx.regs[self.creg] != u64(0):
                    ctx.regs[31] = self.imm
            case "CALL":
                sp = ctx.regs[30] - 8
                ctx.regs[30] = sp
                ctx.mem[sp] = self.address + 4
                ctx.regs[31] = ctx.regs[self.tar]

def decode_instruction(endian, ip, data, lfsr):
    assert(len(data) >= 4)
    opcode = struct.unpack_from("<I" if endian == 'little' else ">I", data, 0)[0]
    if lfsr is not None:
        opcode = opcode ^ lfsr
    opkind = opcode >> 29
#    if lfsr is not None:
#        print(f"[{ip:#06x}] ({lfsr:#x}): {opcode:#x} - {opkind}")
    match opkind:
        case 0:
            return BinOp(ip, data, opcode)
        case 1:
            if (opcode >> 28) & 1:
                return Branch(ip, data, opcode)
            else:
                return SetCC(ip, data, opcode)
        case 2:
            return LoadStoreOp(ip, data, opcode, endian, lfsr)

def get_next_lfsr(val):
    val = (val ^ (val << 13)) & 0xffffffff;
    val = (val ^ (val >> 17)) & 0xffffffff;
    val = (val ^ (val << 5)) & 0xffffffff;
    return val

class Context:
    def __init__(self, endian, encryption):
        self.endian = endian
        self.encryption = encryption
        self.lfsrs = {}

    def get_jmp_targets(self, ins):
        return ins.jmp_targets

    def get_call_targets(self, ins):
        return ins.call_targets

    def ins_groups(self, ins):
        return ins.grps

    def disasm_single(self, data, ip):
        lfsr = None
        if self.encryption:
            if ip not in self.lfsrs:
                res = Instruciton(ip, data)
                res.mnemonic = "ENTRY"
                res.lfsr = struct.unpack("<I" if self.endian == "little" else ">I", res.bytes)[0]
                res.op_str = f"{res.lfsr:#x}"
                nxt = get_next_lfsr(res.lfsr)
                self.lfsrs[ip + res.size] = nxt
                return res
            else:
                lfsr = self.lfsrs[ip]
        ins = decode_instruction(self.endian, ip, data, lfsr)
        if self.encryption:
            nxt = get_next_lfsr(lfsr)
            if InstructionGroup.JMP in ins.grps:
                ins.size = ins.size + 4
                if ins.jmp_targets[0] not in self.lfsrs:
                    cor = data[4:8]
                    cor = struct.unpack("<I" if self.endian == "little" else ">I", cor)[0]
                    cor = cor ^ nxt
#                    print(f"jmp to {ins.jmp_targets[0]:#x} - target lfsr: {cor:#x}")
                    self.lfsrs[ins.jmp_targets[0]] = get_next_lfsr(cor)
                if InstructionGroup.CONDITIONAL not in ins.grps:
                    return ins
            if InstructionGroup.TERMINATOR in ins.grps and not InstructionGroup.CONDITIONAL in ins.grps:
                return ins
            nxt = lfsr
            for i in range(4, ins.size + 4, 4):
                nxt = get_next_lfsr(nxt)
                if ip + i not in self.lfsrs:
                    self.lfsrs[ip + i] = nxt

        #print(f"{ins.address:#06x}: {ins}")
        return ins

class VirtualMemory:
    def __init__(self):
        self.mappings = []

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
        for (mb, ms, data) in self.mappings:
            if mb <= addr and addr + size <= mb + ms:
                return data[addr - mb:addr - mb + size]
        raise RuntimeError("memory access error")

    def write(self, addr, value, size=None):
        if type(value) == int:
            value = value.to_bytes(size, 'little')
        else:
            size = len(value)
        for (mb, ms, data) in self.mappings:
            if mb <= addr and addr + size <= mb + ms:
                data[addr - mb:addr - mb + size] = value
                return
        raise RuntimeError("memory access error")

    def __getitem__(self, key):
        for (mb, ms, data) in self.mappings:
            if mb <= key and key + 8 <= mb + ms:
                return u64(struct.unpack_from("<Q", data, key - mb)[0])
        raise RuntimeError("memory access error")

    def __setitem__(self, key, value):
        for (mb, ms, data) in self.mappings:
            if mb <= key and key + 8 <= mb + ms:
                data[key - mb:key - mb + 8] = struct.pack("<Q", int(value))
                return
        raise RuntimeError("memory access error")

class EmuContext:
    def __init__(self):
        self.mem = VirtualMemory()
        self.regs = [u64(0) for _ in range(32)]

    def step(self):
        ins = decode_instruction(int(self.regs[31]), self.mem.read(self.regs[31], 12))
        print(f"{ins.address:#06x}: {ins.mnemonic} {ins.op_str}")
        self.regs[31] = self.regs[31] + ins.size
        ins.emulate(self)
