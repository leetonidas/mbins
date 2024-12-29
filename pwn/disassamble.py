from enum import Enum

class InstructionGroup(Enum):
    CALL = 1
    JMP = 2
    CONDITIONAL = 3
    TERMINATOR = 4
    RETURN = 5

class JmpKind(Enum):
    DIRECT = 1
    INDIRECT = 2

class Function:
    def __init__(self, Deobfuscator, addr):
        self.deobfuscator = Deobfuscator
        self.addr = addr
        self.calls = set()
        self.blocks = dict()
        self.addr_blockmap = dict()

    def getFunction(Deobfuscator, addr):
        if addr in Deobfuscator.functions:
            return Deobfuscator.functions[addr]
        fun = Function(Deobfuscator, addr)
        Deobfuscator.functions[addr] = fun
        BasicBlock.getBlock(fun, addr)
        return fun

    def getBlockAt(self, addr):
        if addr in self.addr_blockmap:
            block = self.addr_blockmap[addr]
            if block.addr == addr:
                return block
            retblock = BasicBlock.getBlock(self, addr)
            block.split(retblock)
        else:
            return BasicBlock.getBlock(self, addr)

class BasicBlock:
    def __init__(self, Function, addr):
        self.addr = addr
        self.deobfuscator = Function.deobfuscator
        self.function = Function
        self.insns = []
        self.successors = set()
        self.disassembled = False

    def getBlock(Function, addr):
        if addr in Function.blocks:
            return Function.blocks[addr]
        bb = BasicBlock(Function, addr)
        Function.blocks[addr] = bb
        Function.deobfuscator.disassemble_block(bb)
        return bb

    def split(self, block):
        taddr = block.addr
        idx = next((ins[0] for ins in enumerate(self.insns) if ins[1].address == taddr))
        block.insns = self.insns[idx:]
        for ins in block.insns:
            self.function.addr_blockmap[ins.address] = block
        self.insns = self.insns[:idx]
        block.successors = self.successors
        self.successors = {block}
        block.disassembled = True

class Disassembler:
    def __init__(self, addr, dat, ctx):
        self.addr = addr
        self.dat = dat[:]
        self.functions = dict()
        self.waiting_for_return = []
        self.ctx = ctx
        self.queue = []

    def mem_write(self, addr, data):
        offset = self.offset_from_addr(addr)
        self.dat = self.dat[:offset] + data + self.dat[offset + len(data):]

    def mem_read(self, addr, l):
        offset = self.offset_from_addr(addr)
        if l is None:
            return self.dat[offset:]
        else:
            return self.dat[offset:offset+l]

    def offset_from_addr(self, addr):
        return addr - self.addr

    def addr_from_offset(self, offset):
        return offset + self.addr

    def disassemble_function(self, addr):
        Function.getFunction(self, addr)

    def disassemble_block(self, bb):
        self.queue.insert(0, bb)

    def recursive_decode(self, fuel=None):
        while len(self.queue) > 0 and (fuel is None or fuel > 0):
            cur = self.queue[0]
            self.queue = self.queue[1:]
            fuel = self.disassemble(cur, fuel)

    def disassemble(self, block, fuel=None):
        fun = block.function
        ip = block.addr
        while True:
            if ip in fun.addr_blockmap:
                fun.getBlockAt(ip)
                return fuel

            off = self.offset_from_addr(ip)
            assert off >= 0
            ins = self.ctx.disasm_single(self.dat[off:], ip)
            assert ins is not None

            block.insns.append(ins)
            if fuel is not None:
                fuel = fuel - 1
            fun.addr_blockmap[ip] = block

            grps = self.ctx.ins_groups(ins)

            if InstructionGroup.CALL in grps:
                tars = self.ctx.get_call_targets(ins)
                for tar in tars:
                    tfun = getFunction(self, tar)
                    fun.calls.add(tfun)

            if InstructionGroup.JMP in grps:
                tars = self.ctx.get_jmp_targets(ins)
                for tar in tars:
                    block.successors.add(fun.getBlockAt(tar))
                if InstructionGroup.CONDITIONAL in grps:
                    block.successors.add(fun.getBlockAt(ip + ins.size))

            if InstructionGroup.TERMINATOR in grps:
                return fuel

            if fuel == 0:
                return 0

            ip += ins.size
            off += ins.size
