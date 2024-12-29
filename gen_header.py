import leg
import disassamble
from elffile import Elffile
import elffile
import sys
import elf
from reencode import reencodeElf
from numpy import uint64 as u64

def build_reloc_stubs(e, mapping, endian, encrypt, regtype, numregs, regargs, retreg, stacksize, data):
    stmts = []
    defs = []
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
                stmt = f"*(uint64_t *)&vm.data[{mapping[tsec] + rela.r_offset + 4}]", f"(uint64_t) &vm.data[{mapping[stsec] + toff + rela.r_addend}]"
                stmts.append(stmt)

            elif sym.sym.st_shndx == 0:
                nm = sym.name.decode()
                if nm in ["evaluate", "malloc", "printf"]:
                    #print(f"skipping define of {nm}")
                    pass
                else:
                    defs.append(nm)
                stmt = stmt = f"*(uint64_t *)&vm.data[{mapping[tsec] + rela.r_offset + 4}]", f"(uint64_t) {nm}"
                stmts.append(stmt)

    fun = ["#include <cstring>",
                "#include <cstdarg>",
                "#include \"emulator.h\"",
                "",
                f"typedef Context<{regtype}, {numregs}, {str(encrypt).lower()}> Ctx;",
                "struct Node_t;",
                "uint64_t evaluate(struct Node_t *n);"
                "",
                data,
                ""]
    fun = fun + [f"void *{df};" for df in defs]
    fun = fun + ["",
            "template <std::endian ope>"
            "void init(Ctx &vm) {",
            "    if constexpr (std::endian::native == ope) {"]
    fun = fun + [f"    {stmt} ^= {val};" for stmt, val in stmts]
    fun = fun + ["    } else {"]
    fun = fun + [f"    {stmt} ^= std::byteswap({val});" for stmt, val in stmts]
    fun = fun + ["    }",
            "}",
            "",
            "thread_local Ctx *ctx = nullptr;",
            "",
            "Ctx &getVM() {",
            "    if (!ctx) {",
            "        ctx = new Ctx{{ 0 }, vmdata, (uint8_t*) vmdata + sizeof(vmdata)};",
            f"        ctx->regs[30] = (uint64_t) &(new uint64_t[{stacksize}])[{stacksize}];",
            f"        init<std::endian::{endian}>(*ctx);",
            "    }",
            "    return *ctx;",
            "}",
            "",
            "__attribute__((always_inline))",
            "uint64_t call_vm(uint64_t addr, uint64_t nargs, ...) {",
            "    const unsigned regargs[] = {" + ", ".join((str(r) for r in regargs)) + "};",
            "    va_list args;",
            "    va_start(args, nargs);",
            "    Ctx &ctx = getVM();",
            f"    auto save_sp = ctx.regs[{numregs - 2}];"
            f"    for (unsigned i = 0; i < nargs && i < {len(regargs)}; ++i) " + "{",
            "        ctx.regs[regargs[i]] = va_arg(args, uint64_t);",
            "    }",
            f"    for (unsigned i = {len(regargs)}; i < nargs; ++i) " + "{",
            f"        uint64_t *sp = (uint64_t*) ctx.regs[{numregs - 2}];",
            "        *(--sp) = va_arg(args, uint64_t);",
            f"        ctx.regs[{numregs - 2}] = (uint64_t) sp;",
            "    }",
            f"    uint64_t *sp = (uint64_t*) ctx.regs[{numregs - 2}];",
            "    *(--sp) = 0x13371337;",
            f"    ctx.regs[{numregs - 2}] = (uint64_t) sp;",
            f"    ctx.regs[{numregs - 1}] = (uint64_t) &ctx.data[addr];"]

    if encrypt:
        fun = fun + ["    ctx.lfsr = 0;"]

    fun = fun + [f"    while (ctx.regs[{numregs - 1}] != 0x13371337) " + "{",
            f"        step<std::endian::{endian},{regtype},{numregs}>(ctx);",
            "    }",
            f"    ctx.regs[{numregs - 2}] = save_sp;"
            f"    return ctx.regs[{retreg}];",
            "}"]

    fun = "\n".join(fun)
    return fun

def build_function_stups(e, mapping):
    sigs = {"check": ["uint64_t", "uint8_t*", "std::size_t"],
            "get_inp": ["uint64_t", "Node *"],
            "get_lit": ["uint64_t", "Node *"],
            "get_eq": ["uint64_t", "uint64_t", "uint64_t"],
            "get_sum": ["uint64_t", "uint64_t", "uint64_t"],
            "get_xoror8": ["uint64_t", "uint64_t", "uint64_t"],
            }
    bdy = """{
    Ctx &vm = getVM();
    uint64_t *sp = (uint64_t*) vm.regs[30];
    *(--sp) = 0x13371337;
    vm.regs[30] = (uint64_t) sp;"""

    needsEvaluate = False
    funs = []
    for symsec in e.symsecs.values():
        for sym in symsec:
            if sym.sym.st_type() != elf.STT_FUNC or sym.sym.st_shndx not in mapping:
                if sym.name.decode() == "evaluate":
                    needsEvaluate = True
                #print(f"skippin {sym.name}")
                continue
            #print(f"emitting {sym.name}")
            args = sigs[sym.name.decode()]
            off = mapping[sym.sym.st_shndx] + sym.sym.st_value
            fun = [f"{args[0]} {sym.name.decode()}(" + ", ".join((f"{tp} a{i}" for i, tp in enumerate(args[1:]))) + ")" + "{"]
            if args[0] == "void":
                fun.append("    call_vm(" + ", ".join([f"{off:#x}lu", f"{len(args) - 1}"] + [f"({tp}) a{i}" for i, tp in enumerate(args[1:])]) + ");")
            else:
                fun.append(f"    return ({args[0]}) call_vm(" + ", ".join([f"{off:#x}lu", f"{len(args) - 1}"] + [f"({tp}) a{i}" for i, tp in enumerate(args[1:])]) + ");")
            fun.append("}")
            funs.append("\n".join(fun))

    if needsEvaluate:
        funs.insert(0, """
enum NodeKind {
    NODE_EQ,
    NODE_SUM,
    NODE_XOROR8,
    NODE_LIT,
    NODE_INP,
};

typedef struct Node_t {
    enum NodeKind kind;
} Node;

typedef struct {
    Node base;
    Node *left;
    Node *right;
} TreeNode;

typedef struct {
    Node base;
    uint64_t literal;
} LitNode;
""")
        
        funs.append("""
uint64_t evaluate(Node *n) {
    if (n->kind == NODE_LIT)
        return get_lit(n);
    if (n->kind == NODE_INP)
        return get_inp(n);

    TreeNode *nt = (TreeNode*) n;
    uint64_t l = evaluate(nt->left);
    uint64_t r = evaluate(nt->right);

    switch (nt->base.kind) {
    case NODE_EQ:
        return get_eq(l, r);
    case NODE_SUM:
        return get_sum(l, r);
    case NODE_XOROR8:
        return get_xoror8(l, r);
    default:
        return 0;
    }
}
""")

    funs.append("""uint8_t fromhex(char a) {
        if (a >= '0' && a <= '9')
            return a - '0';
        if (a >= 'a' && a <= 'f')
            return a - 'a' + 10;
        if (a >= 'A' && a <= 'F')
            return a - 'A' + 10;
        return 0xff;
}""")

    funs.append("""int main(int argc, char **argv) {
    if (argc != 2)
        return 1;
    uint64_t len = strlen(argv[1]);
    if (len & 1)
        return 1;
    uint8_t *buf = (uint8_t*) malloc(len / 2);
    for (uint64_t i = 0; i < len; i += 2) {
        uint8_t h = fromhex(argv[1][i]);
        uint8_t l = fromhex(argv[1][i + 1]);
        if (h >= 0x10 || l >= 0x10)
            return 1;
        buf[i / 2] = (h << 4) | l;
    }
    return !check(buf, len / 2);
}""")

    return funs

def build_vm_checker(file, endian, encrypt):
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

    if encrypt:
        data, _ = reencodeElf(e, mapping, data, endian)

    vmdata = "uint8_t vmdata[] = {" + ", ".join([hex(d) for d in data]) + "};"

    funs = []
    funs.append(build_reloc_stubs(e, mapping, endian, encrypt, "uint64_t", 32, [i for i in range(8)], 0, 0x400, vmdata))
    funs.extend(build_function_stups(e, mapping))
    file = "\n\n".join(funs)
    return file

if __name__ == "__main__":
    elffile.machineMap[0x200] = "LEG"
    e = Elffile(sys.argv[1])

    addr = 0
    align = 0x4
    data = bytes()
    mapping = {}
    for (secnum, sec) in filter(lambda x: x[1].sh_flags & elf.SHF_ALLOC == elf.SHF_ALLOC, enumerate(e.shdr)):
        secdata = e.rawdata[sec.sh_offset:sec.sh_offset + sec.sh_size]
        data = data + secdata
        mapping[secnum] = addr
        addr = addr + sec.sh_size

    vmdata = "uint8_t vmdata[] = {" + ", ".join([hex(d) for d in data]) + "};"

    funs = []
    funs.append(build_reloc_stubs(e, mapping, "little", "uint64_t", 32, [i for i in range(8)], 0, 0x400, vmdata))
    funs.extend(build_function_stups(e, mapping))
    file = "namespace {\n\n".join(funs) + "\n}"

    with open("generated.cpp", "w") as f:
        f.write(file)
    print(file)

