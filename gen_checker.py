import random
from functools import reduce

random = random.SystemRandom()

def gen_checker(kind, solution):
    if kind == 'strcmp':
        return gen_strcmp(solution)
    elif kind == "lcg":
        return gen_lcg(solution)
    elif kind == "lcg_comb":
        return gen_lcg_combine(solution)
    elif kind == "tree_call":
        return gen_tree_call(solution)
    elif kind == "permutation":
        return gen_permutation(solution)

def gen_strcmp(solution):

    cmps = list(enumerate(solution))
    random.shuffle(cmps)
    cmps = "\n    ".join([f"if (data[{i}] != {tar:#x}u) return 0;" for i, tar in cmps])

    code = """#include "stdint.h"
#include "stddef.h"

uint64_t check(uint8_t * data, size_t len) {
"""
    code = code + f"    if (len != {len(solution)}) return 0;\n    "
    code = code + cmps + """
    return 1;
}
"""
    return code

def randomlcg(m):
    # check for power of 2
    assert ((m - 1) & m) == 0
    c = random.randint(0, m // 2 - 1) * 2 + 1
    a = random.randint(100, m // 4 - 1) * 4 + 1
    x0 = random.randint(0, m)
    return (m, a, c, x0)

def lcg(m, a, c, x0):
    xi = x0
    while True:
        yield xi
        xi = (xi * a + c) % m

def gen_lcg(solution):
    m, a, c, x0 = randomlcg(2**32)
    clcg = lcg(m, a, c, x0)
    cmps = list(enumerate(solution))
    random.shuffle(cmps)
    cmps = list(zip(clcg, cmps))

    cmps = "\n".join([f"    if ((data[{i}] ^ {tar ^ (lcgv >> 24):#x}) != (uint8_t)(lcg >> 24u)) return 0;\n    lcg = lcg * {a}u + {c}u;" for (lcgv, (i, tar)) in cmps])

    code = """#include <stdint.h>
#include <stddef.h>

uint64_t check(uint8_t *data, size_t len) {
"""
    code = code + f"    volatile uint64_t lcg = {x0}u;\n"
    code = code + f"    if (len != {len(solution)}) return 0;\n"
    code = code + cmps + """
    return 1;
}
"""
    return code

def combine_list(lst):
    res = []
    cur = None
    last = []
    for idx, tar in lst:
        if cur is None:
            cur = idx
            last = [tar]
            continue
        
        if cur == idx - 1:
            cur = idx
            last.append(tar)
            if len(last) < 4:
                continue
            res.append((cur + 1 - len(last), last))
            cur = None
            last = []
        else:
            res.append((cur + 1 - len(last), last))
            cur = idx
            last = [tar]
    if cur is not None:
        res.append((cur + 1 - len(last), last))
    return res

def gen_lcg_combine(solution):
    m, a, c, x0 = randomlcg(2**32)
    clcg = lcg(m, a, c, x0)
    while True:
        cmps = list(enumerate(solution))
        random.shuffle(cmps)
        combined = combine_list(cmps)
        if len(list(filter(lambda y: len(y[1]) == 4, combined))) > 0:
            break
    #print(combined)
    cmps = list(zip(clcg, combined))
    ifs = []
    for (lcgv, (i, comp)) in cmps:
        tar = reduce(lambda x, y: x * 0x100 + y, comp[::-1], 0)
        match len(comp):
            case 1:
                ifs.append(f"    if ((data[{i}] ^ {tar ^ (lcgv >> 24):#x}u) != (uint8_t)(lcg >> 24u)) return 0;")
            case 2:
                ifs.append(f"    if (((*(uint16_t*) &data[{i}]) ^ {tar ^ (lcgv >> 16):#x}u) != (uint16_t)(lcg >> 16u)) return 0;")
            case 3:
                ifs.append(f"    if ((((*(uint64_t*) &data[{i}]) & 0xffffff) ^ {tar ^ (lcgv >> 8):#x}u) != ((uint32_t)lcg >> 8u)) return 0;")
            case 4:
                ifs.append(f"    if (((*(uint32_t*) &data[{i}]) ^ {tar ^ lcgv:#x}u) != (uint32_t)lcg) return 0;")

    cmps = f"\n    lcg = lcg * {a}u + {c}u;\n".join(ifs)
    #cmps = "\n".join([f"    if ((data[{i}] ^ {tar ^ (lcgv >> 24):#x}) != (lcg >> 24u)) return 0;\n    lcg = lcg * {a}u + {c}u;" for (lcgv, (i, tar)) in cmps])

    code = """#include <stdint.h>
#include <stddef.h>

uint64_t check(uint8_t *data, size_t len) {
"""
    code = code + f"    volatile uint64_t lcg = {x0}u;\n"
    code = code + f"    if (len != {len(solution)}) return 0;\n"
    code = code + cmps + """
    return 1;
}
"""
    return code

#def build_check_tree(tocheck):
#    if len(tocheck) > 4:
#        split = random.randint(1, len(tocheck) - 1)
#        return ("and", build_check_tree(tocheck[:split]), build_check_tree(tocheck[split:]))
#
#    if random.randint(0, len(tocheck) ** 2) > len(tocheck):
#        split = random.randint(1, len(tocheck) - 1)
#        return ("and", build_check_tree(tocheck[:split]), build_check_tree(tocheck[split:]))
#
#    methods = ["direct"]
#    if len(tocheck) > 1:
#        methods = methods + ["xors", "diff", "diff_fst"]
#
#    mthd = random.choice(methods)
#    pl = ["direct", "not", "neg", "xor"]
#    parts = []
#    for ()

def random_permutation():
    lut = [*range(0x100)]
    random.shuffle(lut)

    perms = []
    visited = set()
    for start in range(len(lut)):
        if start in visited:
            continue
        perm = [start]
        cur = lut[start]
        while cur != start:
            visited.add(cur)
            perm.append(cur)
            cur = lut[cur]
        perms.append(perm)

    kgv = {}
    for perm in perms:
        factors = small_factor(len(perm))
        for factor, mult in factors.items():
            if factor not in kgv:
                kgv[factor] = mult
            else:
                kgv[factor] = max(kgv[factor], mult)

    print(kgv)
    kgvval = 1
    for prime, mult in kgv.items():
        for i in range(mult):
            kgvval *= prime
    print(f"permutation: {perms}, length: {kgvval}")
    return (lut, perms, kgvval)

def small_factor(value):
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127]
    factors = {}
    for p in primes:
        num = 0
        while value % p == 0:
            num += 1
            value = value // p
        factors[p] = num
    if value > 1:
        assert(value > 127)
        factors[value] = 1

    return factors

def gen_permutation(solution):
    lut, perms, kgvval = random_permutation()
    while kgvval > 100000 or kgvval < 500:
        lut, perms, kgvval = random_permutation()

    print(f"lut: {lut}")

    code = ["#include <stdint.h>",
            "#include <stddef.h>",
            "",
            "int printf(char *, ...);",
            "",
            "uint64_t check(uint8_t *data, size_t len) {",
            "    uint8_t lut[256];"
            "    uint8_t res = 0;"
            f"    if (len != {len(solution)}) return 0;",
            "    for (unsigned i = 0; i < 256; ++i)",
            "        lut[i] = i;",
            "",
            f"    for (unsigned i = 0; i < {kgvval - 1}; ++i) {{",
            "        uint8_t tmp;"]
    for perm in perms:
        if len(perm) == 1:
            continue
        code.append(f"        tmp = lut[{perm[-1]}];")
        for (cur, nxt) in zip(perm[-1::-1], perm[-2::-1]):
            code.append(f"        lut[{cur}] = lut[{nxt}];")
        code.append(f"        lut[{perm[0]}] = tmp;")
    code = code + ["    }",""]

 #   code += ["    for (unsigned i = 0; i < sizeof(lut); ++i)",
 #           "        printf(\"%02hhx \", lut[i]);",
 #           "    printf(\"\\n \");",
 #           ""]

    chks = [*enumerate(solution)]
    random.shuffle(chks)

    for (i, val) in chks:
#        code.append(f"    printf(\"%02hhx %02hhx\\n\", data[{i}], lut[data[{i}]] ^ {lut[val]});")
#        print(f"{i:2}: {val:02x} {lut[val]:02x}")
        code.append(f"    res |= lut[data[{i}]] ^ {lut[val]:#x};")

    code = code + ["    return !res;", "}"]
    return "\n".join(code)


def gen_tree_call(solution):
    parts = list(enumerate(solution))
    random.shuffle(parts)

    chks = [("eq", ("inp", i), ("lit", x)) for i, x in parts]

    def ands(chklist):
        if len(chklist) == 1:
            return chklist[0]
        split = random.randint(1, len(chklist) - 1)
        p1 = ands(chklist[:split])
        p2 = ands(chklist[split:])
        return ("sum", p1, p2)

    root = ("eq", ands(chks), ("lit", len(chks)))

    code = """//#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>


#ifndef __LEG__
#include <stdio.h>
#else
#define printf(...)
void *malloc(size_t);
#endif

enum NodeKind {
    NODE_EQ,
    NODE_SUM,
    NODE_XOROR8,
    NODE_LIT,
    NODE_INP,
};

typedef struct {
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

static uint8_t *inp = NULL;
static size_t len = 0;

uint64_t evaluate(Node *n);
"""

    funs = ["""uint64_t get_lit(Node *n) {
    printf("%llx\\n", ((LitNode *) n)->literal);
    return ((LitNode *) n)->literal;
}
""", """uint64_t get_inp(Node *n) {
    LitNode *ln = (LitNode*) n;
    printf("inp[%lx] = %hhx\\n", ln->literal, inp[ln->literal]);
    if (ln->literal >= len)
        return 0;
    return inp[ln->literal];
}
""", """uint64_t get_eq(uint64_t l, uint64_t r) {
    printf("%lx == %lx\\n", l, r);
    return l == r;
}
""","""uint64_t get_sum(uint64_t l, uint64_t r) {
    printf("%lx + %lx\\n", l, r);
    return l + r;
}
""","""uint64_t get_xoror8(uint64_t l, uint64_t r) {
    printf("%lx ^| %lx\\n", l, r);
    return ((l ^ r) << 8) | l;
}
"""]
    random.shuffle(funs)
    code = code + "\n".join(funs)

    treebuild = []
    def emit_tree(tree, inuse, litdefined, treedefined):
        def getlit(litinuse, litdefined, prefix):
            litnotinuse = litdefined.difference(litinuse)
            if not litnotinuse:
                return f"{prefix}{len(litdefined)}"
            return random.choice(list(litnotinuse))

        if tree[0] in ["lit", "inp"]:
            lit = getlit(inuse, litdefined, "l")
            litdefined.add(lit)
            inuse.add(lit)
            treebuild.append(f"\t{lit} = (LitNode*) malloc(sizeof(LitNode));")
            treebuild.append(f"\t{lit}->base.kind = NODE_{tree[0].upper()};");
            treebuild.append(f"\t{lit}->literal   = {tree[1]:#x};")
            return (lit, inuse, litdefined, treedefined)

        fun, left, right = tree
        left_node, inuse, litdefined, treedefined = emit_tree(left, inuse, litdefined, treedefined)
        tnode = getlit(inuse, treedefined, "t")
        inuse.add(tnode)
        treedefined.add(tnode)
        treebuild.append(f"\t{tnode} = (TreeNode*) malloc(sizeof(TreeNode));")
        treebuild.append(f"\t{tnode}->base.kind = NODE_{fun.upper()};");
        treebuild.append(f"\t{tnode}->left      = (Node*){left_node};")
        inuse.discard(left_node)
        right_node, inuse, litdefined, treedefined = emit_tree(right, inuse, litdefined, treedefined)
        treebuild.append(f"\t{tnode}->right     = (Node*){right_node};")
        inuse.discard(left_node)
        return (tnode, inuse, litdefined, treedefined)

    croot, _, litdefined, treedefined = emit_tree(root, set(), set(), set())
    code = code + """uint64_t check(uint8_t *data, size_t _len) {
    inp = data;
    len = _len;

"""
    code = code + f"if (_len != {len(solution)}) return 0;\n"
    code = code + "\n" + "\n".join([f"\tLitNode *{lit};" for lit in litdefined])
    code = code + "\n" + "\n".join([f"\tTreeNode *{tn};" for tn in treedefined])

    code = code + "\n\n" + "\n".join(treebuild)

    code = code + f"\n\n\treturn evaluate((Node*){croot});\n"
    code = code + "}\n"
    return code
