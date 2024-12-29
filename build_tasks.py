from gen_checker import gen_checker
from gen_header import build_vm_checker
import asyncio
from consts import *
from random import SystemRandom

random = SystemRandom()

async def build_chall(i, endian, encrypt, *params, **kwargs):
    checker = gen_checker(*params, **kwargs)

    with open(f"checker/chk{i}.c", "w+") as f:
        f.write(checker)

    args = ["../build-llvm-LEG/bin/clang", "-target", "leg-unknown-pc", "-O1", "-c", f"checker/chk{i}.c", f"-o", f"checker_obj/chk{i}.o"]
    if endian == "big":
        args.extend(["-Xclang", "-target-feature", "-Xclang", "+bigendian"])
    if encrypt:
        args.extend(["-Xclang", "-target-feature", "-Xclang", "+insencryption"])

    proc = await asyncio.create_subprocess_exec(*args)

    args = ["../build-llvm-LEG/bin/clang", "-target", "leg-unknown-pc", "-O1", "-S", "-c", f"checker/chk{i}.c", f"-o", f"checker_obj/chk{i}.s"]
    if endian == "big":
        args.extend(["-Xclang", "-target-feature", "-Xclang", "+bigendian"])
    if encrypt:
        args.extend(["-Xclang", "-target-feature", "-Xclang", "+insencryption"])

    proc2 = await asyncio.create_subprocess_exec(*args)
    
    await proc.wait()
    await proc2.wait()

    vm_checker = build_vm_checker(f"checker_obj/chk{i}.o", endian, encrypt)
    with open(f"checker_vm/chk{i}.cpp", "w+") as f:
        f.write(vm_checker)

    proc = await asyncio.create_subprocess_exec(
        "../build-llvm-LEG/bin/clang++",
        "-iquote", ".", "-std=c++2b", "-O1", "-fvisibility=hidden", f"checker_vm/chk{i}.cpp", "-s", f"-o", f"checker_bin/chk{i}.bin")
    await proc.wait()

def config():
    while True:
        for mthd in ["strcmp", "lcg", "lcg_comb", "tree_call", "permutation"]:
            for end in ["big", "little"]:
                for enc in [True, False]:
                    yield (mthd, end, enc)

if __name__ == "__main__":

    async def build_all():
        tasks = [(mthd, end, enc, i.to_bytes(2, 'big') + sol.to_bytes(16, 'big')) for (i, ((mthd, end, enc), sol)) in enumerate(zip(config(), target_values), 1)]
        random.shuffle(tasks)
        #tasks = [("strcmp", b"thisIsAVeryBadPassword!"), ("lcg", b"thispasswordisevenworse"), ("lcg_comb", b"lmaodoyoueventry"), ("tree_call", b"breakingThe5th?Wall"),("permutation", b"thischallisfucked")]
        #tasks = [("permutation", b"thischallisfucked")]
        #tasks = [build_chall(i, "big", True, kind=mthd, solution=sol) for i, (mthd, sol) in enumerate(tasks)]
        tasks = [build_chall(i, end, enc, kind=mthd, solution=sol) for (i, (mthd, end, enc, sol)) in enumerate(tasks)]
        await asyncio.gather(*tasks)

    asyncio.run(build_all())



