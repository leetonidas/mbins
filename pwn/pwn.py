from analyze import analyze
import subprocess

err = []
res = []
for i in range(1000):
    with open(f"../checker_bin/chk{i}.bin", "rb") as f:
        try:
            flag = analyze(f)
            r = subprocess.run([f"../checker_bin/chk{i}.bin", flag.hex()])
            assert(r.returncode == 0)
            res.append(flag)
        except:
            err.append(i)

print(f"found {len(res)} solutions")
print(f"errored: {err}")

with open("solution.py", "w") as f:
    f.write(str(res))