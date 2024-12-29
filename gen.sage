p = random_prime(2**128, lbound=2**127)

F = Zmod(p)
G.<x> = F[]

rands = [F.random_element() for _ in range(950)]

poly = G(rands)

key = poly[0]

tarvals = [poly(i) for i in range(1,1001)]

with open("consts.py", "w") as f:
    f.write(f"prime = {p}\n")
    f.write(f"key = {key}\n")
    f.write(f"target_values = {tarvals}\n")