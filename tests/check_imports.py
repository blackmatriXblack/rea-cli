import ast, os, sys
mods = set()
for root, _, files in os.walk("rea_core"):
    for name in files:
        if not name.endswith(".py"): continue
        tree = ast.parse(open(os.path.join(root, name), encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names: mods.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods.add(node.module.split(".")[0])
stdlib = sys.stdlib_module_names
external = sorted(m for m in mods if m not in stdlib and m != "rea_core")
print("top-level imports:", ", ".join(sorted(mods)))
print("non-stdlib:", external or "none")
