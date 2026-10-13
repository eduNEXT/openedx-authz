"""Compare the pgettext() pairs in generated.py with the msgctxt/msgid entries in django.po."""
import ast, sys, pathlib, polib

for out in sorted(pathlib.Path(sys.argv[1]).iterdir()):
    gen, po = out / "generated_py.out", out / "django.po"
    print(f"\n=== {out.name} (exit {(out / 'exit_code').read_text().strip()})")
    if not gen.exists():
        print("  no generated module"); continue
    calls = [tuple(a.value for a in n.value.args) for n in ast.parse(gen.read_text()).body
             if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)]
    if not po.exists():
        print(f"  generated calls: {len(calls)}, no django.po"); continue
    entries = {(e.msgctxt, e.msgid): e for e in polib.pofile(str(po))}
    print(f"  generated calls: {len(calls)}, po entries with context: {sum(1 for k in entries if k[0])}")
    for ctx, msg in calls:
        e = entries.get((ctx, msg))
        flags = f" flags={e.flags}" if e and e.flags else ""
        status = "OK " if e else "MISSING"
        print(f"  {status} {ctx!r} -> {msg!r}{flags}")
    for (ctx, msg) in entries:
        if ctx and (ctx, msg) not in calls:
            print(f"  EXTRA IN PO {ctx!r} -> {msg!r}")
