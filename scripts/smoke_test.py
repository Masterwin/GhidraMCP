# /// script
# requires-python = ">=3.10"
# dependencies = ["requests>=2,<3"]
# ///
"""
Smoke test directo contra el servidor HTTP del plugin GhidraMCP (sin pasar por MCP).

Requisitos: Ghidra abierto, el plugin GhidraMCP cargado y un programa abierto en el
CodeBrowser. Por defecto apunta a http://127.0.0.1:8080/.

Uso:
    python scripts/smoke_test.py
    python scripts/smoke_test.py --addr 0x401000 --pattern "55 8b ec"
"""
import argparse
import sys
import requests

def check(name, ok, detail=""):
    mark = "OK  " if ok else "FAIL"
    print(f"[{mark}] {name}{(' -> ' + detail) if detail else ''}")
    return ok

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--server", default="http://127.0.0.1:8080/")
    p.add_argument("--addr", default=None, help="Direccion conocida de una funcion para probar bytes/decompile")
    p.add_argument("--pattern", default=None, help="Patron hex para search_bytes, p.ej. '55 8b ec'")
    args = p.parse_args()
    base = args.server.rstrip("/") + "/"

    passed = True

    # 1) Sanidad: el servidor responde y hay programa cargado
    try:
        r = requests.get(base + "methods", params={"limit": 5}, timeout=5)
        passed &= check("conexion /methods", r.ok and "No program loaded" not in r.text,
                        (r.text.splitlines()[:1] or ["<vacio>"])[0])
    except Exception as e:
        check("conexion /methods", False, str(e))
        print("\nNo hay servidor en pie. Abre Ghidra + plugin + un programa y reintenta.")
        return 1

    # Si no nos dan addr, intentamos sacar una funcion automaticamente
    addr = args.addr
    if not addr:
        try:
            r = requests.get(base + "list_functions", timeout=5)
            # formato esperado por linea: "<nombre> @ <addr>" o similar; buscamos un 0x...
            for line in r.text.splitlines():
                tok = [t for t in line.replace(",", " ").split() if t.lower().startswith("0x")]
                if tok:
                    addr = tok[0]
                    break
        except Exception:
            pass
    print(f"\nDireccion de prueba: {addr or '(ninguna - pasa --addr para probar bytes/decompile)'}\n")

    # 2) read_bytes (endpoint NUEVO)
    if addr:
        r = requests.get(base + "read_bytes", params={"address": addr, "length": 16}, timeout=10)
        passed &= check("NUEVO read_bytes", r.ok and ":" in r.text and "error" not in r.text.lower(),
                        r.text.strip()[:60])

    # 3) search_bytes (endpoint NUEVO)
    pattern = args.pattern or "55 8b ec"  # prologo x86 tipico; en x64 quiza no exista
    r = requests.get(base + "search_bytes", params={"pattern": pattern, "limit": 5}, timeout=15)
    passed &= check(f"NUEVO search_bytes ('{pattern}')",
                    r.ok and "Invalid" not in r.text and "required" not in r.text,
                    r.text.strip().replace("\n", " ")[:60])

    # 4) decompile con timeout configurable (parametro NUEVO)
    if addr:
        r = requests.get(base + "decompile_function", params={"address": addr, "timeout": 120}, timeout=130)
        passed &= check("decompile_function timeout=120",
                        r.ok and "failed" not in r.text.lower() and len(r.text) > 0,
                        f"{len(r.text)} chars de C")

    print("\n" + ("TODO OK" if passed else "HAY FALLOS - revisa arriba"))
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())
