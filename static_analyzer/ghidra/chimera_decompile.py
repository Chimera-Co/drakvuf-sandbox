# Ghidra headless post-script (Jython 2.7): decompile a bounded set of interesting functions to JSON.
# @runtime Jython
#
# Args: <targets.json> <out.json> <max functions> <decompile budget seconds>
# Each function also gets up to MAX_ASM instructions and its callee/caller entry addresses (for the call graph).
# Order: entry points, exported functions, functions containing capa match addresses (targets.json), then the
# largest remaining functions until <max>. Each function gets a decompile timeout; output is capped per function.
import io
import json
import time

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.framework import Application
from ghidra.util.task import ConsoleTaskMonitor

PER_FUNCTION_S = 20
MAX_C_CHARS = 20000
MAX_ASM = 300
MAX_EDGES = 50

args = getScriptArgs()
targets_path, out_path = args[0], args[1]
limit = int(args[2]) if len(args) > 2 else 40
budget = float(args[3]) if len(args) > 3 else 120.0

program = currentProgram
listing = program.getFunctionManager()
monitor = ConsoleTaskMonitor()
chosen = []  # [(function, [reasons], [capa rule names])]
index = {}


def pick(function, reason, rule=None):
    if function is None or function.isExternal() or function.isThunk():
        return
    key = function.getEntryPoint().getOffset()
    if key not in index:
        if len(chosen) >= limit:
            return
        index[key] = len(chosen)
        chosen.append((function, [], []))
    _, reasons, rules = chosen[index[key]]
    if reason not in reasons:
        reasons.append(reason)
    if rule and rule not in rules and len(rules) < 10:
        rules.append(rule)


symbols = program.getSymbolTable()
for address in symbols.getExternalEntryPointIterator():
    function = listing.getFunctionAt(address)
    is_entry = any(s.getName() in ("entry", "_start", "start") for s in symbols.getSymbols(address))
    pick(function, "entry" if is_entry else "export")

try:
    with io.open(targets_path, "r", encoding="utf-8") as fh:
        targets = json.load(fh).get("addresses") or []
except Exception:
    targets = []
space = program.getAddressFactory().getDefaultAddressSpace()
for target in targets:
    try:
        address = space.getAddress(int(str(target.get("addr")), 16))
    except Exception:
        continue
    pick(listing.getFunctionContaining(address), "capa", target.get("rule"))

remaining = sorted((f for f in listing.getFunctions(True) if not f.isThunk() and not f.isExternal()),
                   key=lambda f: -f.getBody().getNumAddresses())
for function in remaining:
    if len(chosen) >= limit:
        break
    pick(function, "largest")

code_listing = program.getListing()


def disassembly(function):
    out = []
    for insn in code_listing.getInstructions(function.getBody(), True):
        if len(out) >= MAX_ASM:
            break
        try:
            raw = " ".join("%02x" % (b & 0xff) for b in insn.getBytes())
        except Exception:
            raw = ""
        out.append({"a": "0x%x" % insn.getAddress().getOffset(), "b": raw, "t": str(insn)[:200]})
    return out


def edges(functions):
    return sorted("0x%x" % f.getEntryPoint().getOffset() for f in functions if not f.isExternal())[:MAX_EDGES]


decompiler = DecompInterface()
decompiler.setOptions(DecompileOptions())
decompiler.openProgram(program)
results, done = [], 0
deadline = time.time() + budget
for function, reasons, rules in chosen:
    entry = {"name": function.getName(), "address": "0x%x" % function.getEntryPoint().getOffset(),
             "size": int(function.getBody().getNumAddresses()), "reasons": reasons, "capa": rules,
             "c": None, "truncated": False, "error": None, "asm": [], "calls": [], "callers": []}
    try:
        entry["asm"] = disassembly(function)
        entry["calls"] = edges(function.getCalledFunctions(monitor))
        entry["callers"] = edges(function.getCallingFunctions(monitor))
    except Exception as exc:  # listing data is extra; the decompile below still runs
        entry["error"] = ("listing: " + str(exc))[:300]
    left = deadline - time.time()
    if left < 1:
        entry["error"] = "skipped: decompile time budget"
        results.append(entry)
        continue
    try:
        res = decompiler.decompileFunction(function, int(min(PER_FUNCTION_S, max(1, left))), monitor)
        if res is not None and res.decompileCompleted():
            code = res.getDecompiledFunction().getC()
            entry["truncated"] = len(code) > MAX_C_CHARS
            entry["c"] = code[:MAX_C_CHARS]
            done += 1
        else:
            entry["error"] = (res.getErrorMessage() if res is not None else "no result") or "timeout"
    except Exception as exc:  # one function failing must not lose the others
        entry["error"] = str(exc)[:300]
    results.append(entry)
decompiler.dispose()

doc = {"version": Application.getApplicationVersion(), "language": str(program.getLanguageID()),
       "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
       "image_base": "0x%x" % program.getImageBase().getOffset(),
       "functions_total": listing.getFunctionCount(), "decompiled": done, "functions": results}
with io.open(out_path, "w", encoding="utf-8") as fh:
    fh.write(unicode(json.dumps(doc, ensure_ascii=True)))  # noqa: F821 (Jython 2.7 builtin)
