#
# extract_scheduler_info.py — IDAPython version
# =============================================================================
#
# Run via:  IDA  ->  File -> Script File...  -> pick this file
# Or:        Alt+F7  ->  pick this file
# On the database TESV.exe.unpacked.exe.i64
#
# Output goes to:
#   C:\Users\nro\Documents\ida scripts and extracted\scheduler\
#
# Six output files:
#   1. functions_named.txt      named functions matching scheduler/render keywords
#   2. strings_threading.txt    string literals about threads/jobs/locks
#   3. strings_render.txt       string literals about render/scene/cull
#   4. thread_creation.txt      every CreateThread / SetAffinity / etc. site
#   5. sync_primitives.txt      every CriticalSection / Wait / Interlocked site
#   6. hot_subs_callgraph.txt   callers + callees of sub_CB7E80, _CA2610, _B06250
#
# IDAPython works on every IDA from 7.0 through 9.x without API breakage.
# =============================================================================

import os
import idaapi
import idautils
import idc

OUT_DIR = r"C:\Users\nro\Documents\ida scripts and extracted\scheduler"

THREADING_KEYWORDS = [
    "Scheduler", "Worker", "Task", "Job", "BSTask", "BSJob", "BSThread",
    "Pool", "ThreadPool", "TaskletGroup", "Tasklet", "ParallelFor", "Async",
    "Atomic", "Mutex", "Semaphore", "Critical", "Lock", "BSCS", "BSLock",
    "BSReadWriteLock", "BSReadLock", "BSWriteLock", "Spinlock", "LockGuard",
    "ConcurrentQueue", "JobList", "JobScheduler",
]

RENDER_KEYWORDS = [
    "Render", "Scene", "Frame", "Update", "Cull", "Draw", "Visible", "Visit",
    "Traverse", "Accumulate", "Geometry", "NiNode", "NiAVObject", "BSShader",
    "BSGeometry", "BSMultiBound", "Shadow", "Reflection", "Water", "Pass",
    "Bucket", "Sort", "Batch", "Submit", "BSRenderPass", "BSGraphics",
]

NAMED_FUNCTION_KEYWORDS = THREADING_KEYWORDS + [
    "BSScene", "BSRender", "NiCamera", "NiCullingProcess", "NiVisitor",
]

THREAD_APIS = [
    "CreateThread", "_beginthreadex", "_beginthread", "CreateRemoteThread",
    "QueueUserWorkItem", "TrySubmitThreadpoolCallback", "CreateThreadpoolWork",
    "SubmitThreadpoolWork", "SetThreadAffinityMask", "SetProcessAffinityMask",
    "SetThreadIdealProcessor", "SetThreadPriority", "SetPriorityClass",
    "GetSystemInfo", "GetNativeSystemInfo", "GetLogicalProcessorInformation",
    "GetActiveProcessorCount", "GetMaximumProcessorCount",
]

SYNC_APIS = [
    "EnterCriticalSection", "LeaveCriticalSection", "TryEnterCriticalSection",
    "InitializeCriticalSection", "InitializeCriticalSectionAndSpinCount",
    "DeleteCriticalSection",
    "WaitForSingleObject", "WaitForSingleObjectEx",
    "WaitForMultipleObjects", "WaitForMultipleObjectsEx",
    "SetEvent", "ResetEvent",
    "CreateEventA", "CreateEventW", "CreateEventExA", "CreateEventExW",
    "CreateSemaphoreA", "CreateSemaphoreW", "ReleaseSemaphore",
    "CreateMutexA", "CreateMutexW",
    "InterlockedIncrement", "InterlockedDecrement",
    "InterlockedExchange", "InterlockedCompareExchange",
    "InterlockedExchangeAdd",
    "AcquireSRWLockExclusive", "ReleaseSRWLockExclusive",
    "AcquireSRWLockShared", "ReleaseSRWLockShared",
]

HOT_SUBS = [
    ("sub_CB7E80", 0x00CB7E80),
    ("sub_CA2610", 0x00CA2610),
    ("sub_B06250", 0x00B06250),
]


def safe_name(ea):
    if ea == idaapi.BADADDR or ea is None:
        return "(BADADDR)"
    n = idc.get_name(ea)
    if not n:
        return "sub_%X" % ea
    return n


def has_any_keyword(text, keywords):
    low = text.lower()
    for k in keywords:
        if k.lower() in low:
            return True
    return False


def find_import_ea(api_name):
    for candidate in (api_name, "__imp_" + api_name, "_" + api_name, "__imp__" + api_name):
        ea = idc.get_name_ea_simple(candidate)
        if ea != idaapi.BADADDR:
            return ea
    return idaapi.BADADDR


def dump_api_calls(f, api_name):
    import_ea = find_import_ea(api_name)
    if import_ea == idaapi.BADADDR:
        f.write("# %s: not imported by name\n\n" % api_name)
        return

    f.write("# %s @ 0x%08X\n" % (api_name, import_ea))
    total = 0
    for xref in idautils.XrefsTo(import_ea, 0):
        fn = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)
        kind = "code" if xref.iscode else "data"
        f.write("  0x%08X  in_func=0x%08X  %s  ->  %s [%s]\n"
                % (xref.frm, fn if fn != idaapi.BADADDR else 0,
                   safe_name(fn), api_name, kind))
        total += 1
        if total >= 300:
            f.write("  ... (truncated at 300)\n")
            break
    f.write("  (%d references)\n\n" % total)


def dump_named_functions(out_path):
    with open(out_path, "w") as f:
        f.write("# Named functions matching scheduler / render keywords\n")
        f.write("# (Auto-named sub_*/loc_* skipped.)\n")
        f.write("# Format: VA  name\n\n")
        n = 0
        for ea in idautils.Functions():
            name = idc.get_name(ea) or ""
            if not name:
                continue
            if name.startswith("sub_") or name.startswith("loc_"):
                continue
            if has_any_keyword(name, NAMED_FUNCTION_KEYWORDS):
                f.write("0x%08X  %s\n" % (ea, name))
                n += 1
        print("DumpNamedFunctions: %d entries" % n)


def dump_strings(out_path, label, keywords):
    with open(out_path, "w") as f:
        f.write("# String literals matching %s keywords\n" % label)
        f.write("# Format: stringVA  '<text>'  caller=0x<va>  <callerName>\n\n")
        n = 0
        for s in idautils.Strings():
            try:
                text = str(s)
            except Exception:
                continue
            if len(text) < 4:
                continue
            if not has_any_keyword(text, keywords):
                continue

            xref = idc.get_first_dref_to(s.ea)
            caller_va = 0
            caller_name = "(no xref)"
            if xref != idaapi.BADADDR:
                fn = idc.get_func_attr(xref, idc.FUNCATTR_START)
                if fn != idaapi.BADADDR:
                    caller_va = fn
                    caller_name = safe_name(fn)

            clean = text.replace("\n", " ").replace("\r", " ").replace("\t", " ").replace("'", '"')
            if len(clean) > 200:
                clean = clean[:200] + "..."
            f.write("0x%08X  '%s'  caller=0x%08X  %s\n"
                    % (s.ea, clean, caller_va, caller_name))
            n += 1
        print("DumpStrings[%s]: %d entries" % (label, n))


def dump_thread_creation(out_path):
    with open(out_path, "w") as f:
        f.write("# Thread creation / configuration call sites\n\n")
        for api in THREAD_APIS:
            dump_api_calls(f, api)
    print("DumpThreadCreation: done")


def dump_sync_sites(out_path):
    with open(out_path, "w") as f:
        f.write("# Synchronization primitive call sites\n\n")
        for api in SYNC_APIS:
            dump_api_calls(f, api)
    print("DumpSyncSites: done")


def dump_function_graph(f, label, ea):
    f.write("==== %s @ 0x%08X ====\n" % (label, ea))

    f.write("  CALLERS (functions that CALL this):\n")
    callers = 0
    for xref in idautils.XrefsTo(ea, 0):
        if not xref.iscode:
            continue
        fn = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)
        f.write("    callsite=0x%08X  in_func=0x%08X  %s\n"
                % (xref.frm, fn if fn != idaapi.BADADDR else 0, safe_name(fn)))
        callers += 1
        if callers >= 300:
            f.write("    ... (truncated)\n")
            break
    if callers == 0:
        f.write("    (no direct callers — only via indirect calls?)\n")
    f.write("  Total callers: %d\n" % callers)

    f.write("  CALLEES (CALL instructions in first 1024 bytes):\n")
    callees = 0
    end = ea + 1024
    cur = ea
    while cur < end and cur != idaapi.BADADDR:
        mnem = idc.print_insn_mnem(cur)
        if mnem == "call":
            target = idc.get_operand_value(cur, 0)
            if target and target != idaapi.BADADDR:
                f.write("    +0x%03X  call 0x%08X  %s\n"
                        % (cur - ea, target, safe_name(target)))
                callees += 1
        nxt = idc.next_head(cur, idaapi.BADADDR)
        if nxt == idaapi.BADADDR or nxt <= cur:
            break
        cur = nxt
    f.write("  Total callees in window: %d\n\n" % callees)


def dump_hot_sub_graphs(out_path):
    with open(out_path, "w") as f:
        f.write("# Call graph for the 3 hot NiDX9 subs.\n\n")
        for label, ea in HOT_SUBS:
            dump_function_graph(f, label, ea)
    print("DumpHotSubGraphs: done")


def main():
    if not os.path.isdir(OUT_DIR):
        os.makedirs(OUT_DIR)
    print("=== Skyrim scheduler/render extraction ===")
    print("Output dir: " + OUT_DIR)

    dump_named_functions(os.path.join(OUT_DIR, "functions_named.txt"))
    dump_strings(os.path.join(OUT_DIR, "strings_threading.txt"),
                 "threading", THREADING_KEYWORDS)
    dump_strings(os.path.join(OUT_DIR, "strings_render.txt"),
                 "rendering", RENDER_KEYWORDS)
    dump_thread_creation(os.path.join(OUT_DIR, "thread_creation.txt"))
    dump_sync_sites(os.path.join(OUT_DIR, "sync_primitives.txt"))
    dump_hot_sub_graphs(os.path.join(OUT_DIR, "hot_subs_callgraph.txt"))

    print("=== Done. ===")


main()
