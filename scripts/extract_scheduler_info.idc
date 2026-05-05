//
// extract_scheduler_info.idc — IDA 9.x compatible
// =============================================================================
//
// Run via:  IDA  ->  File -> Script File...  -> pick this file
// On the database TESV.exe.unpacked.exe.i64
//
// Output goes to:
//   C:\Users\nro\Documents\ida scripts and extracted\scheduler\
//
// Six output files:
//   1. functions_named.txt      named (non sub_) functions matching keywords
//   2. strings_threading.txt    string literals about threads/jobs/locks
//   3. strings_render.txt       string literals about render/scene/cull
//   4. thread_creation.txt      every CreateThread / SetAffinity / GetSysInfo site
//   5. sync_primitives.txt      every CriticalSection / Wait / Interlocked site
//   6. hot_subs_callgraph.txt   callers + callees of sub_CB7E80, _CA2610, _B06250
//
// Total runtime: ~1-3 minutes depending on database size.
// Uses ONLY modern IDA 9 IDC names (msg, get_name, get_name_ea_simple, etc.).
// Helper functions are defined BEFORE main() to avoid forward-reference issues.
//
// =============================================================================

#include <idc.idc>

// ---------------------------------------------------------------------------
// String / matching helpers
// ---------------------------------------------------------------------------

static HasAnyKeyword(haystack, semicolonList)
{
    auto i = 0;
    auto last = 0;
    auto len = strlen(semicolonList);
    auto needle;

    while (i <= len) {
        if (i == len || substr(semicolonList, i, i + 1) == ";") {
            needle = substr(semicolonList, last, i);
            if (strlen(needle) > 0 && strstr(haystack, needle) != -1) {
                return 1;
            }
            last = i + 1;
        }
        i = i + 1;
    }
    return 0;
}

static SanitizeForLine(s, maxLen)
{
    auto result = "";
    auto i = 0;
    auto len = strlen(s);
    if (len > maxLen) {
        len = maxLen;
    }

    while (i < len) {
        auto c = substr(s, i, i + 1);
        if (c == "\n" || c == "\r" || c == "\t") {
            result = result + " ";
        } else if (c == "'") {
            result = result + "\"";
        } else {
            result = result + c;
        }
        i = i + 1;
    }
    if (strlen(s) > maxLen) {
        result = result + "...";
    }
    return result;
}

static SafeName(ea)
{
    if (ea == BADADDR) {
        return "(BADADDR)";
    }
    auto n = get_name(ea);
    if (strlen(n) == 0) {
        return sprintf("sub_%X", ea);
    }
    return n;
}

// ---------------------------------------------------------------------------
// API call-site dumper (used by thread + sync sections)
// ---------------------------------------------------------------------------

static DumpApiCalls(fp, apiName)
{
    // Try the four name decorations that 32-bit Windows imports use.
    auto importEa = get_name_ea_simple(apiName);
    if (importEa == BADADDR) {
        importEa = get_name_ea_simple("__imp_" + apiName);
    }
    if (importEa == BADADDR) {
        importEa = get_name_ea_simple("_" + apiName);
    }
    if (importEa == BADADDR) {
        importEa = get_name_ea_simple("__imp__" + apiName);
    }

    if (importEa == BADADDR) {
        fprintf(fp, "# %s: not imported by name\n\n", apiName);
        return;
    }

    fprintf(fp, "# %s @ 0x%08X\n", apiName, importEa);

    auto total = 0;

    // Code refs (CALL / JMP) to the import.
    auto cxref = get_first_cref_to(importEa);
    while (cxref != BADADDR && total < 200) {
        auto fn = get_func_attr(cxref, FUNCATTR_START);
        fprintf(fp, "  0x%08X  in_func=0x%08X  %s  ->  %s\n",
            cxref, fn, SafeName(fn), apiName);
        cxref = get_next_cref_to(importEa, cxref);
        total = total + 1;
    }

    // Data refs (IAT slot reads) to the import.
    auto dxref = get_first_dref_to(importEa);
    while (dxref != BADADDR && total < 200) {
        fn = get_func_attr(dxref, FUNCATTR_START);
        fprintf(fp, "  0x%08X  in_func=0x%08X  %s  ->  %s [data ref]\n",
            dxref, fn, SafeName(fn), apiName);
        dxref = get_next_dref_to(importEa, dxref);
        total = total + 1;
    }

    fprintf(fp, "  (%d total references)\n\n", total);
}

// ---------------------------------------------------------------------------
// 1. Named functions matching keywords
// ---------------------------------------------------------------------------

static DumpNamedFunctions(outPath)
{
    auto fp = fopen(outPath, "w");
    if (fp == 0) {
        msg("DumpNamedFunctions: cannot open %s\n", outPath);
        return;
    }

    fprintf(fp, "# Named functions matching scheduler / render keywords\n");
    fprintf(fp, "# (Auto-named sub_XXXXXXXX / loc_XXXXXXXX entries are skipped.)\n");
    fprintf(fp, "# Format: VA  name\n\n");

    auto keywords =
        "Scheduler;Worker;Task;Job;Pool;Thread;Tasklet;"
        "Render;Scene;Frame;Update;Cull;Draw;Traverse;Visit;Accumulate;"
        "BSShader;BSGeometry;BSScene;BSRender;BSTask;BSJob;BSCS;BSLock;"
        "NiNode;NiAVObject;NiCamera;NiCullingProcess;NiVisitor";

    auto count = 0;
    auto ea = get_first_func();
    while (ea != BADADDR) {
        auto name = get_name(ea);
        if (strlen(name) == 0) {
            ea = get_next_func(ea);
            continue;
        }
        if (substr(name, 0, 4) == "sub_") {
            ea = get_next_func(ea);
            continue;
        }
        if (substr(name, 0, 4) == "loc_") {
            ea = get_next_func(ea);
            continue;
        }

        if (HasAnyKeyword(name, keywords)) {
            fprintf(fp, "0x%08X  %s\n", ea, name);
            count = count + 1;
        }
        ea = get_next_func(ea);
    }

    fclose(fp);
    msg("DumpNamedFunctions: %d entries written\n", count);
}

// ---------------------------------------------------------------------------
// 2 & 3. String literals matching keywords (segment walk)
// ---------------------------------------------------------------------------

static DumpStringsFromSegments(outPath, label, keywordList)
{
    auto fp = fopen(outPath, "w");
    if (fp == 0) {
        msg("DumpStringsFromSegments[%s]: cannot open %s\n", label, outPath);
        return;
    }

    fprintf(fp, "# String literals matching %s keywords\n", label);
    fprintf(fp, "# Format: stringVA  '<text>'  caller=0x<va>  <callerName>\n\n");

    auto count = 0;
    auto seg = get_first_seg();
    while (seg != BADADDR) {
        auto segName = get_segm_name(seg);
        auto end = get_segm_end(seg);

        // Strings live in .rdata / .data / .rsrc. Skip pure code / reloc.
        auto skipSeg = 0;
        if (segName == ".text") skipSeg = 1;
        if (segName == ".reloc") skipSeg = 1;
        if (segName == ".bind") skipSeg = 1;

        if (skipSeg == 0) {
            auto cur = seg;
            while (cur != BADADDR && cur < end) {
                auto sType = get_str_type(cur);
                if (sType != -1 && sType != BADADDR) {
                    auto str = get_strlit_contents(cur, -1, sType);
                    if (strlen(str) >= 4) {
                        if (HasAnyKeyword(str, keywordList)) {
                            // Find the first thing that references this string.
                            auto xref = get_first_dref_to(cur);
                            auto callerVA = 0;
                            auto callerName = "(no xref)";
                            if (xref != BADADDR) {
                                auto fnStart = get_func_attr(xref, FUNCATTR_START);
                                if (fnStart != BADADDR) {
                                    callerVA = fnStart;
                                    callerName = SafeName(fnStart);
                                }
                            }
                            auto clean = SanitizeForLine(str, 200);
                            fprintf(fp, "0x%08X  '%s'  caller=0x%08X  %s\n",
                                cur, clean, callerVA, callerName);
                            count = count + 1;
                        }
                    }
                }
                auto nx = next_head(cur, end);
                if (nx == BADADDR || nx <= cur) {
                    // Move to next byte if next_head fails
                    cur = cur + 1;
                } else {
                    cur = nx;
                }
            }
        }

        seg = get_next_seg(seg);
    }

    fclose(fp);
    msg("DumpStringsFromSegments[%s]: %d entries written\n", label, count);
}

// ---------------------------------------------------------------------------
// 4. Thread creation API call sites
// ---------------------------------------------------------------------------

static DumpThreadCreationSites(outPath)
{
    auto fp = fopen(outPath, "w");
    if (fp == 0) {
        msg("DumpThreadCreationSites: cannot open %s\n", outPath);
        return;
    }

    fprintf(fp, "# Call sites that create threads or query/configure CPU/threads\n");
    fprintf(fp, "# Format: callSiteVA  in_func=0x<va>  <funcName>  ->  apiName\n\n");

    DumpApiCalls(fp, "CreateThread");
    DumpApiCalls(fp, "_beginthreadex");
    DumpApiCalls(fp, "_beginthread");
    DumpApiCalls(fp, "CreateRemoteThread");
    DumpApiCalls(fp, "QueueUserWorkItem");
    DumpApiCalls(fp, "TrySubmitThreadpoolCallback");
    DumpApiCalls(fp, "CreateThreadpoolWork");
    DumpApiCalls(fp, "SubmitThreadpoolWork");
    DumpApiCalls(fp, "SetThreadAffinityMask");
    DumpApiCalls(fp, "SetProcessAffinityMask");
    DumpApiCalls(fp, "SetThreadIdealProcessor");
    DumpApiCalls(fp, "SetThreadPriority");
    DumpApiCalls(fp, "SetPriorityClass");
    DumpApiCalls(fp, "GetSystemInfo");
    DumpApiCalls(fp, "GetNativeSystemInfo");
    DumpApiCalls(fp, "GetLogicalProcessorInformation");
    DumpApiCalls(fp, "GetActiveProcessorCount");
    DumpApiCalls(fp, "GetMaximumProcessorCount");

    fclose(fp);
    msg("DumpThreadCreationSites: done\n");
}

// ---------------------------------------------------------------------------
// 5. Synchronization primitive call sites
// ---------------------------------------------------------------------------

static DumpSyncSites(outPath)
{
    auto fp = fopen(outPath, "w");
    if (fp == 0) {
        msg("DumpSyncSites: cannot open %s\n", outPath);
        return;
    }

    fprintf(fp, "# Synchronization primitive usage sites\n");
    fprintf(fp, "# Format: callSiteVA  in_func=0x<va>  <funcName>  ->  apiName\n\n");

    DumpApiCalls(fp, "EnterCriticalSection");
    DumpApiCalls(fp, "LeaveCriticalSection");
    DumpApiCalls(fp, "TryEnterCriticalSection");
    DumpApiCalls(fp, "InitializeCriticalSection");
    DumpApiCalls(fp, "InitializeCriticalSectionAndSpinCount");
    DumpApiCalls(fp, "DeleteCriticalSection");
    DumpApiCalls(fp, "WaitForSingleObject");
    DumpApiCalls(fp, "WaitForSingleObjectEx");
    DumpApiCalls(fp, "WaitForMultipleObjects");
    DumpApiCalls(fp, "WaitForMultipleObjectsEx");
    DumpApiCalls(fp, "SetEvent");
    DumpApiCalls(fp, "ResetEvent");
    DumpApiCalls(fp, "CreateEventA");
    DumpApiCalls(fp, "CreateEventW");
    DumpApiCalls(fp, "CreateEventExA");
    DumpApiCalls(fp, "CreateEventExW");
    DumpApiCalls(fp, "CreateSemaphoreA");
    DumpApiCalls(fp, "CreateSemaphoreW");
    DumpApiCalls(fp, "ReleaseSemaphore");
    DumpApiCalls(fp, "CreateMutexA");
    DumpApiCalls(fp, "CreateMutexW");
    DumpApiCalls(fp, "InterlockedIncrement");
    DumpApiCalls(fp, "InterlockedDecrement");
    DumpApiCalls(fp, "InterlockedExchange");
    DumpApiCalls(fp, "InterlockedCompareExchange");
    DumpApiCalls(fp, "InterlockedExchangeAdd");
    DumpApiCalls(fp, "AcquireSRWLockExclusive");
    DumpApiCalls(fp, "ReleaseSRWLockExclusive");
    DumpApiCalls(fp, "AcquireSRWLockShared");
    DumpApiCalls(fp, "ReleaseSRWLockShared");

    fclose(fp);
    msg("DumpSyncSites: done\n");
}

// ---------------------------------------------------------------------------
// 6. Hot sub call graphs (callers + callees)
// ---------------------------------------------------------------------------

static DumpFunctionGraph(fp, label, ea)
{
    fprintf(fp, "==== %s @ 0x%08X ====\n", label, ea);

    fprintf(fp, "  CALLERS (functions that CALL this):\n");
    auto xref = get_first_cref_to(ea);
    auto callerCount = 0;
    while (xref != BADADDR && callerCount < 200) {
        auto fn = get_func_attr(xref, FUNCATTR_START);
        fprintf(fp, "    callsite=0x%08X  in_func=0x%08X  %s\n",
            xref, fn, SafeName(fn));
        xref = get_next_cref_to(ea, xref);
        callerCount = callerCount + 1;
    }
    if (callerCount == 0) {
        fprintf(fp, "    (no direct callers — only reached via indirect calls?)\n");
    }
    fprintf(fp, "  Total callers: %d\n", callerCount);

    fprintf(fp, "  CALLEES (CALL instructions in first ~1024 bytes):\n");
    auto endAddr = ea + 1024;
    auto cur = ea;
    auto calleeCount = 0;
    while (cur != BADADDR && cur < endAddr) {
        auto mnem = print_insn_mnem(cur);
        if (mnem == "call") {
            auto target = GetOperandValue(cur, 0);
            if (target != BADADDR && target != 0) {
                fprintf(fp, "    +0x%03X  call 0x%08X  %s\n",
                    cur - ea, target, SafeName(target));
                calleeCount = calleeCount + 1;
            }
        }
        auto nx = next_head(cur, BADADDR);
        if (nx == BADADDR || nx <= cur) {
            break;
        }
        cur = nx;
    }
    fprintf(fp, "  Total callees in window: %d\n\n", calleeCount);
}

static DumpHotSubGraphs(outPath)
{
    auto fp = fopen(outPath, "w");
    if (fp == 0) {
        msg("DumpHotSubGraphs: cannot open %s\n", outPath);
        return;
    }

    fprintf(fp, "# Call graph for the 3 hot NiDX9 subs.\n");
    fprintf(fp, "# Each section lists CALLERS and a window of CALLEES.\n\n");

    DumpFunctionGraph(fp, "sub_CB7E80", 0x00CB7E80);
    DumpFunctionGraph(fp, "sub_CA2610", 0x00CA2610);
    DumpFunctionGraph(fp, "sub_B06250", 0x00B06250);

    fclose(fp);
    msg("DumpHotSubGraphs: done\n");
}

// ---------------------------------------------------------------------------
// main — defined LAST so all helpers are declared before use
// ---------------------------------------------------------------------------

static main()
{
    auto outDir = "C:\\Users\\nro\\Documents\\ida scripts and extracted\\scheduler\\";

    msg("=== Skyrim scheduler/render extraction ===\n");
    msg("Output dir: %s\n", outDir);
    msg("(directory must exist; create with: mkdir \"...scheduler\")\n\n");

    // Check if output directory exists by trying to create a test file
    auto testPath = outDir + "test.tmp";
    auto testFp = fopen(testPath, "w");
    if (testFp == 0) {
        msg("ERROR: Cannot write to output directory: %s\n", outDir);
        msg("Please create the directory and ensure write permissions.\n");
        return;
    }
    fclose(testFp);
    // Clean up test file
    // Note: IDC doesn't have delete file function, so test file remains

    DumpNamedFunctions(outDir + "functions_named.txt");

    DumpStringsFromSegments(outDir + "strings_threading.txt", "threading",
        "Scheduler;Worker;Task;Job;BSTask;BSJob;BSThread;Pool;ThreadPool;"
        "TaskletGroup;Tasklet;ParallelFor;Async;Atomic;Mutex;Semaphore;"
        "Critical;Lock;BSCS;BSLock;BSReadWriteLock;BSReadLock;BSWriteLock;"
        "Spinlock;LockGuard;ConcurrentQueue");

    DumpStringsFromSegments(outDir + "strings_render.txt", "rendering",
        "Render;Scene;Frame;Update;Cull;Draw;Visible;Visit;Traverse;"
        "Accumulate;Geometry;NiNode;NiAVObject;BSShader;BSGeometry;"
        "BSMultiBound;Shadow;Reflection;Water;Pass;Bucket;Sort;Batch;Submit");

    DumpThreadCreationSites(outDir + "thread_creation.txt");
    DumpSyncSites(outDir + "sync_primitives.txt");
    DumpHotSubGraphs(outDir + "hot_subs_callgraph.txt");

    msg("\n=== Done. ===\n");
    msg("Inspect files in: %s\n", outDir);
}
