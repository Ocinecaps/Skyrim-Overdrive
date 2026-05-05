# Skyrim Rendering Overdrive

A research project to feed Skyrim Legendary Edition's idle CPU cores with real game work.

This is **not** a polished mod — it's an instrumented testbed that captures Skyrim's own 6-worker thread pool, exposes a `RunParallel` / `ParallelFor` API on top of it, and explores which engine work can be safely moved off the render thread. It coexists with **ENB** and **SKSE** without proxying `d3d9.dll` and without hooking D3D9 calls directly.

The project is intentionally documented so that the wrong turns are visible alongside the right ones — every approach we ran, including the ones that turned into dead ends, is in `git log` and the memory notes. **Drawcall-side parallelization (hooking `sub_CB7E80` / `sub_CA2610` directly) is one of those dead ends.** The pool foundation works; what remains is finding work that's *naturally* parallel-safe and feeding it to the workers. That's the next phase.

---

## What works today

- **PE patcher** rewrites a clean unwrapped `TESV.exe` to add a `.injsec` section + TLS callback that `LoadLibraryA`'s `SkyrimRenderOverdrive.dll` at process start. Coexists with ENB's `d3d9.dll` proxy and SKSE's `skse_loader.exe`.
- **Pool capture.** A MinHook detour on `sub_A5B050` (Skyrim's pool factory) snapshots the singleton at construction. Memory-scan fallback if the hook misses.
- **`RunParallel(N, fn, ud)` / `ParallelFor(start, end, body, ud)`** API in [`RenderPoolPatch.h`](SkyrimRenderDLL/RenderPoolPatch.h) — submits OdTask structures into Skyrim's pool's queue, signals the master semaphore, blocks on the per-task-group completion semaphore. Verified working: a self-test of 6 no-op tasks completes in ~1ms; a scaling test shows **4.85× speedup** for 6 CPU-bound tasks vs serial.
- **D3DX SSE replacements** for 7 hot D3DX9_43 functions (MultiplyTranspose, Multiply, Transpose, Vec3 transforms, Normalize, PlaneNormalize). Pure CPU win, no concurrency concern. Active in both DLL builds.
- **Slim DLL build (`SkyrimMultiCoreOverdrive.dll`)** — pool foundation + D3DX replacements + caller-discovery instrumentation. No D3D9/Vulkan/SDL/profiler weight. ~40 KB. Used as the clean-FPS-comparison baseline.
- **Full DLL build (`SkyrimRenderOverdrive.dll`)** — adds the experimental subsystems: D3D9 vtable mirror, NiDX9 hot-sub thunks, Vulkan command queue scaffolding, DXBC analyzer, EIP/Sleep/Wait profilers, crash debugger with IDA-extracted symbol table.

## What's structurally blocked

- **Hooking `sub_CB7E80` / `sub_CA2610` to run them on workers.** Sync-offload (one-call-at-a-time on a worker) ran clean for 45s in normal play but **deadlocks on manual save**: caller holds a CS the worker also needs. Burst-batch (true concurrent dispatch via `ParallelFor`) **crashed on the first drain**: the function isn't safe to run concurrently with itself — vanilla Skyrim never has two of these in flight at once, and there's lock-free shared scratch state somewhere inside that races. Both modules ([`SyncOffloadProof.cpp`](SkyrimRenderDLL/SyncOffloadProof.cpp), [`BurstBatch.cpp`](SkyrimRenderDLL/BurstBatch.cpp)) are kept on disk for reference but no longer compile into either DLL.
- **D3D9 deferred-dispatch pipeline** (move `Set*` and draw calls off the render thread, drain on Present) — works in isolation but corrupts ENB's post-pass because ENB reads device state directly from the real D3D9 device, bypassing our state shadows. Disabled via `kEnablePipeline=false` in [`BootstrapThread.cpp`](SkyrimRenderDLL/BootstrapThread.cpp).

## What's next

**Idle-worker initiative.** The Wait profiler shows the pool's workers are idle on the master semaphore 33–75% of the time. Find CPU work that's *already* organized as independent per-entity loops (AI updates per NPC, particle physics per emitter, pathfinding queries, distant LOD selection) and feed those to `ParallelFor`. These are easier targets than scenegraph code because the engine already isolates each unit; shared mutable state is rarer.

---

## Architecture

Three layers, mirrors the user's [Dawn of War Overdrive](../Dawn-of-war-overdrive-performance-master/) shape:

| Layer | Component | Code |
|---|---|---|
| 1. Offline PE patcher | `SkyrimPatcher.exe` | [`SkyrimPatcher/`](SkyrimPatcher/) |
| 2. In-process injected DLL (full) | `SkyrimRenderOverdrive.dll` | [`SkyrimRenderDLL/`](SkyrimRenderDLL/) |
| 2'. In-process injected DLL (slim) | `SkyrimMultiCoreOverdrive.dll` | [`SkyrimMultiCoreDLL/`](SkyrimMultiCoreDLL/) (links source from `SkyrimRenderDLL/`) |
| 3. Runtime patches | foundation modules + experiments | inside `SkyrimRenderDLL/` |

The slim DLL exists so we have a low-overhead binary for FPS measurements: it strips D3D9 hooks, Vulkan, SDL, and all profilers, keeping only the pool foundation + D3DX replacements.

### Boot chain

```
TESV.exe (patched) →
  TLS callback in .injsec →
    LoadLibraryA("SkyrimRenderOverdrive.dll") →
      DllMain DLL_PROCESS_ATTACH:
        InitLogger
        renderpool::Install()      ← MinHook on sub_A5B050 (pool ctor)
        d3dx::Install()            ← Hook + replace 7 D3DX9_43 functions with SSE
        CreateThread(BootstrapThreadProc)
        return                     ← release loader lock
      BootstrapThread (off the loader lock):
        Sleep(50)                  ← let process startup settle
        crashdbg::Install
        profiler::Install / sleepprof / waitprof / vkq / resmirror::Install
        loop {
          MaybeLogStats from each subsystem
          Sleep(250)
        }
```

The slim DLL's `DllMain` is thinner: just `renderpool::Install()` + `d3dx::Install()`, then a worker that pumps `MaybeLogStats` only.

### The pool ABI (decoded from disasm)

`sub_A5B050` constructs a pool struct at a known singleton address. Key offsets (verified from IDA disasm of `sub_A5AE90`, the worker dispatch loop):

```
Pool struct:
  +0x000  vtable (0x0110DC44 → 0x0110DD1C after init)
  +0x008  HANDLE workerSem
  +0x018  uint32_t workerCount = 6
  +0x050  uint8_t shutdownFlag
  +0x054  CRITICAL_SECTION queueCs
  +0x06C  OdTask* queue[64]      (64 buckets, intra-bucket linked list via task->[+0x14])
  +0x26C  HANDLE masterSem       (released to wake workers on enqueue)

OdTask:
  +0x00  void**     vtable[4]   ([0]=dtor, [1]=Validate, [2]=Run, [3]=Finish)
  +0x04  uint8_t    requeueFlag
  +0x08  OdTaskGroup* group
  +0x0C  uint8_t    skipValidate
  +0x14  OdTask*    next
```

The worker loop: `WaitForSingleObject(masterSem)`, `EnterCriticalSection(queueCs)`, scan buckets for a non-null head, dequeue one, leave CS, optionally call `vtable[1]` (Validate), call `vtable[2]` (Run), call `vtable[3]` (Finish), increment `group->counter`, if `counter == target` release `group->sem`. Our `RunParallel` builds N OdTasks all pointing at one OdTaskGroup with `target=N`, splices them into bucket 0, releases the master semaphore N times, blocks on `group->sem`.

See [`RenderPoolPatch.cpp`](SkyrimRenderDLL/RenderPoolPatch.cpp) for the full implementation. ABI comments at the top of the file mirror the disasm exactly.

---

## Codebase tour

### Foundation (always active)

- [`RenderPoolPatch.{h,cpp}`](SkyrimRenderDLL/) — pool capture, `RunParallel`, `ParallelFor`, self-test, scaling test
- [`D3DXReplace.{h,cpp}`](SkyrimRenderDLL/) — SSE replacements for 7 D3DX9_43 functions, plus per-function caller-retaddr histograms (Phase 3 target discovery)
- [`DebugLogger.{h,cpp}`](SkyrimRenderDLL/) — append-only log to `<SkyrimDir>\skyrim_overdrive.log` (or `\skyrim_multicore.log` for the slim DLL), mirrored to `OutputDebugStringA`
- [`MinHook/`](SkyrimRenderDLL/MinHook/) — vendored MinHook 1.3.4

### Experiments (kept on disk, not currently compiled)

- [`SyncOffloadProof.{h,cpp}`](SkyrimRenderDLL/) — proves a worker CAN run `sub_CB7E80`. Deadlocks on save.
- [`BurstBatch.{h,cpp}`](SkyrimRenderDLL/) — proves a worker pool CANNOT run `sub_CB7E80` concurrently with itself. Crashes on first drain.
- [`ParentLoopProbe.{h,cpp}`](SkyrimRenderDLL/) — caller-retaddr histograms on `sub_CB7E80` / `sub_CA2610` / `sub_CB1480` / `sub_CB1FF0`. Confirmed both hot subs are 100% dispatched from one site at `0x00CB1BF0` inside `sub_CB1B90` (vtable[23]).

### Full-DLL-only subsystems (compile into `SkyrimRenderOverdrive.dll`, not the slim build)

- [`D3D9Hook.{h,cpp}`](SkyrimRenderDLL/) — `Direct3DCreate9` → `IDirect3D9::CreateDevice` chain hook
- [`D3D9DeviceVtable.{h,cpp}`](SkyrimRenderDLL/) — vtable detours for `IDirect3DDevice9` (119 methods), forms the basis of mirror-mode and pipeline experiments
- [`D3D9Mirror.{h,cpp}`](SkyrimRenderDLL/) — typed wrappers + dedup cache for redundant state changes
- [`D3D9PipelineDispatcher.{h,cpp}`](SkyrimRenderDLL/) — deferred D3D9 dispatch (shelved due to ENB incompat)
- [`NiDX9Hooks.{h,cpp}`](SkyrimRenderDLL/) — record-and-replay thunks on hot NiDX9 functions
- [`VulkanWindow.{h,cpp}`](SkyrimRenderDLL/), [`VulkanCommandQueue.{h,cpp}`](SkyrimRenderDLL/) — Vulkan side panel + draining infrastructure (currently unused; instrumentation-only mode)
- [`DxbcParser.{h,cpp}`](SkyrimRenderDLL/), [`DxbcToSpirv.{h,cpp}`](SkyrimRenderDLL/), [`SpirvBuilder.{h,cpp}`](SkyrimRenderDLL/) — DXBC → SPIR-V translator (one-shot histogram analyzer + scaffolding for the eventual replacement renderer)
- [`ResourceMirror.{h,cpp}`](SkyrimRenderDLL/) — captures shader bytecode + buffer metadata at every D3D9 `CreateXxx`
- [`ScenegraphProfiler.{h,cpp}`](SkyrimRenderDLL/) — per-frame scenegraph traversal stats
- [`SleepProfiler.{h,cpp}`](SkyrimRenderDLL/), [`WaitProfiler.{h,cpp}`](SkyrimRenderDLL/), [`D3D9ReadProfiler.{h,cpp}`](SkyrimRenderDLL/) — kernel32 hook profilers
- [`CrashDebugger.{h,cpp}`](SkyrimRenderDLL/) — vectored exception handler that walks the stack symbolically (Windows DLLs via dbghelp PDBs, TESV.exe via IDA-extracted symbol table)

---

## Build & deploy

### Prerequisites

- Visual Studio 2022 with the **Desktop development with C++** workload (v143 toolset, Win32 build tools).
- LunarG Vulkan SDK (any 1.x) installed at the path referenced in [`SkyrimRenderDLL/SkyrimRenderDLL.vcxproj`](SkyrimRenderDLL/SkyrimRenderDLL.vcxproj). Headers only — we do **not** link `vulkan-1.lib` (LunarG removed `Lib32` in 1.4.304.0). Vulkan is loaded at runtime via [volk](https://github.com/zeux/volk) (vendored as [`SkyrimRenderDLL/volk.{c,h}`](SkyrimRenderDLL/)).
- SDL3 dev zip (used only by the full DLL's `VulkanWindow` — slim DLL doesn't need it).
- Skyrim Legendary Edition with a **non-SteamStub-wrapped** `TESV.exe`. If yours is wrapped, unpack with Steamless once to produce `TESV.exe.unpacked.exe` next to it.

The 32-bit `vulkan-1.dll` at `C:\Windows\SysWOW64\vulkan-1.dll` ships with every modern GPU driver — almost certainly already present.

### Build

Open `SkyrimOverdrive.sln` in VS2022, select `Release | Win32`, build the solution. Outputs land in `Release\Win32\` and per-project `Release\` folders:

- `SkyrimPatcher.exe` — offline PE patcher utility
- `SkyrimRenderOverdrive.dll` — full injected DLL (all instrumentation)
- `SkyrimMultiCoreOverdrive.dll` — slim injected DLL (foundation only, ~40 KB)

### Deploy

1. Copy `SkyrimRenderOverdrive.dll` (or rename the slim DLL to that name) into the Skyrim install folder.
2. Run `SkyrimPatcher.exe` once. It backs up `TESV.exe` to `TESV.exe.original`, reads `TESV.exe.unpacked.exe` (your manually-Steamless'd copy), adds the `.injsec` section + TLS callback, zeroes the PE checksum, writes the patched binary back as `TESV.exe`.
3. Launch via `skse_loader.exe` as usual.
4. Logs go to `<SkyrimDir>\skyrim_overdrive.log` (full DLL) or `\skyrim_multicore.log` (slim DLL).

To revert: copy `TESV.exe.original` back to `TESV.exe`.

### Reboot fragility

The TLS-callback stub uses an absolute VA for `kernel32!LoadLibraryA`, which moves across OS reboots due to ASLR session bias. Re-run the patcher after every reboot. A PEB-walking stub would fix this; not implemented yet.

---

## The journey

A short log of the major experiments and what they revealed. Mostly for future-self when the rationale for a structural choice is forgotten.

### Phase 1 — Bootstrap (V1)

PE patcher + TLS callback + DLL load + SDL3+Vulkan window. Proved the loader chain works alongside ENB and SKSE. See `README_V1_BOOTSTRAP.md`.

### Phase 2a — D3D9 Mirror

Vtable-detour the device, record drawcalls + state, build a mirror that elides redundant `Set*` calls. Worked: ~17% redundant-call elimination measured. Net FPS impact: tiny — Skyrim's renderer already deduplicates well. The mirror remains useful as instrumentation but isn't a perf win on its own.

### Phase 2b — D3D9 Pipeline (shelved)

Move `Set*`/draw recording to a queue, drain on Present from a dedicated thread. Plan was to give the render thread headroom by deferring D3D9 work. Result: visual glitches with ENB — ENB's d3d9 proxy reads device state during its post-pass and saw stale state because our pipeline had deferred Skyrim's `Set*` calls. Cross-thread state-shadow infrastructure to fix it would essentially mean writing our own d3d9 wrapper. Out of scope. `kEnablePipeline=false` permanently.

### Phase 3 — Multi-core via the Skyrim pool

Wait profiler showed Skyrim's own 6-worker pool (built by `sub_A5B050`) had workers idle on the master semaphore 33–75% of the time. Hypothesis: feed CPU prep work to the pool from outside, get parallel speedup without fighting the D3D9 chain.

**M0 (foundation):** captured the pool, built `RunParallel` / `ParallelFor` on top of its task ABI. Self-test passes; 4.85× scaling on synthetic load.

**M1 (sync-offload of `sub_CB7E80`):** hook the dominant hot per-object function, route 1-in-N calls onto a single pool worker, sync-wait. 1-in-1000 ran clean for 45 seconds, 6 distinct worker TIDs exercised, 0 lost dispatches. **But 1-in-100 hung the game on manual save** — a save-thread (or render thread under save CS) called the hook, sync-waited on a worker that needed the same CS. Classic sync-offload deadlock.

**M2 (burst-batch of `sub_CB7E80` + `sub_CA2610`):** render-thread-only queueing with K=32, fan out across all 6 workers via `ParallelFor`. Designed to be deadlock-proof (other threads passthrough). **Crashed immediately on the first drain.** sub_CB7E80 isn't safe to run concurrently with itself — vanilla code never has two in flight, and there's lock-free shared state inside that races.

**Conclusion:** drawcall-side parallelization of these specific functions is structurally blocked. To make them parallel-safe would require a full audit of every shared-state access inside the function and everything it transitively calls. Multi-week deep RE for unknown payoff. Pivot.

### Phase 3 (next) — Idle-worker initiative

Stop hooking the scenegraph code. Identify CPU work in Skyrim that's *naturally* organized as per-entity independent loops (AI, particles, pathfinding, distant LOD selection, animation sampling) and feed THAT to `RunParallel`. The pool is already built and tested; only the choice of work changes.

---

## Files of interest at a glance

- [`SkyrimRenderDLL/RenderPoolPatch.{h,cpp}`](SkyrimRenderDLL/) — pool capture + Parallel API. Read this first.
- [`SkyrimRenderDLL/D3DXReplace.{h,cpp}`](SkyrimRenderDLL/) — SSE wins + caller histograms.
- [`SkyrimMultiCoreDLL/SlimDllmain.cpp`](SkyrimMultiCoreDLL/SlimDllmain.cpp) — minimal DllMain for the FPS-comparison binary.
- [`SkyrimRenderDLL/dllmain.cpp`](SkyrimRenderDLL/dllmain.cpp) — full DllMain wiring all the experiments.
- [`SkyrimRenderDLL/BootstrapThread.cpp`](SkyrimRenderDLL/BootstrapThread.cpp) — runs the experiment-side init off the loader lock.
- [`SkyrimPatcher/PEPatch.cpp`](SkyrimPatcher/) — TLS-callback injection logic.

---

## Status summary

| Component | State |
|---|---|
| PE patcher | Working |
| TLS-callback DLL load (with ENB + SKSE) | Working |
| Pool capture + `RunParallel` / `ParallelFor` | Working, 4.85× scaling proven |
| D3DX SSE replacements (×7) | Working |
| Slim DLL (foundation only) | Working, no-crash, used for FPS-baseline |
| Full DLL (with experiments) | Working in instrumentation-only mode |
| Drawcall-side parallelization (sub_CB7E80, sub_CA2610) | **Structurally blocked** |
| D3D9 pipeline deferred dispatch | **Shelved** (ENB incompatibility) |
| Idle-worker initiative (Phase 3 pivot) | **Not started** |

---

## License

Personal research. Not currently licensed for redistribution.
