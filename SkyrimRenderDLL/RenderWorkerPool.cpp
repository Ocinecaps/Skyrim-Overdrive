#include "RenderWorkerPool.h"
#include "D3D9Replay.h"
#include "DebugLogger.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>
#include <utility>
#include <windows.h>

// ExitThunk_HotSub reads this thread_local to decide whether to replay locally
// (default; render thread) or leave the buffer for the pool's coordinator
// (worker threads). Defined in NiDX9Hooks.cpp; declared here for the workers
// to set on themselves.
namespace overdrive::nidx9 {
extern __declspec(thread) bool t_skipReplay;
}

namespace overdrive::workerpool {

namespace {

struct Job {
    uint32_t index;
    std::function<void()> fn;
};

struct OutboxEntry {
    uint32_t index;
    overdrive::replay::Buffer buffer;
};

// =============================================================================
// Pool state
// =============================================================================

std::vector<std::thread> g_workers;
bool g_initialized = false;

std::mutex              g_jobMutex;
std::condition_variable g_jobCv;
std::deque<Job>         g_jobQueue;
bool                    g_shutdown = false;

std::mutex              g_outboxMutex;
std::vector<OutboxEntry> g_outbox;

std::atomic<uint32_t>   g_submittedCount{0};
std::atomic<uint32_t>   g_completedCount{0};

// Persistent stats (cumulative since pool init).
std::atomic<uint32_t> g_statScopes{0};
std::atomic<uint32_t> g_statSubmitted{0};
std::atomic<uint32_t> g_statCompleted{0};
std::atomic<uint32_t> g_statRecords{0};
std::atomic<uint32_t> g_statOutboxHigh{0};

std::chrono::steady_clock::time_point g_lastLog;

// =============================================================================
// Worker loop
// =============================================================================
//
// Workers pick jobs from g_jobQueue. For each job:
//   1. Set t_skipReplay = true so ExitThunk_HotSub leaves the buffer for
//      the coordinator (instead of replaying it inline on this worker).
//   2. Run the callable. The callable should invoke Skyrim code that
//      hits one of our hooked hot subs. EnterThunk_HotSub at depth=0
//      calls StartRecording; sub runs; ExitThunk at depth=0 calls
//      StopRecording but skips the local Replay because t_skipReplay.
//   3. Move the thread_local g_buffer into the outbox under the job's
//      submission index. Clear g_buffer for the next job.
//   4. Decrement the in-flight counter; signal coordinator if last job.

void WorkerLoop(int workerId) {
    overdrive::nidx9::t_skipReplay = true;

    for (;;) {
        Job job;
        {
            std::unique_lock<std::mutex> lk(g_jobMutex);
            g_jobCv.wait(lk, []{ return g_shutdown || !g_jobQueue.empty(); });
            if (g_shutdown && g_jobQueue.empty()) return;
            job = std::move(g_jobQueue.front());
            g_jobQueue.pop_front();
        }

        if (job.fn) {
            // Run the recorded work. Hot-sub thunks fire on this thread;
            // recording is on for the duration of each outer hot-sub call.
            try {
                job.fn();
            } catch (...) {
                // Don't let an exception take down the worker. Outbox entry
                // for this job's index will be missing — the coordinator
                // will skip it during drain.
            }
        }

        // Move the buffer into the outbox. The buffer is in this thread's
        // overdrive::replay::g_buffer (TLS). std::move is O(1) since both
        // member vectors transfer their underlying storage.
        OutboxEntry entry;
        entry.index = job.index;
        entry.buffer = std::move(overdrive::replay::CurrentBuffer());
        // After move, source vectors are empty but otherwise valid. Clear
        // explicitly to make the contract obvious.
        overdrive::replay::CurrentBuffer().Clear();

        {
            std::lock_guard<std::mutex> lk(g_outboxMutex);
            g_outbox.push_back(std::move(entry));
            const uint32_t depth = static_cast<uint32_t>(g_outbox.size());
            uint32_t prevHigh = g_statOutboxHigh.load(std::memory_order_relaxed);
            while (depth > prevHigh &&
                   !g_statOutboxHigh.compare_exchange_weak(prevHigh, depth,
                                                          std::memory_order_relaxed)) {}
        }

        g_statRecords.fetch_add(static_cast<uint32_t>(entry.buffer.records.size()),
                                std::memory_order_relaxed);
        g_statCompleted.fetch_add(1, std::memory_order_relaxed);
        g_completedCount.fetch_add(1, std::memory_order_release);
    }
}

}  // namespace

// =============================================================================
// Public API
// =============================================================================

bool Init(int n) {
    if (g_initialized) return true;
    if (n <= 0) n = 4;
    if (n > kMaxWorkers) n = kMaxWorkers;

    g_workers.reserve(n);
    for (int i = 0; i < n; ++i) {
        g_workers.emplace_back(WorkerLoop, i);
    }
    g_initialized = true;
    g_lastLog = std::chrono::steady_clock::now();
    OD_LOG("[WPool] Initialized with %d worker threads. Idle until first Submit().", n);
    return true;
}

void StartScope() {
    if (!g_initialized) Init(0);  // lazy default
    g_submittedCount.store(0, std::memory_order_relaxed);
    g_completedCount.store(0, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lk(g_outboxMutex);
        g_outbox.clear();
    }
    g_statScopes.fetch_add(1, std::memory_order_relaxed);
}

void EndScope() {
    // Reserved. Currently nothing to do — the outbox is cleared by
    // DrainAndReplay (called between WaitAll and EndScope in the canonical
    // sequence) and StartScope (which clears at the start of the next scope).
}

uint32_t Submit(std::function<void()> fn) {
    if (!g_initialized) Init(0);
    const uint32_t idx = g_submittedCount.fetch_add(1, std::memory_order_relaxed);
    g_statSubmitted.fetch_add(1, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lk(g_jobMutex);
        g_jobQueue.push_back({idx, std::move(fn)});
    }
    g_jobCv.notify_one();
    return idx;
}

void WaitAll() {
    const uint32_t target = g_submittedCount.load(std::memory_order_relaxed);
    // Spin-wait briefly, then yield. Most parallel scopes finish in microseconds;
    // Sleep(0) gives time slices back without inter-thread mutex contention.
    while (g_completedCount.load(std::memory_order_acquire) < target) {
        Sleep(0);
    }
}

void DrainAndReplay(IDirect3DDevice9* dev) {
    if (!g_initialized) return;

    // Snapshot outbox under lock; replay with lock released so we don't
    // serialize against workers finishing future scopes (they'd be writing
    // future-scope entries we don't care about until next StartScope clears).
    std::vector<OutboxEntry> drained;
    {
        std::lock_guard<std::mutex> lk(g_outboxMutex);
        drained = std::move(g_outbox);
        g_outbox.clear();
    }
    if (drained.empty()) return;

    // Sort by submission index so the replay order matches the submission
    // order, regardless of which worker happened to finish each job first.
    std::sort(drained.begin(), drained.end(),
              [](const OutboxEntry& a, const OutboxEntry& b) {
                  return a.index < b.index;
              });

    if (dev) {
        for (const auto& e : drained) {
            if (!e.buffer.records.empty()) {
                overdrive::replay::Replay(dev, e.buffer);
            }
        }
    }
}

Stats GetStats() {
    Stats s;
    s.scopesEntered    = g_statScopes.load(std::memory_order_relaxed);
    s.jobsSubmitted    = g_statSubmitted.load(std::memory_order_relaxed);
    s.jobsCompleted    = g_statCompleted.load(std::memory_order_relaxed);
    s.recordsReplayed  = g_statRecords.load(std::memory_order_relaxed);
    s.outboxHighWater  = g_statOutboxHigh.load(std::memory_order_relaxed);
    return s;
}

void MaybeLogStats() {
    const auto now     = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - g_lastLog);
    if (elapsed.count() < 5000) return;
    g_lastLog = now;
    if (!g_initialized) return;

    const Stats s = GetStats();
    OD_LOG("[WPool] workers=%zu scopes=%u submitted=%u completed=%u "
           "recordsReplayed=%u outboxHigh=%u  (DORMANT until parent loop hooked)",
           g_workers.size(), s.scopesEntered, s.jobsSubmitted, s.jobsCompleted,
           s.recordsReplayed, s.outboxHighWater);
}

}
