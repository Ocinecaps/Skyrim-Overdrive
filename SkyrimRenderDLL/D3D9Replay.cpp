#include "D3D9Replay.h"

#include <atomic>

namespace overdrive::replay {

thread_local bool   g_recording = false;
thread_local Buffer g_buffer;

std::atomic<uint32_t> g_recordedCount{0};
std::atomic<uint32_t> g_replayedCount{0};

// Captured D3D9 device. Set by mirror::Install(dev); read by the hot-sub
// thunks in NiDX9Hooks.cpp to call Replay() against the right device.
// Plain pointer (not atomic): set once during D3D9Hook init on the loader
// thread, then only read from the render thread thereafter.
IDirect3DDevice9* g_device = nullptr;
void              SetDevice(IDirect3DDevice9* dev) { g_device = dev; }
IDirect3DDevice9* GetDevice()                       { return g_device; }

void StartRecording() {
    g_recording = true;
    g_buffer.Clear();
}

void StopRecording() {
    g_recording = false;
    if (!g_buffer.records.empty()) {
        g_recordedCount.fetch_add(g_buffer.records.size(),
                                  std::memory_order_relaxed);
    }
}

uint32_t StatsRecorded() { return g_recordedCount.load(std::memory_order_relaxed); }
uint32_t StatsReplayed() { return g_replayedCount.load(std::memory_order_relaxed); }

// Increments the cumulative replayed-count atomic. Called by DoReplay (in
// D3D9Mirror.cpp) after dispatching a buffer.
void NoteReplayedCount(uint32_t n) {
    g_replayedCount.fetch_add(n, std::memory_order_relaxed);
}

// Function-pointer dispatch — D3D9Mirror.cpp registers its DoReplay() at
// static-init time. Until that happens (early DllMain phases), Replay just
// returns E_NOTIMPL and bumps a small counter so missed calls are visible.
ReplayFn g_replayImpl = nullptr;

void SetReplayImpl(ReplayFn fn) {
    g_replayImpl = fn;
}

HRESULT Replay(IDirect3DDevice9* dev, const Buffer& buf) {
    if (g_replayImpl) return g_replayImpl(dev, buf);
    return E_NOTIMPL;
}

}
