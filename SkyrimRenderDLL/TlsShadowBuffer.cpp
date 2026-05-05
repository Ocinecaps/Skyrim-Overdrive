#include "TlsShadowBuffer.h"
#include "DebugLogger.h"

#include <windows.h>
#include <atomic>
#include <cstring>

namespace overdrive::tlsshadow {

namespace {

// Shadow storage. 8 slots × 8 KB = 64 KB total. Aligned to 16 bytes so SSE
// reads/writes inside the replacement function are aligned.
__declspec(align(16)) uint8_t g_shadowBAC080[kMaxShadowSlots][kShadowBufferBytes];
__declspec(align(16)) uint8_t g_shadowBAE0A8[kMaxShadowSlots][kShadowBufferBytes];

// Slot ownership. tid 0 = unclaimed; otherwise the TID of the owning thread.
// Atomic so multiple threads can race to claim slots without a CS.
std::atomic<DWORD> g_slotOwner[kMaxShadowSlots];

// Per-thread slot index. We can't use real TLS without changing the .vcxproj
// (the existing build doesn't enable /Tp TLS), so we walk the owner array.
// With 8 slots that's at most 8 reads — cheap. Could cache in __declspec(thread)
// later if profiling shows it matters.

}  // namespace

void Init() {
    std::memset(g_shadowBAC080, 0, sizeof(g_shadowBAC080));
    std::memset(g_shadowBAE0A8, 0, sizeof(g_shadowBAE0A8));
    for (int i = 0; i < kMaxShadowSlots; ++i) {
        g_slotOwner[i].store(0, std::memory_order_relaxed);
    }
    OD_LOG("[TlsShadow] Init: %d slots × %d bytes × 2 buffers = %d bytes total",
           kMaxShadowSlots, kShadowBufferBytes,
           kMaxShadowSlots * kShadowBufferBytes * 2);
}

int ClaimSlot() {
    const DWORD tid = GetCurrentThreadId();
    // Already claimed?
    for (int i = 0; i < kMaxShadowSlots; ++i) {
        if (g_slotOwner[i].load(std::memory_order_acquire) == tid) {
            return i;
        }
    }
    // Find a free slot and CAS-claim it.
    for (int i = 0; i < kMaxShadowSlots; ++i) {
        DWORD expected = 0;
        if (g_slotOwner[i].compare_exchange_strong(expected, tid,
                                                   std::memory_order_acq_rel)) {
            // Zero the shadow on first claim so stale data from a previous
            // owner doesn't leak in. (Init() zeroes initially; this is
            // belt-and-suspenders for a hypothetical re-claim after release.)
            std::memset(g_shadowBAC080[i], 0, kShadowBufferBytes);
            std::memset(g_shadowBAE0A8[i], 0, kShadowBufferBytes);
            OD_LOG("[TlsShadow] tid=%lu claimed slot %d", (unsigned long)tid, i);
            return i;
        }
    }
    OD_LOG("[TlsShadow] WARN: tid=%lu found no free slot (all %d in use)",
           (unsigned long)tid, kMaxShadowSlots);
    return -1;
}

int GetSlot() {
    const DWORD tid = GetCurrentThreadId();
    for (int i = 0; i < kMaxShadowSlots; ++i) {
        if (g_slotOwner[i].load(std::memory_order_acquire) == tid) {
            return i;
        }
    }
    return -1;
}

void ReleaseSlot(int slot) {
    if (slot < 0 || slot >= kMaxShadowSlots) return;
    const DWORD tid = GetCurrentThreadId();
    DWORD expected = tid;
    if (g_slotOwner[slot].compare_exchange_strong(expected, 0,
                                                  std::memory_order_acq_rel)) {
        OD_LOG("[TlsShadow] tid=%lu released slot %d", (unsigned long)tid, slot);
    }
}

void* GetShadowBAC080(int slot) {
    if (slot < 0 || slot >= kMaxShadowSlots) return nullptr;
    return g_shadowBAC080[slot];
}

void* GetShadowBAE0A8(int slot) {
    if (slot < 0 || slot >= kMaxShadowSlots) return nullptr;
    return g_shadowBAE0A8[slot];
}

void MergeSlot(int slot, uint32_t realBac080VA, uint32_t realBae0a8VA) {
    if (slot < 0 || slot >= kMaxShadowSlots) return;
    // Bulk copy from shadow back to the real globals. Each call is 4 KB ×
    // 2 = 8 KB of memcpy. SIMD-aligned (we declared the shadow with 16-byte
    // alignment), so the runtime memcpy will use SSE/AVX moves.
    std::memcpy(reinterpret_cast<void*>(realBac080VA),
                g_shadowBAC080[slot], kShadowBufferBytes);
    std::memcpy(reinterpret_cast<void*>(realBae0a8VA),
                g_shadowBAE0A8[slot], kShadowBufferBytes);
}

}  // namespace
