#include "BackupManager.h"
#include "Logging.h"

#include <windows.h>

namespace patcher {

namespace {
std::string OriginalPath(const std::string& exePath) { return exePath + ".original"; }
std::string PreviousPath(const std::string& exePath) { return exePath + ".previous"; }
}

bool EnsurePatchReadySource(const std::string& exePath) {
    if (GetFileAttributesA(exePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LOGE("EnsurePatchReadySource: source exe not found: %s", exePath.c_str());
        return false;
    }

    const std::string original = OriginalPath(exePath);
    const std::string previous = PreviousPath(exePath);

    if (GetFileAttributesA(original.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LOGI("First-ever patch on this exe: capturing pristine backup -> %s",
             original.c_str());
        if (!CopyFileA(exePath.c_str(), original.c_str(), TRUE)) {
            LOGE("CopyFile failed (capture .original), GetLastError=%lu", GetLastError());
            return false;
        }
        return true;
    }

    LOGI("Snapshotting current TESV.exe -> %s (rollback point)", previous.c_str());
    if (!CopyFileA(exePath.c_str(), previous.c_str(), FALSE)) {
        LOGW("CopyFile failed (snapshot .previous), GetLastError=%lu — continuing",
             GetLastError());
    }

    LOGI("Restoring TESV.exe from %s for clean re-patch", original.c_str());
    if (!CopyFileA(original.c_str(), exePath.c_str(), FALSE)) {
        LOGE("CopyFile failed (restore from .original), GetLastError=%lu", GetLastError());
        return false;
    }
    return true;
}

bool RestoreFromOriginal(const std::string& exePath) {
    const std::string original = OriginalPath(exePath);
    if (GetFileAttributesA(original.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LOGE("RestoreFromOriginal: backup not found: %s", original.c_str());
        return false;
    }
    if (!CopyFileA(original.c_str(), exePath.c_str(), FALSE)) {
        LOGE("RestoreFromOriginal: CopyFile failed, GetLastError=%lu", GetLastError());
        return false;
    }
    LOGI("Restored TESV.exe from %s", original.c_str());
    return true;
}

bool RestoreFromPrevious(const std::string& exePath) {
    const std::string previous = PreviousPath(exePath);
    if (GetFileAttributesA(previous.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LOGE("RestoreFromPrevious: snapshot not found: %s", previous.c_str());
        return false;
    }
    if (!CopyFileA(previous.c_str(), exePath.c_str(), FALSE)) {
        LOGE("RestoreFromPrevious: CopyFile failed, GetLastError=%lu", GetLastError());
        return false;
    }
    LOGI("Restored TESV.exe from %s", previous.c_str());
    return true;
}

}
