#include "Logging.h"
#include "BackupManager.h"
#include "PEPatch.h"
#include "BytePatches.h"
#include "Inspector.h"

#include <windows.h>
#include <commdlg.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <string>
#include <vector>

using namespace patcher;

namespace {

enum class Action { Patch, Revert, RevertPrevious, Inspect, Diff, Cancel };

constexpr const char* kSteamAppId        = "72850";   // Skyrim Legendary Edition
constexpr const char* kInjectedDll       = "SkyrimRenderOverdrive.dll";
constexpr const char* kSteamAppIdFile    = "steam_appid.txt";

std::string PatcherLogPath() {
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    PathRemoveFileSpecA(buf);
    return std::string(buf) + "\\skyrim_overdrive_patcher.log";
}

bool ParseArgvForExe(std::string& outPath, Action& outAction) {
    outAction = Action::Patch;  // default; overridden by flags
    int argc = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argvW) return false;

    bool foundPath = false;
    for (int i = 1; i < argc; ++i) {
        char buf[MAX_PATH] = {};
        WideCharToMultiByte(CP_ACP, 0, argvW[i], -1, buf, MAX_PATH, nullptr, nullptr);
        std::string a(buf);
        if (a == "--revert" || a == "-r")          outAction = Action::Revert;
        else if (a == "--undo" || a == "-u")       outAction = Action::RevertPrevious;
        else if (a == "--inspect" || a == "-i")    outAction = Action::Inspect;
        else if (a == "--diff" || a == "-d")       outAction = Action::Diff;
        else if (a == "--patch" || a == "-p")      outAction = Action::Patch;
        else if (!a.empty() && a[0] != '-')        { outPath = a; foundPath = true; }
    }
    LocalFree(argvW);
    return foundPath;
}

bool PromptForExe(std::string& outPath) {
    char szFile[MAX_PATH] = {};
    const char* defaultPath = "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Skyrim\\TESV.exe";
    if (GetFileAttributesA(defaultPath) != INVALID_FILE_ATTRIBUTES) {
        strncpy_s(szFile, defaultPath, _TRUNCATE);
    }

    OPENFILENAMEA ofn{};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = nullptr;
    ofn.lpstrFile    = szFile;
    ofn.nMaxFile     = sizeof(szFile);
    ofn.lpstrFilter  = "Skyrim Executable (TESV.exe)\0TESV.exe\0All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrTitle   = "Select Skyrim TESV.exe";
    ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR;

    if (!GetOpenFileNameA(&ofn)) return false;
    outPath = szFile;
    return true;
}

// Three-way action menu. Yes=Patch, No=Inspect, Cancel=open submenu.
Action AskAction(const std::string& exePath, const ExeReport& currentState) {
    std::string body;
    bool hasBind = false;
    for (const auto& s : currentState.sections) {
        if (s.name == ".bind") { hasBind = true; break; }
    }

    body  = "Target: " + exePath + "\n\n";
    body += "Current state: ";
    if (!currentState.valid)                 body += "INVALID PE";
    else if (hasBind)                        body += "SteamStub-WRAPPED (will be unstubbed via .unpacked.exe sibling)";
    else if (currentState.referencesOurDll)  body += "ALREADY PATCHED with our DLL (unwrapped)";
    else if (currentState.hasInjsec)         body += "Has .injsec but no DLL ref (stale?)";
    else                                     body += "Unwrapped, pristine layout (not patched)";
    body += "\n\n";
    body += "Choose action:\n";
    body += "  YES    = Apply patch (re-patches cleanly if already patched)\n";
    body += "  NO     = Inspect (PE info + diff vs .original) — read-only\n";
    body += "  CANCEL = More options (Revert / Undo last patch / Cancel)";

    int r = MessageBoxA(nullptr, body.c_str(),
                        "SkyrimPatcher — Action",
                        MB_YESNOCANCEL | MB_ICONQUESTION);
    if (r == IDYES)    return Action::Patch;
    if (r == IDNO)     return Action::Inspect;

    // Submenu
    int s = MessageBoxA(nullptr,
        "More options:\n\n"
        "  YES    = Revert to .original (pristine, undoes ALL changes)\n"
        "  NO     = Undo to .previous (restore state before last patch)\n"
        "  CANCEL = Do nothing",
        "SkyrimPatcher — More",
        MB_YESNOCANCEL | MB_ICONQUESTION);
    if (s == IDYES) return Action::Revert;
    if (s == IDNO)  return Action::RevertPrevious;
    return Action::Cancel;
}

bool VerifyWriteAccess(const std::string& exePath) {
    HANDLE h = CreateFileA(exePath.c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        LOGE("Cannot open exe for write (GetLastError=%lu). "
             "Likely permissions: try 'Run as administrator', "
             "or close Skyrim/Steam first.", err);
        return false;
    }
    CloseHandle(h);
    return true;
}

// If <exePath> is SteamStub-wrapped (has a .bind section), replace its content
// with the user's pre-unpacked sibling at <exePath>.unpacked.exe.
//
// Why: Steam's SteamStub DRM lives in the .bind section. SteamStub validates
// its own headers at process start; any modification (NumberOfSections,
// SizeOfImage, etc.) triggers "Application load error 3:0000065432". The .text
// section is also encrypted on disk and SteamStub does the decryption — so
// patching around SteamStub without unpacking is impractical.
//
// Solution: use the user's existing Steamless-unpacked sibling
// (TESV.exe.unpacked.exe — which they already produced for IDA analysis) as
// the patch source. The unpacked file has no .bind section, no encrypted
// .text, and a real entry point in .text. After replacing, our PE patches
// land in a normal binary and run cleanly.
//
// The user's TESV.exe.unpacked.exe is READ ONLY — never modified.
// The wrapped original is preserved at TESV.exe.original (full revert path).
bool DesteamstubViaSibling(const std::string& exePath) {
    ExeReport r = InspectExe(exePath);
    if (!r.valid) {
        LOGE("DesteamstubViaSibling: cannot inspect exe: %s", r.error.c_str());
        return false;
    }
    bool hasBind = false;
    for (const auto& s : r.sections) {
        if (s.name == ".bind") { hasBind = true; break; }
    }
    if (!hasBind) {
        LOGI("Exe has no .bind section — already unwrapped. Skipping desteamstub step.");
        return true;
    }

    LOGI("Exe is SteamStub-wrapped (.bind section present). Looking for unpacked sibling...");

    const std::string unpackedPath = exePath + ".unpacked.exe";
    if (GetFileAttributesA(unpackedPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LOGE("SteamStub-wrapped exe but no .unpacked.exe sibling at:\n  %s\n"
             "You must unpack TESV.exe with Steamless once before running this patcher.",
             unpackedPath.c_str());
        return false;
    }

    // Sanity-check the sibling: it should be a valid PE32 with NO .bind section.
    ExeReport siblingReport = InspectExe(unpackedPath);
    if (!siblingReport.valid) {
        LOGE("Unpacked sibling is not a valid PE: %s — %s",
             unpackedPath.c_str(), siblingReport.error.c_str());
        return false;
    }
    for (const auto& s : siblingReport.sections) {
        if (s.name == ".bind") {
            LOGE("Unpacked sibling still has a .bind section — Steamless run was incomplete?");
            return false;
        }
    }

    LOGI("Found valid unpacked sibling: %s (size=%lu)",
         unpackedPath.c_str(), siblingReport.fileSizeBytes);
    LOGI("Copying unpacked content over TESV.exe (sibling itself remains untouched)");
    if (!CopyFileA(unpackedPath.c_str(), exePath.c_str(), FALSE)) {
        LOGE("Failed to copy unpacked sibling over exe, GetLastError=%lu", GetLastError());
        return false;
    }
    LOGI("Desteamstub OK: TESV.exe is now the unwrapped image; SteamStub bypassed.");
    return true;
}

void EnsureSteamAppIdFile(const std::string& exePath) {
    char dir[MAX_PATH] = {};
    strncpy_s(dir, exePath.c_str(), _TRUNCATE);
    PathRemoveFileSpecA(dir);
    std::string appIdPath = std::string(dir) + "\\" + kSteamAppIdFile;

    HANDLE h = CreateFileA(appIdPath.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        LOGW("Could not create %s (GetLastError=%lu). Steam launch bypass may fail.",
             appIdPath.c_str(), GetLastError());
        return;
    }
    DWORD written = 0;
    WriteFile(h, kSteamAppId, static_cast<DWORD>(strlen(kSteamAppId)), &written, nullptr);
    CloseHandle(h);
    LOGI("Wrote %s with app id %s (lets game launch outside Steam's verifier)",
         appIdPath.c_str(), kSteamAppId);
}

bool DoPatch(const std::string& exePath) {
    if (!VerifyWriteAccess(exePath)) return false;
    if (!EnsurePatchReadySource(exePath)) return false;
    if (!DesteamstubViaSibling(exePath)) return false;
    // Byte-splice patches (Sleep -> PAUSE in hot message-pump loop, etc).
    // Applied AFTER desteamstub (so we patch the unpacked image) but BEFORE
    // AddInjsecAndTLS (which doesn't touch .text — order is safe either way).
    if (!ApplyBytePatches(exePath)) {
        LOGW("ApplyBytePatches: at least one patch site had unknown bytes "
             "(non-fatal — TLS-DLL injection still applies).");
    }
    if (!AddInjsecAndTLS(exePath, kInjectedDll)) return false;
    if (!ZeroChecksumAndTimestamp(exePath)) {
        LOGW("Header cleanup failed (non-fatal)");
    }
    EnsureSteamAppIdFile(exePath);
    LOGI("Patch complete. TESV.exe will load %s via TLS callback.", kInjectedDll);
    return true;
}

void ShowText(const char* title, const std::string& text, UINT icon) {
    MessageBoxA(nullptr, text.c_str(), title, MB_OK | icon);
}

void ShowPatchResult(bool ok, const std::string& exePath, const std::string& logPath) {
    std::string msg;
    if (ok) {
        msg  = "TESV.exe patched successfully.\n\n";
        msg += "Patched:        " + exePath + "\n";
        msg += "Pristine backup: " + exePath + ".original\n";
        msg += "Rollback point:  " + exePath + ".previous (state before this patch)\n";
        msg += "Steam app id:    written next to TESV.exe (steam_appid.txt)\n";
        msg += "Log:             " + logPath + "\n\n";
        msg += "IMPORTANT: launch the game by double-clicking skse_loader.exe\n";
        msg += "directly. Do NOT use Steam's 'Play' button — Steam will reject\n";
        msg += "the modified exe with 'Application load error 3:0000065432'.\n\n";
        msg += "Make sure SkyrimRenderOverdrive.dll and SDL3.dll are in the\n";
        msg += "same folder as TESV.exe before launching.";
        ShowText("SkyrimPatcher — DONE", msg, MB_ICONINFORMATION);
    } else {
        msg  = "PATCH FAILED.\n\nTarget: " + (exePath.empty() ? std::string("(none)") : exePath) + "\n";
        msg += "Log:    " + logPath + "\n\nOpen the log for details.";
        ShowText("SkyrimPatcher — FAILED", msg, MB_ICONERROR);
    }
}

}

int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    const std::string logPath = PatcherLogPath();
    InitLog(logPath);
    LOGI("SkyrimPatcher v1 (bootstrapper)");
    LOGI("Log file: %s", logPath.c_str());

    std::string exePath;
    Action action = Action::Patch;
    bool fromArgv = ParseArgvForExe(exePath, action);

    if (!fromArgv) {
        if (!PromptForExe(exePath)) {
            LOGI("No file selected; exiting");
            CloseLog();
            return 0;
        }
    } else {
        LOGI("Exe path from command line: %s", exePath.c_str());
    }

    if (GetFileAttributesA(exePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        ShowText("SkyrimPatcher", "Selected file does not exist:\n" + exePath, MB_ICONERROR);
        CloseLog();
        return 1;
    }

    // Inspect once for the menu summary; always cheap.
    ExeReport currentState = InspectExe(exePath);

    if (!fromArgv) {
        action = AskAction(exePath, currentState);
    } else {
        const char* names[] = {"Patch","Revert","RevertPrevious","Inspect","Diff","Cancel"};
        LOGI("Action from CLI: %s", names[static_cast<int>(action)]);
    }

    bool ok = false;
    switch (action) {
        case Action::Patch:
            ok = DoPatch(exePath);
            ShowPatchResult(ok, exePath, logPath);
            break;
        case Action::Revert:
            ok = RestoreFromOriginal(exePath);
            ShowText("SkyrimPatcher — Revert",
                     ok ? "Restored TESV.exe from .original (pristine).\nLog: " + logPath
                        : "Revert FAILED. See log: " + logPath,
                     ok ? MB_ICONINFORMATION : MB_ICONERROR);
            break;
        case Action::RevertPrevious:
            ok = RestoreFromPrevious(exePath);
            ShowText("SkyrimPatcher — Undo",
                     ok ? "Restored TESV.exe from .previous (pre-last-patch state).\nLog: " + logPath
                        : "Undo FAILED — no .previous snapshot exists yet.\nLog: " + logPath,
                     ok ? MB_ICONINFORMATION : MB_ICONERROR);
            break;
        case Action::Inspect: {
            std::string txt = "PE INSPECTION\n=============\n\n" + FormatReport(currentState);
            txt += "\n\nDIFF VS .ORIGINAL\n=================\n\n" + DiffAgainstOriginal(exePath);
            LOGI("Inspect output:\n%s", txt.c_str());
            ShowText("SkyrimPatcher — Inspect", txt, MB_ICONINFORMATION);
            ok = true;
            break;
        }
        case Action::Diff: {
            std::string txt = "DIFF VS .ORIGINAL\n=================\n\n" + DiffAgainstOriginal(exePath);
            LOGI("Diff output:\n%s", txt.c_str());
            ShowText("SkyrimPatcher — Diff", txt, MB_ICONINFORMATION);
            ok = true;
            break;
        }
        case Action::Cancel:
            LOGI("User cancelled");
            ok = true;
            break;
    }

    CloseLog();
    return ok ? 0 : 1;
}
