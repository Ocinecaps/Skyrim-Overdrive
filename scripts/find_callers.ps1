# find_callers.ps1
# ==============================================================================
# Direct caller scanner for TESV.exe.unpacked.exe.
#
# Why this exists: the IDA scripts kept failing and prior PowerShell scans
# silently produced 0 results due to int/uint coercion bugs in tight loops.
# This embeds a C# class via Add-Type so the hot loop is real .NET code with
# no PowerShell type magic.
#
# What it finds:
#   1. Direct E8 (relative-call) callers of:
#         sub_CB7E80, sub_CA2610, sub_B06250
#   2. Anywhere the vtable START VAs appear as a 4-byte literal:
#         vtable_1156B70 (slot 25 = sub_CB7E80)
#         vtable_1154A8C (slot 26 = sub_CA2610)
#      A class constructor writes the vtable pointer into the object as one
#      of these literals — finding xrefs reveals the constructor and from
#      there the class instantiations.
#   3. CreateThread / _beginthreadex import IAT slot xrefs (E8 + FF15) to
#      surface Skyrim's existing thread infrastructure.
#
# Output: writes a single text report next to the script.
# ==============================================================================

$ErrorActionPreference = "Stop"

$exePath = "C:\Program Files (x86)\Steam\steamapps\common\Skyrim\TESV.exe.unpacked.exe"
$outPath = "C:\Users\nro\Desktop\Skyrim-rendering-overdrive\scripts\callers_report.txt"

if (-not (Test-Path -LiteralPath $exePath)) {
    throw "Unpacked exe not found at: $exePath"
}

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

public static class CallerScanner {

    public class Section {
        public string Name;
        public uint VirtualAddress;   // RVA
        public uint VirtualSize;
        public uint RawOffset;
        public uint RawSize;
        public uint Characteristics;
    }

    public static byte[] FileBytes;
    public static uint  ImageBase;
    public static List<Section> Sections = new List<Section>();
    public static Section TextSection;

    public static void Load(string path) {
        FileBytes = File.ReadAllBytes(path);
        // PE header
        uint peOff = BitConverter.ToUInt32(FileBytes, 0x3C);
        if (BitConverter.ToUInt32(FileBytes, (int)peOff) != 0x00004550)
            throw new Exception("Not a PE file");
        ushort nSections = BitConverter.ToUInt16(FileBytes, (int)peOff + 6);
        ushort optHdrSize = BitConverter.ToUInt16(FileBytes, (int)peOff + 20);
        uint optHdrOff = peOff + 24;
        // PE32 ImageBase at offset 28 of OptionalHeader
        ImageBase = BitConverter.ToUInt32(FileBytes, (int)optHdrOff + 28);
        uint secOff = optHdrOff + optHdrSize;
        for (int i = 0; i < nSections; i++) {
            uint baseOff = secOff + (uint)i * 40;
            Section s = new Section();
            s.Name = Encoding.ASCII.GetString(FileBytes, (int)baseOff, 8).TrimEnd('\0');
            s.VirtualSize    = BitConverter.ToUInt32(FileBytes, (int)baseOff + 8);
            s.VirtualAddress = BitConverter.ToUInt32(FileBytes, (int)baseOff + 12);
            s.RawSize        = BitConverter.ToUInt32(FileBytes, (int)baseOff + 16);
            s.RawOffset      = BitConverter.ToUInt32(FileBytes, (int)baseOff + 20);
            s.Characteristics= BitConverter.ToUInt32(FileBytes, (int)baseOff + 36);
            Sections.Add(s);
            if (s.Name == ".text") TextSection = s;
        }
        if (TextSection == null) throw new Exception(".text section missing");
    }

    public static uint VaToFileOff(uint va) {
        uint rva = va - ImageBase;
        foreach (var s in Sections) {
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize) {
                return s.RawOffset + (rva - s.VirtualAddress);
            }
        }
        return 0xFFFFFFFF;
    }

    public static uint FileOffToVa(uint fileOff) {
        foreach (var s in Sections) {
            if (fileOff >= s.RawOffset && fileOff < s.RawOffset + s.RawSize) {
                return ImageBase + s.VirtualAddress + (fileOff - s.RawOffset);
            }
        }
        return 0;
    }

    // Returns name of containing section (for context).
    public static string SectionFor(uint va) {
        uint rva = va - ImageBase;
        foreach (var s in Sections) {
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize) {
                return s.Name;
            }
        }
        return "?";
    }

    // E8 scan: find every relative-call to any VA in `targets`.
    // Returns list of "callerVa,targetVa".
    public static List<string> ScanE8Callers(uint[] targets) {
        HashSet<uint> tset = new HashSet<uint>(targets);
        List<string> hits = new List<string>();
        uint start = TextSection.RawOffset;
        uint end   = TextSection.RawOffset + TextSection.RawSize - 5;
        byte[] b = FileBytes;
        for (uint p = start; p < end; p++) {
            if (b[p] != 0xE8) continue;
            int rel = BitConverter.ToInt32(b, (int)p + 1);
            uint callerVa = FileOffToVa(p);
            // unchecked addition: callerVa + 5 + rel  (rel may be negative)
            uint targetVa = unchecked((uint)((long)callerVa + 5L + (long)rel));
            if (tset.Contains(targetVa)) {
                hits.Add(callerVa.ToString("X8") + "," + targetVa.ToString("X8"));
            }
        }
        return hits;
    }

    // FF 15 scan: find indirect calls through an IAT slot. The 4 bytes after
    // FF 15 are an absolute VA pointing at the IAT entry.
    public static List<string> ScanFF15Callers(uint[] iatSlots) {
        HashSet<uint> tset = new HashSet<uint>(iatSlots);
        List<string> hits = new List<string>();
        uint start = TextSection.RawOffset;
        uint end   = TextSection.RawOffset + TextSection.RawSize - 6;
        byte[] b = FileBytes;
        for (uint p = start; p < end; p++) {
            if (b[p] != 0xFF || b[p + 1] != 0x15) continue;
            uint slotVa = BitConverter.ToUInt32(b, (int)p + 2);
            if (tset.Contains(slotVa)) {
                uint callerVa = FileOffToVa(p);
                hits.Add(callerVa.ToString("X8") + "," + slotVa.ToString("X8"));
            }
        }
        return hits;
    }

    // Literal-VA scan: find every 4-byte location in the whole image (any
    // section) holding one of `targets` as a uint32 little-endian.
    // Used to find xrefs to vtable start VAs (constructors store these into
    // freshly-constructed objects).
    public static List<string> ScanLiteralVas(uint[] targets) {
        HashSet<uint> tset = new HashSet<uint>(targets);
        List<string> hits = new List<string>();
        byte[] b = FileBytes;
        for (int p = 0; p < b.Length - 4; p++) {
            uint v = BitConverter.ToUInt32(b, p);
            if (tset.Contains(v)) {
                uint atVa = FileOffToVa((uint)p);
                string sec = atVa == 0 ? "?" : SectionFor(atVa);
                hits.Add(((uint)p).ToString("X8") + "," + atVa.ToString("X8") + "," + v.ToString("X8") + "," + sec);
            }
        }
        return hits;
    }
}
"@ -Language CSharp

Write-Host "Loading $exePath ..."
[CallerScanner]::Load($exePath)
Write-Host ("ImageBase=0x{0:X8}  .text VA=0x{1:X8}  size=0x{2:X}" -f `
    [CallerScanner]::ImageBase, `
    ([CallerScanner]::ImageBase + [CallerScanner]::TextSection.VirtualAddress), `
    [CallerScanner]::TextSection.VirtualSize)

# Hot subs we want callers of.
$hotSubs = [uint32[]](0xCB7E80, 0xCA2610, 0xB06250)

# Vtable START VAs — find every 4-byte literal pointing here = candidate
# constructor / instantiation site.
$vtableStarts = [uint32[]](0x01156B70, 0x01154A8C)

Write-Host "Scanning E8 callers of hot subs ..."
$e8 = [CallerScanner]::ScanE8Callers($hotSubs)
Write-Host ("  {0} E8 hits" -f $e8.Count)

Write-Host "Scanning literal-VA refs to vtable starts ..."
$lit = [CallerScanner]::ScanLiteralVas($vtableStarts)
Write-Host ("  {0} literal hits" -f $lit.Count)

# Resolve thread-API IAT slots dynamically by parsing the import directory.
# Simpler: scan for ASCII "CreateThread" then the IAT slot is the address of
# the IMAGE_THUNK_DATA elsewhere. For now we rely on the user's prior
# DebugLogger-style discovery — known IAT slot VAs from earlier session work.
# If unknown, leave empty and surface E8 + literal hits only.
$threadIatSlots = [uint32[]]@()  # populate later if we discover them

Write-Host "Writing report to $outPath ..."

$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine("# TESV.exe.unpacked.exe — caller analysis")
[void]$sb.AppendLine("# Generated by find_callers.ps1")
[void]$sb.AppendLine("# ImageBase=0x{0:X8}" -f [CallerScanner]::ImageBase)
[void]$sb.AppendLine("")
[void]$sb.AppendLine("=== Direct E8 callers of hot subs ===")
[void]$sb.AppendLine("# Format: callerVa,targetVa")
foreach ($h in $e8) { [void]$sb.AppendLine($h) }
[void]$sb.AppendLine("")
[void]$sb.AppendLine(("# Total E8 hits: {0}" -f $e8.Count))
[void]$sb.AppendLine("")
[void]$sb.AppendLine("=== Literal-VA refs to vtable starts ===")
[void]$sb.AppendLine("# Format: fileOff,atVa,literalValue,section")
[void]$sb.AppendLine("# (atVa in .text = code that loads the vtable ptr — likely a constructor)")
[void]$sb.AppendLine("# (atVa in .rdata = the vtable itself or a vtable of a derived class)")
foreach ($h in $lit) { [void]$sb.AppendLine($h) }
[void]$sb.AppendLine("")
[void]$sb.AppendLine(("# Total literal hits: {0}" -f $lit.Count))

[System.IO.File]::WriteAllText($outPath, $sb.ToString())
Write-Host "Done. Report at: $outPath"
