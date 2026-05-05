using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

// FindCallers.cs
// =============================================================================
// Direct caller scanner for TESV.exe.unpacked.exe.
//
// What it finds:
//   1. Direct E8 (relative-call) callers of:
//         sub_CB7E80, sub_CA2610, sub_B06250
//   2. Anywhere a tracked vtable START VA appears as a 4-byte literal:
//         vtable_1156B70 (slot 25 = sub_CB7E80)
//         vtable_1154A8C (slot 26 = sub_CA2610)
//      A class constructor writes the vtable pointer into a fresh object as
//      one of these literals — finding xrefs reveals the constructor and
//      from there the class instantiation sites.
//
// Output: writes callers_report.txt next to itself.
// =============================================================================

public static class FindCallers
{
    public class Section
    {
        public string Name;
        public uint VirtualAddress;
        public uint VirtualSize;
        public uint RawOffset;
        public uint RawSize;
        public uint Characteristics;
    }

    public static byte[] FileBytes;
    public static uint ImageBase;
    public static List<Section> Sections = new List<Section>();
    public static Section TextSection;

    public static void Load(string path)
    {
        FileBytes = File.ReadAllBytes(path);
        uint peOff = BitConverter.ToUInt32(FileBytes, 0x3C);
        if (BitConverter.ToUInt32(FileBytes, (int)peOff) != 0x00004550)
            throw new Exception("Not a PE file");
        ushort nSections = BitConverter.ToUInt16(FileBytes, (int)peOff + 6);
        ushort optHdrSize = BitConverter.ToUInt16(FileBytes, (int)peOff + 20);
        uint optHdrOff = peOff + 24;
        ImageBase = BitConverter.ToUInt32(FileBytes, (int)optHdrOff + 28);
        uint secOff = optHdrOff + optHdrSize;
        for (int i = 0; i < nSections; i++)
        {
            uint baseOff = secOff + (uint)i * 40;
            Section s = new Section();
            s.Name = Encoding.ASCII.GetString(FileBytes, (int)baseOff, 8).TrimEnd('\0');
            s.VirtualSize = BitConverter.ToUInt32(FileBytes, (int)baseOff + 8);
            s.VirtualAddress = BitConverter.ToUInt32(FileBytes, (int)baseOff + 12);
            s.RawSize = BitConverter.ToUInt32(FileBytes, (int)baseOff + 16);
            s.RawOffset = BitConverter.ToUInt32(FileBytes, (int)baseOff + 20);
            s.Characteristics = BitConverter.ToUInt32(FileBytes, (int)baseOff + 36);
            Sections.Add(s);
            if (s.Name == ".text") TextSection = s;
        }
        if (TextSection == null) throw new Exception(".text missing");
    }

    public static uint FileOffToVa(uint fileOff)
    {
        foreach (var s in Sections)
        {
            if (fileOff >= s.RawOffset && fileOff < s.RawOffset + s.RawSize)
                return ImageBase + s.VirtualAddress + (fileOff - s.RawOffset);
        }
        return 0;
    }

    public static string SectionFor(uint va)
    {
        if (va < ImageBase) return "?";
        uint rva = va - ImageBase;
        foreach (var s in Sections)
        {
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.VirtualSize)
                return s.Name;
        }
        return "?";
    }

    public static List<string> ScanE8Callers(uint[] targets)
    {
        var tset = new HashSet<uint>(targets);
        var hits = new List<string>();
        uint start = TextSection.RawOffset;
        uint end = TextSection.RawOffset + TextSection.RawSize - 5;
        byte[] b = FileBytes;
        for (uint p = start; p < end; p++)
        {
            if (b[p] != 0xE8) continue;
            int rel = BitConverter.ToInt32(b, (int)p + 1);
            uint callerVa = FileOffToVa(p);
            uint targetVa = unchecked((uint)((long)callerVa + 5L + (long)rel));
            if (tset.Contains(targetVa))
                hits.Add(callerVa.ToString("X8") + "," + targetVa.ToString("X8"));
        }
        return hits;
    }

    public static List<string> ScanLiteralVas(uint[] targets)
    {
        var tset = new HashSet<uint>(targets);
        var hits = new List<string>();
        byte[] b = FileBytes;
        int n = b.Length - 4;
        for (int p = 0; p < n; p++)
        {
            uint v = BitConverter.ToUInt32(b, p);
            if (tset.Contains(v))
            {
                uint atVa = FileOffToVa((uint)p);
                string sec = SectionFor(atVa);
                hits.Add(((uint)p).ToString("X8") + "," + atVa.ToString("X8") + "," + v.ToString("X8") + "," + sec);
            }
        }
        return hits;
    }

    // Returns 32 vtable slots starting at vtableVa.
    public static List<string> DumpVtableSlots(uint vtableVa, int slots)
    {
        var lines = new List<string>();
        uint rva = vtableVa - ImageBase;
        Section s = null;
        foreach (var ss in Sections)
            if (rva >= ss.VirtualAddress && rva < ss.VirtualAddress + ss.VirtualSize) { s = ss; break; }
        if (s == null) { lines.Add("# vtable VA 0x" + vtableVa.ToString("X8") + " not in any section"); return lines; }
        uint fileOff = s.RawOffset + (rva - s.VirtualAddress);
        for (int i = 0; i < slots; i++)
        {
            int off = (int)fileOff + i * 4;
            if (off + 4 > FileBytes.Length) break;
            uint slotVa = BitConverter.ToUInt32(FileBytes, off);
            lines.Add(string.Format("  slot[{0,2}]  +0x{1:X2}  ->  0x{2:X8}", i, i * 4, slotVa));
        }
        return lines;
    }

    // Heuristic: walk back from a code VA to find the previous function start.
    // We look for either CC-padding followed by a prologue, or a RET (C3/C2)
    // followed by aligned bytes then a prologue. Common Skyrim/MSVC prologues:
    //   55 8B EC                push ebp; mov ebp, esp
    //   8B FF                   mov edi, edi (hot-patch nop)
    //   83 EC ??                sub esp, imm8
    //   81 EC ?? ?? ?? ??       sub esp, imm32
    //   53                      push ebx (often after 55 8B EC, but also bare)
    //   56                      push esi
    //   57                      push edi
    // Walk forward from a function start until we hit a RET (C3 / C2 imm16)
    // followed by alignment padding (CC...) and then a recognizable prologue
    // (55 8B EC or 8B FF). Returns the VA of the byte AFTER the function's
    // last instruction (i.e., one past the last RET).
    //
    // Heuristic: scan forward up to maxLen bytes. Track the most recent RET
    // we've seen. When we find a prologue preceded by >=1 CC byte, the
    // function ended at the most recent RET before that point.
    public static uint FindFuncEnd(uint startVa, int maxLen)
    {
        // This is a BYTE-WALK, not a real disassembler — it doesn't know
        // about jump tables / data embedded in code, so it can be fooled.
        // Heuristic: find the first RET (C3 or C2 imm16) that is followed by
        // >=2 CC alignment bytes. That's the canonical end-of-function marker
        // emitted by MSVC for /align:16 .text padding.
        if (TextSection == null) return 0;
        uint rva = startVa - ImageBase;
        if (rva < TextSection.VirtualAddress || rva >= TextSection.VirtualAddress + TextSection.VirtualSize)
            return 0;
        int p = (int)(TextSection.RawOffset + (rva - TextSection.VirtualAddress));
        int textEnd = (int)(TextSection.RawOffset + TextSection.RawSize);
        int hardLimit = Math.Min(p + maxLen, textEnd - 4);
        byte[] b = FileBytes;
        for (int i = p; i < hardLimit; i++)
        {
            byte op = b[i];
            int retEnd = -1;
            if (op == 0xC3) retEnd = i + 1;
            else if (op == 0xC2 && i + 2 < hardLimit) retEnd = i + 3;
            if (retEnd < 0) continue;
            // Check for >=2 CC pad bytes after the ret.
            if (retEnd + 1 < hardLimit && b[retEnd] == 0xCC && b[retEnd + 1] == 0xCC)
                return FileOffToVa((uint)retEnd);
        }
        return 0;
    }

    public static uint FindContainingFunc(uint codeVa, int maxBack)
    {
        uint rva = codeVa - ImageBase;
        if (TextSection == null) return 0;
        uint fileOff = TextSection.RawOffset + (rva - TextSection.VirtualAddress);
        byte[] b = FileBytes;
        for (int back = 0; back < maxBack; back++)
        {
            int p = (int)fileOff - back;
            if (p < (int)TextSection.RawOffset + 1) break;
            // Look for prologue patterns
            if (b[p] == 0x55 && p + 2 < b.Length && b[p + 1] == 0x8B && b[p + 2] == 0xEC)
            {
                // Confirm it's actually a function start: previous byte should be CC, C3, C2, or section padding
                if (p > 0 && (b[p - 1] == 0xCC || b[p - 1] == 0xC3 || b[p - 1] == 0x90))
                    return FileOffToVa((uint)p);
            }
            if (b[p] == 0x8B && p + 1 < b.Length && b[p + 1] == 0xFF)
            {
                if (p > 0 && (b[p - 1] == 0xCC || b[p - 1] == 0xC3 || b[p - 1] == 0x90))
                    return FileOffToVa((uint)p);
            }
        }
        return 0;
    }

    public static void Main(string[] args)
    {
        string exePath = @"C:\Program Files (x86)\Steam\steamapps\common\Skyrim\TESV.exe.unpacked.exe";
        string outPath = @"C:\Users\nro\Desktop\Skyrim-rendering-overdrive\scripts\callers_report.txt";
        if (args.Length >= 1) exePath = args[0];
        if (args.Length >= 2) outPath = args[1];

        Console.WriteLine("Loading " + exePath);
        Load(exePath);
        Console.WriteLine(string.Format("ImageBase=0x{0:X8}  .text VA=0x{1:X8}  size=0x{2:X}",
            ImageBase, ImageBase + TextSection.VirtualAddress, TextSection.VirtualSize));

        uint[] hotSubs = new uint[] { 0xCB7E80, 0xCA2610, 0xB06250 };
        uint[] vtableStarts = new uint[] { 0x01156B70, 0x01154A8C };
        // Constructors / dtors (places where vtable is written into object) +
        // the two non-vtable callers of B06250 we found in the first pass.
        uint[] interestingFuncs = new uint[] { 0xCB7224, 0xCB877E, 0xCAD9CE, 0xCCCF71 };

        Console.WriteLine("Scanning E8 callers of hot subs ...");
        var e8 = ScanE8Callers(hotSubs);
        Console.WriteLine("  " + e8.Count + " E8 hits");

        Console.WriteLine("Scanning literal-VA refs to vtable starts ...");
        var lit = ScanLiteralVas(vtableStarts);
        Console.WriteLine("  " + lit.Count + " literal hits");

        Console.WriteLine("Scanning E8 callers of interesting funcs ...");
        var e8b = ScanE8Callers(interestingFuncs);
        Console.WriteLine("  " + e8b.Count + " hits");

        // Walk back from the literal-load sites to find their containing
        // function (likely constructor / dtor of the class).
        Console.WriteLine("Resolving constructors via literal-load -> containing func ...");
        var ctorStarts = new List<uint>();
        foreach (var h in lit)
        {
            string[] parts = h.Split(',');
            uint atVa = uint.Parse(parts[1], System.Globalization.NumberStyles.HexNumber);
            uint funcStart = FindContainingFunc(atVa, 0x4000);
            if (funcStart != 0 && !ctorStarts.Contains(funcStart))
                ctorStarts.Add(funcStart);
            Console.WriteLine(string.Format("  literal@0x{0:X8} -> containing func 0x{1:X8}", atVa, funcStart));
        }

        Console.WriteLine("Scanning E8 callers of resolved constructors ...");
        var e8c = ScanE8Callers(ctorStarts.ToArray());
        Console.WriteLine("  " + e8c.Count + " hits");

        // Also check what 0x005EADD0 (the placeholder) and 0x00707866 (slot 0
        // of vtable_1154A8C) actually do — read the first few bytes.
        Console.WriteLine("Inspecting placeholder funcs ...");

        var sb = new StringBuilder();
        sb.AppendLine("# TESV.exe.unpacked.exe — caller analysis");
        sb.AppendLine("# Generated by FindCallers.exe");
        sb.AppendLine(string.Format("# ImageBase=0x{0:X8}", ImageBase));
        sb.AppendLine("");
        sb.AppendLine("=== Direct E8 callers of hot subs ===");
        sb.AppendLine("# Format: callerVa,targetVa");
        foreach (var h in e8) sb.AppendLine(h);
        sb.AppendLine("");
        sb.AppendLine("# Total: " + e8.Count);
        sb.AppendLine("");
        sb.AppendLine("=== E8 hits — containing-function heuristic ===");
        sb.AppendLine("# Walks back from each caller to find the prologue (55 8B EC / 8B FF preceded by CC/C3/90).");
        foreach (var h in e8)
        {
            string[] parts = h.Split(',');
            uint callerVa = uint.Parse(parts[0], System.Globalization.NumberStyles.HexNumber);
            uint targetVa = uint.Parse(parts[1], System.Globalization.NumberStyles.HexNumber);
            uint funcStart = FindContainingFunc(callerVa, 0x4000);
            sb.AppendLine(string.Format("  caller=0x{0:X8} -> target=sub_{1:X}  containing_func~=0x{2:X8}",
                callerVa, targetVa, funcStart));
        }
        sb.AppendLine("");
        sb.AppendLine("=== Literal-VA refs to vtable starts ===");
        sb.AppendLine("# Format: fileOff,atVa,literalValue,section");
        foreach (var h in lit) sb.AppendLine(h);
        sb.AppendLine("");
        sb.AppendLine("=== E8 callers of interesting funcs (constructors + B06250-callers) ===");
        sb.AppendLine("# Format: callerVa,targetVa");
        foreach (var h in e8b) sb.AppendLine(h);
        sb.AppendLine("");
        sb.AppendLine("# Total: " + e8b.Count);
        sb.AppendLine("");
        sb.AppendLine("=== Resolved constructor / dtor function starts (from literal walk-back) ===");
        foreach (var c in ctorStarts) sb.AppendLine(string.Format("  0x{0:X8}", c));
        sb.AppendLine("");
        sb.AppendLine("=== E8 callers of those constructor / dtor functions ===");
        sb.AppendLine("# Format: callerVa,targetVa");
        foreach (var h in e8c) sb.AppendLine(h);
        sb.AppendLine("");
        sb.AppendLine("# Total: " + e8c.Count);
        sb.AppendLine("");
        sb.AppendLine("=== Function end addresses (for EIP-sampling profiler bounds) ===");
        foreach (uint funcStart in new uint[] { 0x00CB7E80, 0x00CA2610, 0x00B06250 })
        {
            uint endVa = FindFuncEnd(funcStart, 0x4000);
            uint sz = endVa > funcStart ? endVa - funcStart : 0;
            sb.AppendLine(string.Format("  sub_{0:X}  start=0x{0:X8}  end=0x{1:X8}  size=0x{2:X} ({2} bytes)",
                funcStart, endVa, sz));
        }
        sb.AppendLine("");
        sb.AppendLine("=== First 16 bytes of 0x005EADD0 (vtable placeholder candidate) ===");
        {
            uint va = 0x005EADD0;
            uint off = (va - ImageBase) + 0; // placeholder
            // Use VaToFile via section walk
            uint rva2 = va - ImageBase;
            foreach (var s in Sections)
            {
                if (rva2 >= s.VirtualAddress && rva2 < s.VirtualAddress + s.VirtualSize)
                {
                    uint fo = s.RawOffset + (rva2 - s.VirtualAddress);
                    var hex = new StringBuilder();
                    for (int i = 0; i < 16; i++) hex.AppendFormat("{0:X2} ", FileBytes[fo + i]);
                    sb.AppendLine("  bytes: " + hex.ToString().Trim());
                    break;
                }
            }
        }
        sb.AppendLine("");
        sb.AppendLine("=== First 16 bytes of 0x00707866 (slot 0 of vtable_1154A8C — unusual!) ===");
        {
            uint va = 0x00707866;
            uint rva2 = va - ImageBase;
            foreach (var s in Sections)
            {
                if (rva2 >= s.VirtualAddress && rva2 < s.VirtualAddress + s.VirtualSize)
                {
                    uint fo = s.RawOffset + (rva2 - s.VirtualAddress);
                    var hex = new StringBuilder();
                    for (int i = 0; i < 16; i++) hex.AppendFormat("{0:X2} ", FileBytes[fo + i]);
                    sb.AppendLine("  bytes: " + hex.ToString().Trim());
                    break;
                }
            }
        }
        sb.AppendLine("");
        sb.AppendLine("=== Vtable @ 0x01156B70 (slot 25 = sub_CB7E80) ===");
        foreach (var ln in DumpVtableSlots(0x01156B70, 32)) sb.AppendLine(ln);
        sb.AppendLine("");
        sb.AppendLine("=== Vtable @ 0x01154A8C (slot 26 = sub_CA2610) ===");
        foreach (var ln in DumpVtableSlots(0x01154A8C, 33)) sb.AppendLine(ln);

        File.WriteAllText(outPath, sb.ToString());
        Console.WriteLine("Done. Report at: " + outPath);
    }
}
