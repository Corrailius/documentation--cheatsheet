# The Windows .exe Format

> **How to read this document:** Every major section opens with a short **"In plain English"** box. Read those if you're new to this and just want the idea, no jargon. Everything below the box is the full technical reference — structs, byte offsets, flag tables — for people who need to actually parse or build these files. Skip nothing if you're a beginner trying to *become* an expert; the plain-English boxes are a ramp, not a replacement.

---

## Table of Contents

1. [Start Here: What Even Is an .exe?](#start-here-what-even-is-an-exe)
2. [History & Evolution](#history--evolution)
3. [The PE (Portable Executable) Format](#the-pe-portable-executable-format)
4. [File Structure in Detail](#file-structure-in-detail)
   - [DOS Header (MZ Header)](#1-dos-header-mz-header)
   - [DOS Stub](#2-dos-stub)
   - [PE Signature](#3-pe-signature)
   - [COFF File Header](#4-coff-file-header)
   - [Optional Header](#5-optional-header)
   - [Section Table](#6-section-table)
   - [Sections (Raw Data)](#7-sections-raw-data)
5. [Magic Bytes & Markers](#magic-bytes--markers)
6. [Standard Sections Reference](#standard-sections-reference)
7. [Data Directories](#data-directories)
8. [How Windows Loads an .exe](#how-windows-loads-an-exe)
9. [Creating an .exe](#creating-an-exe)
   - [From C/C++ (MSVC)](#from-cc-msvc)
   - [From C/C++ (MinGW/GCC)](#from-cc-mingwgcc)
   - [From C# (.NET)](#from-c-net)
   - [From Rust](#from-rust)
   - [From Python (PyInstaller)](#from-python-pyinstaller)
   - [From Assembly (NASM)](#from-assembly-nasm)
10. [Inspecting an .exe](#inspecting-an-exe)
11. [PE Variants](#pe-variants)
12. [Security Features](#security-features)
13. [Common Pitfalls & Notes](#common-pitfalls--notes)
14. [Glossary](#glossary)

---

## Start Here: What Even Is an .exe?

> **In plain English:** Double-clicking an `.exe` doesn't run "code" directly — it runs a very specific, very rigid file layout that Windows knows how to read. That layout is called **PE (Portable Executable)**. Think of a `.exe` like a shipping container arriving at a port: before the crane (Windows) can unload it, there's a stack of paperwork stapled to the front telling the dock workers what's inside, where each crate goes, and which crates are fragile (executable) vs. just cargo (data). This document walks through that paperwork, crate by crate.

A `.exe` file is the standard binary format for programs on Windows. Opening one causes the operating system to load it into memory and begin executing its machine code. Under the hood, virtually all modern `.exe` files use the **PE (Portable Executable)** format, a direct descendant of the older COFF (Common Object File Format) from Unix.

The same PE format is shared by several file types you've probably seen without realizing they're all the same skeleton underneath:

| Extension | What it is | Plain-English version |
|---|---|---|
| `.exe` | Standalone executable | The program itself |
| `.dll` | Dynamic-link library | Shared code other programs borrow from |
| `.sys` | Kernel driver | Code that talks directly to hardware |
| `.scr` | Screensaver | Literally just a renamed `.exe` |
| `.ocx`, `.cpl`, `.efi` | Specialized executables | ActiveX controls, Control Panel items, firmware apps |

**Why would a non-developer ever care?** A few real reasons this knowledge is useful even if you don't write code:
- Understanding why antivirus software flags certain files (packed/obfuscated PE sections are a major red flag).
- Knowing what "this app isn't digitally signed" warnings actually mean (Section [Security Features](#security-features)).
- Curiosity about that cryptic "This program cannot be run in DOS mode" message — you'll see exactly where that text lives in a few sections.

---

## History & Evolution

> **In plain English:** Windows has been backward-compatible with itself for over 40 years, and the `.exe` format is the proof. Every new format kept a tiny fossil of the old one bolted to the front, so even a `.exe` built today still technically "knows" how to talk to a 1981 computer.

| Era | Format | Notes |
|-----|--------|-------|
| MS-DOS (1981–1990) | **MZ** | Simple segmented format, named after Mark Zbikowski |
| Windows 3.x (1990–1995) | **NE** (New Executable) | Added resources, imports; 16-bit |
| Windows 9x / NT (1993+) | **PE** (Portable Executable) | 32-bit; still the basis of modern executables |
| Windows XP 64-bit+ | **PE32+** (also called PE64) | 64-bit variant of PE |
| Modern Windows | **PE32 / PE32+** | Same format, extended with security features |

The MZ header is still present in every modern `.exe` as a compatibility fossil — it contains a tiny 16-bit program that prints "This program cannot be run in DOS mode." That's the line, and now you know exactly why it's there: it's a leftover safety net from 1981, still riding along in every Windows program built in 2026.

---

## The PE (Portable Executable) Format

> **In plain English:** "Portable" here doesn't mean "small" or "easy to copy" — it means the format was designed to work across *different CPU types* (the original goal was x86, MIPS, Alpha, and PowerPC all sharing one file layout). The diagram below is the floor plan of every `.exe` on your computer, top to bottom, in the exact order bytes appear on disk.

The PE format was introduced with Windows NT 3.1 in 1993, designed by Microsoft in collaboration with DEC. It was meant to be portable across CPU architectures (x86, MIPS, Alpha, PowerPC, ARM) — which is why it's called "Portable."

The overall memory layout looks like this:

```
┌───────────────────────────────┐  Offset 0x00
│        DOS Header (MZ)        │  64 bytes
├───────────────────────────────┤
│          DOS Stub             │  Variable (usually ~64 bytes)
├───────────────────────────────┤
│        PE Signature           │  4 bytes ("PE\0\0")
├───────────────────────────────┤
│       COFF File Header        │  20 bytes
├───────────────────────────────┤
│       Optional Header         │  96 bytes (PE32) / 112 bytes (PE32+)
│   + Data Directory Entries    │  + 128 bytes (16 × 8-byte entries)
├───────────────────────────────┤
│        Section Table          │  N × 40 bytes
├───────────────────────────────┤
│    Section 1 Raw Data (.text) │
├───────────────────────────────┤
│    Section 2 Raw Data (.data) │
├───────────────────────────────┤
│           ...                 │
└───────────────────────────────┘
```

Read top to bottom: first comes a fossil from 1981 (DOS header + stub), then the "yes, this is really a PE file" stamp, then two headers describing the whole program, then a table of contents for the actual content, then the content itself.

---

## File Structure in Detail

### 1. DOS Header (MZ Header)

> **In plain English:** This is the "return-to-sender" label glued to the front of every `.exe`. Its only modern job is pointing to where the *real* header starts. Everything else in it is vestigial — Windows barely glances at it except for one field.

Located at **offset 0x00**, always 64 bytes. The first two bytes are always `4D 5A` (ASCII: `MZ`) — Mark Zbikowski's initials, the engineer who designed the original format.

```c
typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;      // 0x00 — Magic number: 0x5A4D ("MZ")
    WORD  e_cblp;       // 0x02 — Bytes on last page of file
    WORD  e_cp;         // 0x04 — Pages in file
    WORD  e_crlc;       // 0x06 — Relocations
    WORD  e_cparhdr;    // 0x08 — Size of header in paragraphs
    WORD  e_minalloc;   // 0x0A — Minimum extra paragraphs needed
    WORD  e_maxalloc;   // 0x0C — Maximum extra paragraphs needed
    WORD  e_ss;         // 0x0E — Initial (relative) SS value
    WORD  e_sp;         // 0x10 — Initial SP value
    WORD  e_csum;       // 0x12 — Checksum
    WORD  e_ip;         // 0x14 — Initial IP value
    WORD  e_cs;         // 0x16 — Initial (relative) CS value
    WORD  e_lfarlc;     // 0x18 — File address of relocation table
    WORD  e_ovno;       // 0x1A — Overlay number
    WORD  e_res[4];     // 0x1C — Reserved words
    WORD  e_oemid;      // 0x24 — OEM identifier
    WORD  e_oeminfo;    // 0x26 — OEM information
    WORD  e_res2[10];   // 0x28 — Reserved words
    LONG  e_lfanew;     // 0x3C — *** File offset of the PE header ***
} IMAGE_DOS_HEADER;
```

> **Key field:** `e_lfanew` at offset `0x3C` (byte 60) — this 4-byte value tells you the file offset of the PE header. Always read this first when parsing a PE file. Every other field in this struct exists purely so old DOS could (theoretically) still load the file; modern Windows ignores them.

---

### 2. DOS Stub

> **In plain English:** This is an actual, tiny, working 16-bit program — not just text. If you somehow ran a modern `.exe` on real MS-DOS, this stub is the thing that would actually execute, print the "cannot be run in DOS mode" message, and politely quit.

A tiny 16-bit program that runs if you execute the file from a real DOS environment. It prints the message "This program cannot be run in DOS mode." and exits. You can replace it with a custom stub if needed (some tools do this for branding or to embed extra metadata).

---

### 3. PE Signature

> **In plain English:** A 4-byte stamp of authenticity. After the DOS fossil, this is the moment the file says "okay, the old stuff is over — everything from here is the real, modern format."

Located at `e_lfanew` offset. Always exactly **4 bytes**:

```
50 45 00 00   →  "PE\0\0"
```

---

### 4. COFF File Header

> **In plain English:** The cover page of the shipping manifest. Before you even look at the cargo, this tells you: what kind of forklift you'll need (CPU architecture), how many crates are coming (section count), and when the shipment was packed (timestamp).

Immediately follows the PE signature. **20 bytes**.

```c
typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;              // Target CPU architecture
    WORD  NumberOfSections;     // How many sections follow
    DWORD TimeDateStamp;        // Unix timestamp of when the file was linked
    DWORD PointerToSymbolTable; // Usually 0 in executables
    DWORD NumberOfSymbols;      // Usually 0 in executables
    WORD  SizeOfOptionalHeader; // Size of the Optional Header that follows
    WORD  Characteristics;      // File attribute flags
} IMAGE_FILE_HEADER;
```

#### Machine Values (common):

| Value | Architecture |
|-------|-------------|
| `0x014C` | x86 (32-bit Intel) |
| `0x8664` | x86-64 (AMD64, 64-bit) |
| `0xAA64` | ARM64 (AArch64) |
| `0x01C4` | ARM (Thumb-2) |
| `0x0200` | Intel Itanium (IA-64) |

#### Characteristics Flags:

| Flag | Value | Meaning |
|------|-------|---------|
| `IMAGE_FILE_EXECUTABLE_IMAGE` | `0x0002` | This is a valid executable |
| `IMAGE_FILE_LARGE_ADDRESS_AWARE` | `0x0020` | Can use >2GB address space |
| `IMAGE_FILE_32BIT_MACHINE` | `0x0100` | 32-bit machine |
| `IMAGE_FILE_DLL` | `0x2000` | This is a DLL, not an .exe |
| `IMAGE_FILE_SYSTEM` | `0x1000` | System file (driver) |

---

### 5. Optional Header

> **In plain English:** Despite the name, nothing about this header is actually optional for a runnable program — think of it as "optional" the way a car engine is "optional" equipment on a car (technically a separate part, but you're not driving anywhere without it). This is where the real blueprint lives: where in memory to load the program, which instruction to run first, how much stack/heap to reserve.

This header comes in two flavors:

- **PE32** (32-bit): starts with magic `0x010B`, 96 bytes + data dirs
- **PE32+** (64-bit): starts with magic `0x020B`, 112 bytes + data dirs

```c
// PE32 version (simplified)
typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD  Magic;                    // 0x010B = PE32, 0x020B = PE32+
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;               // Total size of all .text sections
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;      // RVA of first instruction to execute
    DWORD BaseOfCode;               // RVA where .text section begins
    DWORD BaseOfData;               // RVA where .data section begins (PE32 only)
    DWORD ImageBase;                // Preferred load address (usually 0x00400000)
    DWORD SectionAlignment;         // Section alignment in memory (usually 0x1000 = 4KB)
    DWORD FileAlignment;            // Section alignment on disk (usually 0x200 = 512B)
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion;    // Usually 6 (Vista+) or 10
    WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue;        // Reserved, must be 0
    DWORD SizeOfImage;              // Total size of the image in memory
    DWORD SizeOfHeaders;            // Size of all headers (DOS + PE + section table)
    DWORD CheckSum;                 // CRC checksum (only required for drivers)
    WORD  Subsystem;                // Target subsystem (GUI, console, etc.)
    WORD  DllCharacteristics;       // Security feature flags
    DWORD SizeOfStackReserve;       // Virtual stack reservation (default 1MB)
    DWORD SizeOfStackCommit;        // Physical stack commit (default 4KB)
    DWORD SizeOfHeapReserve;        // Virtual heap reservation (default 1MB)
    DWORD SizeOfHeapCommit;         // Physical heap commit (default 4KB)
    DWORD LoaderFlags;              // Obsolete
    DWORD NumberOfRvaAndSizes;      // Number of data directory entries (usually 16)
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER;
```

#### Subsystem Values:

| Value | Name | Description |
|-------|------|-------------|
| `1` | NATIVE | Driver / system component |
| `2` | WINDOWS_GUI | Windows app (no console window) |
| `3` | WINDOWS_CUI | Console application |
| `9` | WINDOWS_CE_GUI | Windows CE |
| `10` | EFI_APPLICATION | UEFI firmware application |

#### DllCharacteristics (Security Flags):

> **In plain English:** This is a short checklist of defensive features the program asks Windows to turn on for it — things like randomizing where it loads in memory (harder for attackers to predict) or refusing to ever execute the stack (harder for a buffer overflow to hijack it).

| Flag | Value | Description |
|------|-------|-------------|
| `DYNAMIC_BASE` | `0x0040` | ASLR: image can be relocated at load time |
| `FORCE_INTEGRITY` | `0x0080` | Enforce code integrity check |
| `NX_COMPAT` | `0x0100` | DEP/NX compatible (no-execute stack) |
| `NO_ISOLATION` | `0x0200` | Do not use isolation |
| `NO_SEH` | `0x0400` | No structured exception handling |
| `NO_BIND` | `0x0800` | Do not bind the image |
| `WDM_DRIVER` | `0x2000` | WDM (driver model) driver |
| `GUARD_CF` | `0x4000` | Control Flow Guard enabled |
| `TERMINAL_SERVER_AWARE` | `0x8000` | TS / Remote Desktop compatible |

---

### 6. Section Table

> **In plain English:** A table of contents for the actual cargo. Each row says: here's a chunk of data, here's its name (`.text`, `.data`, etc.), here's where it lives on disk, and here's where it should be placed in memory once loaded.

An array of **40-byte** section headers, one per section. The number of entries equals `NumberOfSections` from the COFF header.

```c
typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[8];               // Section name (e.g., ".text\0\0\0"), NOT null-terminated if 8 chars
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;       // Actual used size in memory
    } Misc;
    DWORD VirtualAddress;        // RVA of section start in memory
    DWORD SizeOfRawData;         // Size on disk (multiple of FileAlignment)
    DWORD PointerToRawData;      // File offset of section data
    DWORD PointerToRelocations;  // Unused in executables (0)
    DWORD PointerToLinenumbers;  // Deprecated (0)
    WORD  NumberOfRelocations;   // Unused in executables (0)
    WORD  NumberOfLinenumbers;   // Deprecated (0)
    DWORD Characteristics;       // Section flags (read/write/execute/etc.)
} IMAGE_SECTION_HEADER;
```

#### Section Characteristics Flags:

| Flag | Value | Meaning |
|------|-------|---------|
| `IMAGE_SCN_CNT_CODE` | `0x00000020` | Contains executable code |
| `IMAGE_SCN_CNT_INITIALIZED_DATA` | `0x00000040` | Contains initialized data |
| `IMAGE_SCN_CNT_UNINITIALIZED_DATA` | `0x00000080` | Contains uninitialized data (BSS) |
| `IMAGE_SCN_MEM_DISCARDABLE` | `0x02000000` | Can be discarded after load |
| `IMAGE_SCN_MEM_NOT_CACHED` | `0x04000000` | Cannot be cached |
| `IMAGE_SCN_MEM_NOT_PAGED` | `0x08000000` | Cannot be paged |
| `IMAGE_SCN_MEM_SHARED` | `0x10000000` | Shared between processes |
| `IMAGE_SCN_MEM_EXECUTE` | `0x20000000` | Executable (CPU can run this) |
| `IMAGE_SCN_MEM_READ` | `0x40000000` | Readable |
| `IMAGE_SCN_MEM_WRITE` | `0x80000000` | Writable |

Common combinations:
- `.text`: `0x60000020` (code + execute + read)
- `.data`: `0xC0000040` (initialized data + read + write)
- `.rdata`: `0x40000040` (initialized data + read only)
- `.bss`: `0xC0000080` (uninitialized data + read + write)

---

### 7. Sections (Raw Data)

> **In plain English:** Finally, the actual cargo — not paperwork about the cargo, but the bytes themselves: the compiled instructions, the strings in your program, the icon, the version info.

The actual binary content of each section, stored sequentially. Each section starts at its `PointerToRawData` offset (aligned to `FileAlignment`).

---

## Magic Bytes & Markers

> **In plain English:** "Magic bytes" are fixed, predictable byte sequences that act like a fingerprint — a tool can look at the first two bytes of *any* file and instantly know "this claims to be a Windows executable," without trusting the file extension at all (file extensions are just a label anyone can change; magic bytes are baked into the content).

These are the byte sequences that identify and delimit a PE file:

| Location | Bytes (hex) | ASCII | Purpose |
|----------|-------------|-------|---------|
| Offset 0x00 | `4D 5A` | `MZ` | DOS magic — start of any PE file |
| Offset e_lfanew | `50 45 00 00` | `PE\0\0` | PE signature |
| Optional Header | `0B 01` | — | PE32 (32-bit) magic |
| Optional Header | `0B 02` | — | PE32+ (64-bit) magic |
| Optional Header | `07 01` | — | ROM image magic (rare) |
| Rich Header | `52 69 63 68` | `Rich` | End marker of the undocumented Rich header (MSVC linker metadata) |
| Rich Header (start) | `44 61 6E 53` XOR key | `DanS` (XOR'd) | Start of Rich header (after decoding) |

### The Rich Header (Undocumented)

> **In plain English:** A hidden, undocumented Easter egg Microsoft's compiler quietly tucks into every binary it builds. It's basically a fingerprint of exactly which compiler version, which linker, and which build tools touched the file — useful for security researchers trying to figure out who (or what toolchain) built a suspicious file.

MSVC-compiled binaries contain a hidden block between the DOS stub and the PE signature called the **Rich header**. It records which compiler tools and versions were used to build the binary — useful for forensics and malware attribution.

```
[DOS Header]
[DOS Stub]
[DanS marker (XOR-obfuscated)] ← Rich header start
[tool version entries...]
[Rich marker: "Rich" + 4-byte XOR key] ← Rich header end
[PE Signature: "PE\0\0"]
```

---

## Standard Sections Reference

> **In plain English:** Sections are the "rooms" inside the building. Each one has a consistent purpose across virtually every Windows program ever compiled — once you learn what `.text` and `.rsrc` mean here, you'll recognize them in any PE file you ever open.

| Name | Typical Flags | Contents |
|------|--------------|----------|
| `.text` | r-x | Machine code (compiled functions) |
| `.data` | rw- | Initialized global and static variables |
| `.rdata` | r-- | Read-only data: string literals, const globals, debug info |
| `.bss` | rw- | Uninitialized globals (zero-filled at load; may have no raw data) |
| `.idata` | r-- | Import tables (which DLLs/functions are needed) |
| `.edata` | r-- | Export tables (functions this binary exposes, mainly for DLLs) |
| `.reloc` | r-- | Base relocation table (for ASLR) |
| `.rsrc` | r-- | Resources: icons, strings, dialogs, manifests, version info |
| `.pdata` | r-- | Exception handling data (64-bit and RISC) |
| `.xdata` | r-- | Unwind information for exceptions |
| `.tls` | rw- | Thread Local Storage data |
| `.debug` | r-- | Debug info (usually stripped from release builds) |
| `.sxdata` | r-- | Safe exception handler table |
| `UPX0`/`UPX1` | rwx | Sections from the UPX packer |
| `.netsect` | r-- | .NET metadata (CLR header, MSIL/CIL bytecode) |

---

## Data Directories

> **In plain English:** If the Section Table is the table of contents for the *building*, Data Directories are sticky notes pointing to specific *rooms within rooms* — "the imports are exactly here," "the digital signature is exactly there." Sixteen fixed slots, most either used or left empty depending on what the program needs.

The Optional Header ends with 16 **Data Directory** entries. Each is 8 bytes: a 4-byte RVA and a 4-byte size. They point to important structures within the sections.

| Index | Name | Description |
|-------|------|-------------|
| 0 | Export Table | `.edata` — functions exported by this image |
| 1 | Import Table | `.idata` — DLLs and functions this image imports |
| 2 | Resource Table | `.rsrc` — embedded resources |
| 3 | Exception Table | `.pdata` — exception handler info |
| 4 | Certificate Table | Authenticode digital signature |
| 5 | Base Relocation Table | `.reloc` — addresses to patch on rebase |
| 6 | Debug | Debug information |
| 7 | Architecture | Reserved |
| 8 | Global Ptr | RVA of global pointer register value |
| 9 | TLS Table | Thread Local Storage descriptors |
| 10 | Load Config Table | Loader-specific configuration (CFG, safe SEH, etc.) |
| 11 | Bound Import | Pre-resolved import addresses (legacy) |
| 12 | IAT | Import Address Table (filled by loader) |
| 13 | Delay Import Descriptor | Lazily-loaded imports |
| 14 | CLR Runtime Header | .NET / CLR metadata pointer |
| 15 | Reserved | Must be zero |

---

## How Windows Loads an .exe

> **In plain English:** This is the story version of everything above — what actually happens, in order, the instant you double-click a program. Every step below uses a piece of the file structure you just read about.

1. **Shell / CreateProcess**: A process calls `CreateProcess()` or the shell invokes it.
2. **Open file**: The kernel opens the file and maps it into a section object.
3. **Validate**: Checks for `MZ` magic, reads `e_lfanew`, checks for `PE\0\0`.
4. **Map image**: Maps each section into virtual memory at `ImageBase` (or a new random address if ASLR is enabled).
5. **Apply relocations**: If the image was loaded at a different address than `ImageBase`, the `.reloc` section is used to patch absolute addresses.
6. **Resolve imports**: The loader reads `.idata`, loads required DLLs, and fills in the IAT (Import Address Table) with actual function addresses.
7. **TLS callbacks**: Any Thread Local Storage initializers are called.
8. **Entry point**: Execution jumps to `AddressOfEntryPoint`. For MSVC programs, this is the CRT startup code, which eventually calls your `main()` or `WinMain()`.

---

## Creating an .exe

> **In plain English:** This section is a quick cookbook — one recipe per programming language — showing the minimum commands needed to turn source code into a working `.exe`. If you've never compiled anything before, picking any one of these and running it is the fastest way to see everything above turn into a real file you can open in a hex editor.

### From C/C++ (MSVC)

```cmd
:: Compile a simple console app
cl.exe hello.c /Fe:hello.exe

:: With optimization and no debug info
cl.exe /O2 /GL hello.c /link /LTCG /OUT:hello.exe

:: GUI application (no console window)
cl.exe hello.c /link /SUBSYSTEM:WINDOWS /OUT:hello.exe
```

Using CMake:
```cmake
cmake_minimum_required(VERSION 3.20)
project(MyApp)
add_executable(MyApp main.cpp)
set_target_properties(MyApp PROPERTIES WIN32_EXECUTABLE TRUE) # GUI mode
```

### From C/C++ (MinGW/GCC)

```bash
# 32-bit
i686-w64-mingw32-gcc hello.c -o hello.exe

# 64-bit
x86_64-w64-mingw32-gcc hello.c -o hello.exe

# Static linking (self-contained, no MinGW DLLs needed)
x86_64-w64-mingw32-gcc hello.c -o hello.exe -static

# GUI subsystem
x86_64-w64-mingw32-gcc hello.c -o hello.exe -mwindows
```

### From C# (.NET)

```csharp
// hello.cs
using System;
class Program {
    static void Main() => Console.WriteLine("Hello, World!");
}
```

```cmd
:: .NET Framework (csc.exe)
csc.exe hello.cs /out:hello.exe

:: .NET 6+ (dotnet CLI)
dotnet new console -n MyApp
dotnet publish -c Release -r win-x64 --self-contained true
```

The resulting `.exe` has a CLR header in the PE and contains CIL bytecode, not native machine code (unless compiled with Native AOT).

### From Rust

```toml
# Cargo.toml
[package]
name = "hello"
version = "0.1.0"
edition = "2021"
```

```bash
cargo build --release --target x86_64-pc-windows-gnu
# Output: target/x86_64-pc-windows-gnu/release/hello.exe
```

### From Python (PyInstaller)

```bash
pip install pyinstaller

# Single-file exe (bundles interpreter + all dependencies)
pyinstaller --onefile hello.py

# GUI app (no console window)
pyinstaller --onefile --windowed hello.py

# Custom icon
pyinstaller --onefile --icon=app.ico hello.py
```

Output is in `dist/hello.exe`. Note: this bundles a full Python interpreter, so files can be 20–60MB — much larger than the C/C++ examples above, because there's an entire language runtime riding along inside the PE sections.

### From Assembly (NASM)

For a minimal hand-crafted 64-bit Windows console executable — this is about as close as you can get to writing the bytes by hand:

```nasm
; hello.asm
bits 64
default rel

section .data
    msg db "Hello, World!", 13, 10, 0
    msg_len equ $ - msg

section .text
    global main
    extern ExitProcess
    extern GetStdHandle
    extern WriteConsoleA

main:
    ; Get STDOUT handle
    mov rcx, -11          ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov rbx, rax

    ; Write to console
    mov rcx, rbx
    lea rdx, [msg]
    mov r8, msg_len
    lea r9, [rsp+32]
    push 0
    sub rsp, 40
    call WriteConsoleA
    add rsp, 48

    ; Exit
    xor rcx, rcx
    call ExitProcess
```

```bash
nasm -f win64 hello.asm -o hello.obj
link hello.obj kernel32.lib /entry:main /subsystem:console /out:hello.exe
```

---

## Inspecting an .exe

> **In plain English:** You don't need to write code to look inside one of these files — there are free GUI tools that just show you the headers and sections as a navigable tree, no hex math required.

### Built-in Windows Tools

```cmd
:: Check if a file is a valid PE and show subsystem
dumpbin /headers hello.exe

:: List imported DLLs and functions
dumpbin /imports hello.exe

:: List exported functions (for DLLs)
dumpbin /exports hello.dll

:: Disassemble the .text section
dumpbin /disasm hello.exe
```

### Free Third-Party Tools

| Tool | Use |
|------|-----|
| [PE-bear](https://github.com/hasherezade/pe-bear) | GUI PE viewer/editor |
| [CFF Explorer](https://ntcore.com/?page_id=388) | Full PE editor with hex view |
| [x64dbg](https://x64dbg.com/) | Dynamic debugger |
| [Ghidra](https://ghidra-sre.org/) | Full decompiler (NSA, free) |
| [IDA Free](https://hex-rays.com/ida-free/) | Disassembler / decompiler |
| [Detect-It-Easy (DiE)](https://github.com/horsicq/Detect-It-Easy) | Packer/compiler detection |
| [pestudio](https://www.winitor.com/) | Malware static analysis |

### Python (with `pefile`)

```python
import pefile

pe = pefile.PE("hello.exe")

print(f"Machine:       {hex(pe.FILE_HEADER.Machine)}")
print(f"Subsystem:     {pe.OPTIONAL_HEADER.Subsystem}")
print(f"Entry point:   {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
print(f"Image base:    {hex(pe.OPTIONAL_HEADER.ImageBase)}")
print(f"Sections:      {pe.FILE_HEADER.NumberOfSections}")

for section in pe.sections:
    name = section.Name.decode(errors='replace').strip('\x00')
    print(f"  {name:10s} VA={hex(section.VirtualAddress)} Size={section.Misc_VirtualSize}")

print("\nImports:")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f"  {entry.dll.decode()}")
    for imp in entry.imports:
        print(f"    {imp.name.decode() if imp.name else f'ord({imp.ordinal})'}")
```

---

## PE Variants

> **In plain English:** Not every `.exe` is "just" compiled machine code waiting to run. Some are wrappers around an entirely different runtime (.NET), and some are wrappers around *another, hidden PE file* (packers, often used by both legitimate software and malware to shrink or hide the real payload).

### .NET / CLR Executables

Managed code (C#, VB.NET, F#) produces a PE with:
- A valid native entry point that calls `mscoree.dll!_CorExeMain`
- Data directory entry 14 pointing to the **CLR header** (`IMAGE_COR20_HEADER`)
- The `.text` section containing CIL (Common Intermediate Language) bytecode
- A metadata stream describing types, methods, and assemblies

### Packed Executables

Packers like UPX, MPRESS, or Themida wrap the original PE inside another PE:
- The wrapper PE contains a decompression stub in `.text`
- The original PE is stored compressed in a data section (e.g., `UPX1`)
- At runtime, the stub decompresses the original into memory and jumps to it

This is exactly why "packed" is a word that makes antivirus software nervous — a packer hides the real `.text` section from static analysis until the moment the program actually runs.

### 32-bit vs 64-bit

| Feature | PE32 | PE32+ |
|---------|------|-------|
| Magic | `0x010B` | `0x020B` |
| Pointer size | 4 bytes | 8 bytes |
| `ImageBase` | DWORD (4 bytes) | ULONGLONG (8 bytes) |
| Stack/Heap sizes | DWORD | ULONGLONG |
| Default `ImageBase` | `0x00400000` | `0x0000000140000000` |
| `BaseOfData` field | Present | **Absent** |

---

## Security Features

> **In plain English:** Modern `.exe` files come with optional defensive features baked in — like a house that can have an alarm system, reinforced windows, and a deadbolt, none of which are physically required for the house to exist, but all of which make it harder to break into.

| Feature | How to Enable | What it Does |
|---------|--------------|--------------|
| **ASLR** | `/DYNAMICBASE` linker flag | Randomizes load address; requires `.reloc` section |
| **DEP/NX** | `/NXCOMPAT` linker flag | Marks stack/heap as non-executable |
| **SafeSEH** | `/SAFESEH` (x86 only) | Whitelists valid exception handlers |
| **CFG** | `/guard:cf` | Control Flow Guard: limits valid indirect call targets |
| **CET** | `/CETCOMPAT` | Intel CET shadow stack protection |
| **Authenticode** | `signtool.exe` | Embeds a digital signature in the Certificate Table |
| **Manifest** | Embedded resource | Declares UAC level, DPI awareness, OS compatibility |

That last row, **Manifest**, is the technical reason Windows pops up "Do you want to allow this app to make changes to your device?" — the manifest resource literally declares whether the program needs administrator rights.

---

## Common Pitfalls & Notes

> **In plain English:** These are the gotchas that trip up everyone the first time they try to parse or build a PE file by hand — the kind of thing you only learn after your first parser crashes on a real-world file.

- **RVA vs File Offset**: RVA (Relative Virtual Address) is an offset from `ImageBase` in memory. File offset is a raw byte offset in the `.exe` file on disk. These are different because sections are aligned differently in memory vs on disk. Use the section table to convert between them.

- **Alignment**: All sections must start on `FileAlignment` boundaries (disk) and `SectionAlignment` boundaries (memory). Misalignment causes the loader to reject the file.

- **The `SizeOfImage`** must be a multiple of `SectionAlignment` and must cover all sections.

- **TimeDateStamp**: Reproducible builds often zero this out. Malware analysis tools use it for attribution (though it can be forged).

- **Checksum**: Required to be valid only for kernel drivers (`.sys`). User-mode executables can have a zero checksum.

- **Forward exports**: A DLL can forward an export to another DLL. The export table entry contains a string like `"NTDLL.RtlAllocateHeap"` instead of an RVA.

- **Ordinal imports**: An import may reference a function by ordinal number rather than name. The `Name` field will be NULL in `pefile`.

---

## Glossary

> **In plain English:** A one-stop cheat sheet. If you forget what an acronym means anywhere above, it's defined here.

| Term | Definition |
|------|------------|
| **RVA** | Relative Virtual Address — offset from `ImageBase` in memory |
| **VA** | Virtual Address — absolute address in memory (`ImageBase + RVA`) |
| **IAT** | Import Address Table — filled by the loader with actual function addresses |
| **ILT / INT** | Import Lookup Table / Name Table — original import names before patching |
| **PE** | Portable Executable — the file format |
| **COFF** | Common Object File Format — ancestor of PE |
| **MZ** | DOS magic bytes, named after Mark Zbikowski |
| **Subsystem** | Whether the executable is a GUI app, console app, or driver |
| **ASLR** | Address Space Layout Randomization |
| **DEP/NX** | Data Execution Prevention / No-Execute (hardware stack protection) |
| **CFG** | Control Flow Guard |
| **CIL / MSIL** | Common (Intermediate) Language — .NET bytecode |
| **CLR** | Common Language Runtime — the .NET execution engine |
| **UPX** | Universal Packer for eXecutables — popular open-source packer |
| **Stub** | The 16-bit DOS program at the beginning of every .exe |
| **Rich Header** | Undocumented MSVC linker metadata block |
| **TLS** | Thread Local Storage — per-thread variables |
| **Section** | A named block of memory in the PE (`.text`, `.data`, etc.) |
| **FileAlignment** | Granularity of section data on disk (usually 512 bytes) |
| **SectionAlignment** | Granularity of section data in memory (usually 4096 bytes = 1 page) |

---

*Document covers the PE format as defined in the Microsoft PE/COFF Specification and implemented in Windows NT through Windows 11. For the official specification, see [Microsoft PE and COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).*
