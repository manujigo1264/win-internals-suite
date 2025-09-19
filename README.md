# Win Internals Suite

[![Language: C++17](https://img.shields.io/badge/language-C++17-blue.svg)](https://en.cppreference.com/w/)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://learn.microsoft.com/en-us/windows/win32/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A compact **Windows internals utility** written in modern C++ (C++17).  
It enumerates processes and modules using native APIs (`ToolHelp32`, **PSAPI**) and computes SHA-256 hashes with **BCrypt** — all in a single, auditable source file with **no third-party dependencies**.

> Perfect for **learning**, **triage**, or as a **clean reference implementation**.

---

## 📑 Table of Contents
- [Features](#-features)
- [Requirements](#-requirements)
- [Build](#-build)
  - [Visual Studio (recommended)](#visual-studio-recommended)
  - [MSVC command line](#msvc-command-line)
  - [MinGW-w64 (experimental)](#mingw-w64-experimental)
- [Usage](#-usage)
- [Example Output](#-example-output)
- [Design Notes](#-design-notes)
- [Roadmap](#-roadmap)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features
- 🔍 **Process enumeration**: PID, image name, parent PID, session, etc.
- 📦 **Module enumeration**: per process (base address, size, full path).
- 🔐 **Optional SHA-256 hashing**: module images via **BCrypt**.
- 📄 **Single-file** implementation: easy to read, diff, and reuse.
- 🛠 **No external libraries** beyond Windows SDK libs: `Psapi.lib`, `Bcrypt.lib`.

---

## 🖥 Requirements
- Windows 10 / 11 with Windows SDK
- **C++17** (or newer)
- Linker dependencies: `Psapi.lib`, `Bcrypt.lib`
- Recommended: x64 build target

---

## ⚙ Build

### Visual Studio (recommended)
1. Open the repo folder in **Visual Studio 2022**  
   - *File → Open → Folder…* or open the `.sln`.
2. Add `winsuite.cpp` to your project if not already present.
3. Set C++ language standard: **C++17** (or newer).
4. Linker → Input → Additional Dependencies:  
   `Psapi.lib;Bcrypt.lib;` (plus defaults).
5. Build in **Release / x64** configuration.
6. Build: `Ctrl + Shift + B`.

### MSVC command line
```powershell
cl /std:c++17 /EHsc /W4 /nologo winsuite.cpp Psapi.lib Bcrypt.lib
```

### MinGW-w64 (experimental)
Make sure `psapi` and `bcrypt` headers/libs are available.
```bash
g++ -std=c++17 -O2 -Wall winsuite.cpp -lpsapi -lbcrypt -o winsuite.exe
```

---

## ▶ Usage
Run from either a standard or elevated terminal.  
(Some processes require elevation for full visibility.)

```powershell
winsuite.exe
```

**Default behavior**:
- Lists processes.
- For each accessible process, lists loaded modules.
- If hashing is enabled, prints SHA-256 for each module image.

> Future flags (planned):  
> `--pid <PID>` (filter), `--no-hash` (skip hashing), `--json` / `--csv` (structured output)

---

## 📝 Example Output
```
PID   PPID  Name               Session  Arch   Modules
----  ----  -----------------  -------  -----  --------------------------------------------
0048  0000  System             0        x64    (kernel modules not listed)
1056  0048  smss.exe           0        x64    C:\Windows\System32\smss.exe
3420  7168  explorer.exe       1        x64    C:\Windows\Explorer.EXE
                                              C:\Windows\System32\user32.dll  SHA256: 9F...
                                              C:\Windows\System32\gdi32.dll   SHA256: A1...
```

---

## 🛠 Design Notes
- **Discovery path**: `CreateToolhelp32Snapshot` + `PROCESSENTRY32` / `MODULEENTRY32` → dependency-free and simple.
- **Metadata normalization**: PSAPI helps keep sizes/paths consistent across OS versions.
- **Crypto**: Uses BCrypt (`BCryptOpenAlgorithmProvider`, `BCryptHashData`, `BCryptFinishHash`) instead of bundling hashing code.

---

## 🚀 Roadmap
- [ ] CLI flags: PID filter, output formats, hashing toggle  
- [ ] JSON / CSV emitters  
- [ ] WOW64 / bitness refinements  
- [ ] Better handling for protected processes  
- [ ] Optional **CMake** build system  
- [ ] Unit tests for hashing & formatting  

---

## ❗ Troubleshooting
- **Access denied / missing modules** → run from an **elevated console**.  
- **Unresolved externals** → confirm `Psapi.lib` and `Bcrypt.lib` are linked.  
- **AV/EDR alerts** → process/module enumeration and hashing may be flagged by security software; expect partial results in hardened environments.

---

## 🤝 Contributing
Pull requests are welcome!  
Please keep changes **small, focused, and well-commented** to preserve the single-file ethos.

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
