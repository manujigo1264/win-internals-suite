#include "ui_helpers.h"
#include <iostream>
#include <iomanip>

void print_banner() {
    std::wcout << L"\n";
    std::wcout << L"======== WinSuite Security Toolkit ========\n";
    std::wcout << L"   Advanced Windows Internals Analysis\n";
    std::wcout << L"==========================================\n\n";
}

void usage() {
    print_banner();
    std::cout <<
        "USAGE: winsuite <command> [options]\n\n"
        "PROCESS ANALYSIS:\n"
        "  ps                       List all running processes\n"
        "  ps-enhanced [filter]     Enhanced process listing with filtering\n"
        "  mods <pid>               List modules loaded by process\n"
        "  mods-enhanced <pid>      Detailed module analysis\n\n"
        "FILE ANALYSIS:\n"
        "  pe <path>                Parse PE file structure\n"
        "  scan <path>              Basic malware signature scan\n"
        "  scan-enhanced <path>     Advanced threat detection\n"
        "  batch-scan <dir>         Scan directory recursively\n\n"
        "OPTIONS:\n"
        "  -v, --verbose            Verbose output\n"
        "  --json                   JSON output format\n"
        "  --no-color               Disable colored output\n"
        "  -o <file>                Output to file\n\n"
        "EXAMPLES:\n"
        "  winsuite ps-enhanced chrome\n"
        "  winsuite scan-enhanced malware.exe\n"
        "  winsuite mods 1234\n"
        "  winsuite --json scan suspicious.dll\n\n"
        "Run without arguments for interactive mode.\n\n";
}

void ProgressIndicator::show_scanning(const std::wstring& filename) {
    std::wcout << L"[SCANNING] " << filename << L" ... ";
    std::wcout.flush();
}

void ProgressIndicator::show_complete(bool success) {
    if (success) {
        std::wcout << L"✓ COMPLETE\n";
    }
    else {
        std::wcout << L"✗ FAILED\n";
    }
}

void ProgressIndicator::show_progress(size_t current, size_t total) {
    if (total == 0) return;

    int percent = static_cast<int>((current * 100) / total);
    std::wcout << L"\rProgress: [";

    int bars = percent / 5;
    for (int i = 0; i < 20; i++) {
        if (i < bars) {
            std::wcout << L"█";
        }
        else {
            std::wcout << L"░";
        }
    }

    std::wcout << L"] " << std::setw(3) << percent << L"% ("
        << current << L"/" << total << L")";
    std::wcout.flush();
}

void ProgressIndicator::clear_line() {
    std::wcout << L"\r" << std::wstring(80, L' ') << L"\r";
    std::wcout.flush();
}