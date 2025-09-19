#include "proc_enum.h"
#include "common.h"
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>

// Helper function to convert wide string to narrow string
std::string wstring_to_string(const std::wstring& wstr) {
    std::string result;
    for (wchar_t wc : wstr) {
        if (wc < 128) result += static_cast<char>(wc);
        else result += '?';
    }
    return result;
}

// RAII wrapper for snapshot handles
class SnapshotHandle {
private:
    HANDLE h_;

public:
    explicit SnapshotHandle(DWORD flags, DWORD pid = 0)
        : h_(CreateToolhelp32Snapshot(flags, pid)) {
    }

    ~SnapshotHandle() {
        if (h_ != INVALID_HANDLE_VALUE)
            CloseHandle(h_);
    }

    operator HANDLE() const { return h_; }
    bool valid() const { return h_ != INVALID_HANDLE_VALUE; }

    // Delete copy operations for safety
    SnapshotHandle(const SnapshotHandle&) = delete;
    SnapshotHandle& operator=(const SnapshotHandle&) = delete;
};

// Enumeration result codes
enum class EnumResult {
    Success,
    SnapshotFailed,
    AccessDenied,
    InvalidPid,
    NoResults,
    ProcessNotFound
};

// Data structures for returned information
struct ProcessInfo {
    DWORD pid;
    std::wstring name;
    DWORD parentPid;
    DWORD threadCount;

    ProcessInfo(DWORD p, const std::wstring& n, DWORD parent = 0, DWORD threads = 0)
        : pid(p), name(n), parentPid(parent), threadCount(threads) {
    }
};

struct ModuleInfo {
    void* baseAddress;
    DWORD size;
    std::wstring name;
    std::wstring path;

    ModuleInfo(void* base, DWORD sz, const std::wstring& n, const std::wstring& p)
        : baseAddress(base), size(sz), name(n), path(p) {
    }
};

// Utility functions
class SystemUtils {
public:
    // Check if current process is running with elevated privileges
    static bool is_elevated() {
        BOOL elevated = FALSE;
        HANDLE token = nullptr;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            TOKEN_ELEVATION elevation;
            DWORD size;
            if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
                elevated = elevation.TokenIsElevated;
            }
            CloseHandle(token);
        }
        return elevated != FALSE;
    }

    // Get error message for last Windows error
    static std::wstring get_last_error_message() {
        DWORD error = GetLastError();
        LPWSTR buffer = nullptr;

        DWORD length = FormatMessageW(  // Use FormatMessageW
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

        std::wstring message;  // Use wstring
        if (length > 0 && buffer) {
            message = buffer;
            while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
                message.pop_back();
            }
        }

        if (buffer) LocalFree(buffer);
        return message.empty() ? L"Unknown error" : message;
    }

    // Validate PID range
    static bool is_valid_pid(DWORD pid) {
        return pid > 0 && pid <= 0x7FFFFFFF;
    }

    // Check if process exists
    static bool process_exists(DWORD pid) {
        if (!is_valid_pid(pid)) return false;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess) {
            CloseHandle(hProcess);
            return true;
        }
        return false;
    }
};

// Main enumeration class
class ProcessEnumerator {
private:
    PROCESSENTRY32W pe_;
    MODULEENTRY32W me_;

public:
    ProcessEnumerator() : pe_{ sizeof(pe_) }, me_{ sizeof(me_) } {}

    // Enumerate all processes with filtering support
    EnumResult enumerate_processes(std::vector<ProcessInfo>& processes,
        const std::wstring& filter = L"") {
        processes.clear();

        SnapshotHandle snap(TH32CS_SNAPPROCESS);
        if (!snap.valid()) {
            return EnumResult::SnapshotFailed;
        }

        for (BOOL ok = Process32FirstW(snap, &pe_); ok; ok = Process32NextW(snap, &pe_)) {
            std::wstring name(pe_.szExeFile);

            // Case-insensitive filtering
            if (filter.empty() || case_insensitive_search(name, filter)) {
                processes.emplace_back(
                    pe_.th32ProcessID,
                    name,
                    pe_.th32ParentProcessID,
                    pe_.cntThreads
                );
            }
        }

        return processes.empty() ? EnumResult::NoResults : EnumResult::Success;
    }

    // Enumerate modules for a specific process
    EnumResult enumerate_modules(DWORD pid, std::vector<ModuleInfo>& modules) {
        modules.clear();

        if (!SystemUtils::is_valid_pid(pid)) {
            return EnumResult::InvalidPid;
        }

        if (!SystemUtils::process_exists(pid)) {
            return EnumResult::ProcessNotFound;
        }

        SnapshotHandle snap(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (!snap.valid()) {
            DWORD error = GetLastError();
            return (error == ERROR_ACCESS_DENIED) ? EnumResult::AccessDenied : EnumResult::SnapshotFailed;
        }

        for (BOOL ok = Module32FirstW(snap, &me_); ok; ok = Module32NextW(snap, &me_)) {
            modules.emplace_back(
                me_.modBaseAddr,
                me_.modBaseSize,
                me_.szModule,
                me_.szExePath
            );
        }

        return modules.empty() ? EnumResult::NoResults : EnumResult::Success;
    }

private:
    bool case_insensitive_search(const std::wstring& text, const std::wstring& pattern) {
        return std::search(text.begin(), text.end(), pattern.begin(), pattern.end(),
            [](wchar_t a, wchar_t b) {
                return towlower(a) == towlower(b);
            }) != text.end();
    }
};

// Display functions with improved formatting
class ProcessDisplay {
public:
    static void print_processes(const std::vector<ProcessInfo>& processes) {
        if (processes.empty()) {
            std::cout << "No processes found.\n";
            return;
        }

        // Header
        std::cout << std::left
            << std::setw(8) << "PID"
            << std::setw(8) << "PPID"
            << std::setw(8) << "Threads"
            << "Process Name\n";
        std::cout << std::string(60, '-') << "\n";

        // Process entries
        for (const auto& proc : processes) {
            std::cout << std::left
                << std::setw(8) << proc.pid
                << std::setw(8) << proc.parentPid
                << std::setw(8) << proc.threadCount
                << wstring_to_string(proc.name) << "\n";
        }

        std::cout << "\nTotal processes: " << processes.size() << "\n";
    }

    static void print_modules(DWORD pid, const std::vector<ModuleInfo>& modules) {
        if (modules.empty()) {
            std::cout << "No modules found for PID " << pid << ".\n";
            return;
        }

        std::cout << "Modules for PID " << pid << ":\n";
        std::cout << std::string(80, '=') << "\n";

        for (const auto& mod : modules) {
            std::cout << "Base: 0x" << std::hex << std::setw(16) << std::setfill('0')
                << reinterpret_cast<uintptr_t>(mod.baseAddress)
                << "  Size: 0x" << std::setw(8) << mod.size << std::dec
                << "  Name: " << wstring_to_string(mod.name) << "\n"
                << "  Path: " << wstring_to_string(mod.path) << "\n\n";
        }

        std::cout << "Total modules: " << modules.size() << "\n";
    }

    static void print_error(EnumResult result, DWORD pid = 0) {
        switch (result) {
        case EnumResult::SnapshotFailed:
            std::cout << "Failed to create snapshot: " << SystemUtils::get_last_error_message() << "\n";
            break;
        case EnumResult::AccessDenied:
            std::cout << "Access denied";
            if (pid != 0) std::cout << " for PID " << pid;
            std::cout << ". Try running as administrator.\n";
            break;
        case EnumResult::InvalidPid:
            std::cout << "Invalid PID: " << pid << "\n";
            break;
        case EnumResult::ProcessNotFound:
            std::cout << "Process " << pid << " not found.\n";
            break;
        case EnumResult::NoResults:
            std::cout << "No results found.\n";
            break;
        default:
            std::cout << "Unknown error occurred.\n";
            break;
        }
    }
};

// Improved command functions
void cmd_ps_improved(const std::wstring& filter = L"") {
    ProcessEnumerator enumerator;
    std::vector<ProcessInfo> processes;

    if (!SystemUtils::is_elevated()) {
        std::cout << "Note: Not running with elevated privileges. Some information may be limited.\n\n";
    }

    EnumResult result = enumerator.enumerate_processes(processes, filter);

    if (result == EnumResult::Success) {
        ProcessDisplay::print_processes(processes);
    }
    else {
        ProcessDisplay::print_error(result);
    }
}

void cmd_mods_improved(DWORD pid) {
    if (!SystemUtils::is_valid_pid(pid)) {
        ProcessDisplay::print_error(EnumResult::InvalidPid, pid);
        return;
    }

    ProcessEnumerator enumerator;
    std::vector<ModuleInfo> modules;

    EnumResult result = enumerator.enumerate_modules(pid, modules);

    if (result == EnumResult::Success) {
        ProcessDisplay::print_modules(pid, modules);
    }
    else {
        ProcessDisplay::print_error(result, pid);
    }
}

// Original simple functions (for compatibility)
void cmd_ps() {
    SnapshotHandle snap(TH32CS_SNAPPROCESS);
    if (!snap.valid()) {
        std::cout << "Snapshot failed: " << SystemUtils::get_last_error_message() << "\n";
        return;
    }

    PROCESSENTRY32W pe{ sizeof(pe) };
    std::cout << std::left << std::setw(8) << "PID" << "Process Name\n";
    std::cout << std::string(40, '-') << "\n";

    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        std::cout << std::left << std::setw(8) << pe.th32ProcessID
            << wstring_to_string(pe.szExeFile) << "\n";
    }
}

void cmd_mods(DWORD pid) {
    SnapshotHandle snap(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (!snap.valid()) {
        DWORD error = GetLastError();
        std::cout << "Module snapshot failed for PID " << pid
            << ": " << SystemUtils::get_last_error_message() << "\n";

        if (error == ERROR_ACCESS_DENIED) {
            std::cout << "Try running as administrator.\n";
        }
        return;
    }

    MODULEENTRY32W me{ sizeof(me) };
    for (BOOL ok = Module32FirstW(snap, &me); ok; ok = Module32NextW(snap, &me)) {
        std::cout << "Base=0x" << std::hex << std::setw(16) << std::setfill('0')
            << reinterpret_cast<uintptr_t>(me.modBaseAddr)
            << "  Size=0x" << std::setw(8) << me.modBaseSize
            << std::dec << "  Path=" << wstring_to_string(me.szExePath) << "\n";
    }
}

// Example usage
void example_usage() {
    std::cout << "=== Original Functions ===\n";
    std::cout << "All processes:\n";
    cmd_ps();

    std::cout << "\nModules for PID 4 (System):\n";
    cmd_mods(4);

    std::cout << "\n=== Improved Functions ===\n";
    std::cout << "All processes (improved):\n";
    cmd_ps_improved();

    std::cout << "\nFiltered processes (containing 'exe'):\n";
    cmd_ps_improved(L"exe");

    std::cout << "\nModules for current process (improved):\n";
    cmd_mods_improved(GetCurrentProcessId());
}