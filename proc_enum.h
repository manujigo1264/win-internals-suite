#pragma once
#include "common.h"

// Forward declarations
struct ProcessInfo;
struct ModuleInfo;

// RAII wrapper for snapshot handles
class SnapshotHandle {
private:
    HANDLE h_;

public:
    explicit SnapshotHandle(DWORD flags, DWORD pid = 0);
    ~SnapshotHandle();

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

    ProcessInfo(DWORD p, const std::wstring& n, DWORD parent = 0, DWORD threads = 0);
};

struct ModuleInfo {
    void* baseAddress;
    DWORD size;
    std::wstring name;
    std::wstring path;

    ModuleInfo(void* base, DWORD sz, const std::wstring& n, const std::wstring& p);
};

// Utility functions
class SystemUtils {
public:
    // Check if current process is running with elevated privileges
    static bool is_elevated();

    // Get error message for last Windows error
    static std::wstring get_last_error_message();

    // Validate PID range
    static bool is_valid_pid(DWORD pid);

    // Check if process exists
    static bool process_exists(DWORD pid);
};

// Main enumeration class
class ProcessEnumerator {
private:
    PROCESSENTRY32W pe_;
    MODULEENTRY32W me_;

public:
    ProcessEnumerator();

    // Enumerate all processes with filtering support
    EnumResult enumerate_processes(std::vector<ProcessInfo>& processes,
        const std::wstring& filter = L"");

    // Enumerate modules for a specific process
    EnumResult enumerate_modules(DWORD pid, std::vector<ModuleInfo>& modules);

private:
    bool case_insensitive_search(const std::wstring& text, const std::wstring& pattern);
};

// Display functions with improved formatting
class ProcessDisplay {
public:
    static void print_processes(const std::vector<ProcessInfo>& processes);
    static void print_modules(DWORD pid, const std::vector<ModuleInfo>& modules);
    static void print_error(EnumResult result, DWORD pid = 0);
};

// Improved command functions
void cmd_ps_improved(const std::wstring& filter = L"");
void cmd_mods_improved(DWORD pid);

// Original simple functions (for compatibility)
void cmd_ps();
void cmd_mods(DWORD pid);

// Example usage function
void example_usage();