#pragma once
#include "common.h"
#include "malware_types.h"
#include <vector>
#include <string>
#include <functional>
#include <unordered_set>
#include "dll_analyzer.h"

// Forward declaration for threat level display
std::wstring threat_level_to_string(ThreatLevel level);

// Directory scanning configuration
struct ScanConfig {
    bool recursive = true;                    // Scan subdirectories
    bool include_hidden = false;              // Scan hidden files
    bool include_system = false;              // Scan system files
    size_t max_file_size = 100 * 1024 * 1024; // 100MB max file size
    size_t max_depth = 10;                    // Maximum directory depth
    std::unordered_set<std::wstring> file_extensions; // Extensions to scan (empty = all)
    std::unordered_set<std::wstring> exclude_dirs;    // Directories to skip

    ScanConfig() {
        // Default executable extensions
        file_extensions = {
            L".exe", L".dll", L".sys", L".ocx", L".scr", L".cpl", L".com", L".pif"
        };

        // Default directories to exclude
        exclude_dirs = {
            L"System Volume Information", L"$Recycle.Bin", L"Windows\\WinSxS",
            L"Windows\\System32\\DriverStore", L"ProgramData\\Microsoft\\Windows Defender"
        };
    }
};

// Scan statistics
struct DirectoryScanStats {
    size_t total_files = 0;
    size_t scanned_files = 0;
    size_t skipped_files = 0;
    size_t error_files = 0;
    size_t directories_processed = 0;
    size_t threats_found = 0;
    size_t clean_files = 0;
    std::chrono::milliseconds total_time{ 0 };

    void print_summary() const;
};

// File scan result with path info
struct FileScanResult {
    std::wstring relative_path;
    ScanResult scan_result;
    bool scan_successful = false;
    std::wstring error_message;

    FileScanResult(const std::wstring& path) : relative_path(path) {}
};

// Progress callback function type
using ProgressCallback = std::function<void(size_t current, size_t total, const std::wstring& current_file)>;

// Main directory scanner class
class DirectoryScanner {
private:
    ScanConfig config_;
    MalwareScanner scanner_;
    DirectoryScanStats stats_;
    ProgressCallback progress_callback_;

public:
    DirectoryScanner(const ScanConfig& config = ScanConfig());

    // Set progress callback
    void set_progress_callback(ProgressCallback callback);

    // Main scanning functions
    std::vector<FileScanResult> scan_directory(const std::wstring& directory_path);
    std::vector<FileScanResult> scan_directory_async(const std::wstring& directory_path);

    // Get scan statistics
    const DirectoryScanStats& get_stats() const { return stats_; }

    // Configuration
    void set_config(const ScanConfig& config) { config_ = config; }
    const ScanConfig& get_config() const { return config_; }

private:
    // Internal scanning methods
    void scan_directory_recursive(const std::wstring& directory_path,
        const std::wstring& base_path,
        std::vector<FileScanResult>& results,
        size_t current_depth = 0);

    // File enumeration
    std::vector<std::wstring> enumerate_files(const std::wstring& directory_path);
    std::vector<std::wstring> enumerate_directories(const std::wstring& directory_path);

    // Filtering and validation
    bool should_scan_file(const std::wstring& file_path) const;
    bool should_scan_directory(const std::wstring& dir_path, size_t depth) const;
    bool is_valid_file_extension(const std::wstring& file_path) const;
    bool is_excluded_directory(const std::wstring& dir_path) const;

    // Utility functions
    std::wstring get_file_extension(const std::wstring& file_path) const;
    std::wstring get_relative_path(const std::wstring& full_path, const std::wstring& base_path) const;
    size_t get_file_size(const std::wstring& file_path) const;
};

// Utility functions for common scan configurations
namespace ScanPresets {
    ScanConfig executable_files_only();
    ScanConfig all_files();
    ScanConfig quick_scan();           // Fast scan with size/depth limits
    ScanConfig deep_scan();            // Comprehensive scan
    ScanConfig malware_hunting();      // Focus on malware-prone locations
}

// High-level scanning functions
std::vector<FileScanResult> scan_directory_enhanced_impl(const std::wstring& directory_path,
    const ScanConfig& config = ScanConfig(),
    ProgressCallback progress = nullptr);

void print_directory_scan_results(const std::vector<FileScanResult>& results,
    const DirectoryScanStats& stats);

void save_directory_scan_report(const std::vector<FileScanResult>& results,
    const DirectoryScanStats& stats,
    const std::wstring& scanned_directory);

// Helper function to convert detection category to wide string
std::wstring category_to_wstring(DetectionCategory category);

// Main directory scanning function used by main.cpp
void scan_directory_enhanced(const std::wstring& directory_path);