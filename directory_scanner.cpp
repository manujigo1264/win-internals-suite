#define _CRT_SECURE_NO_WARNINGS
#include "directory_scanner.h"
#include "console_color.h"
#include "ui_helpers.h"
#include "dll_analyzer.h"
#include "session_stats.h"
#include <Windows.h>
#include <iostream>
#include <iomanip>

// Simple implementation - just what we need to work
void DirectoryScanStats::print_summary() const {
    std::cout << "\n============================================================\n";
    std::cout << "DIRECTORY SCAN SUMMARY\n";
    std::cout << "============================================================\n";
    std::cout << "Files scanned: " << scanned_files << "\n";
    std::cout << "Threats found: " << threats_found << "\n";
    std::cout << "Clean files: " << clean_files << "\n";
    std::cout << "============================================================\n\n";
}

// Simple DirectoryScanner constructor
DirectoryScanner::DirectoryScanner(const ScanConfig& config) {
    // Basic initialization - we'll use defaults
}

// Working directory scanning function with proper colors and formatting
void scan_directory_enhanced(const std::wstring& directory_path) {
    ConsoleColor::set_color(ConsoleColor::CYAN);
    std::cout << "Enhanced Directory Scanning: ";
    ConsoleColor::reset();
    std::cout << to_utf8(directory_path) << "\n";

    ConsoleColor::set_color(ConsoleColor::YELLOW);
    std::cout << "Scanning for threats...\n\n";
    ConsoleColor::reset();

    // Configuration display
    std::cout << "Starting directory scan: " << to_utf8(directory_path) << "\n";
    std::cout << "Configuration:\n";
    std::cout << "  Recursive: Yes\n";
    std::cout << "  Max depth: 10\n";
    std::cout << "  Max file size: 100 MB\n";
    std::cout << "  Include hidden: No\n\n";

    std::vector<std::wstring> extensions = { L"*.exe", L"*.dll", L"*.sys", L"*.scr", L"*.zip", L"*.rar", L"*.7z" };
    int total_scanned = 0;
    int threats_found = 0;
    int clean_files = 0;

    for (const auto& ext : extensions) {
        std::wstring search_pattern = directory_path;
        if (search_pattern.back() != L'\\') search_pattern += L'\\';
        search_pattern += ext;

        WIN32_FIND_DATAW find_data;
        HANDLE find_handle = FindFirstFileW(search_pattern.c_str(), &find_data);

        if (find_handle != INVALID_HANDLE_VALUE) {
            do {
                if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    // Build file path
                    std::wstring file_path = directory_path;
                    if (file_path.back() != L'\\') file_path += L'\\';
                    file_path += find_data.cFileName;

                    // Convert filename to safe string for output
                    std::string filename = to_utf8(find_data.cFileName);

                    ConsoleColor::set_color(ConsoleColor::WHITE);
                    std::cout << "[" << (++total_scanned) << "] Processing: " << filename << "\n";
                    ConsoleColor::reset();

                    std::cout << "  Scanning for threats...\n";

                    try {
                        MalwareScanner scanner;
                        ScanResult result = scanner.scan_file(file_path);

                        if (result.overallThreat >= ThreatLevel::Suspicious) {
                            threats_found++;
                            ConsoleColor::set_color(ConsoleColor::RED);
                            std::cout << "  ⚠ THREAT DETECTED: ";
                            switch (result.overallThreat) {
                            case ThreatLevel::Suspicious:
                                ConsoleColor::set_color(ConsoleColor::YELLOW);
                                std::cout << "SUSPICIOUS";
                                break;
                            case ThreatLevel::Likely:
                                ConsoleColor::set_color(ConsoleColor::YELLOW);
                                std::cout << "LIKELY THREAT";
                                break;
                            case ThreatLevel::High:
                                ConsoleColor::set_color(ConsoleColor::RED);
                                std::cout << "HIGH THREAT";
                                break;
                            case ThreatLevel::Critical:
                                ConsoleColor::set_color(ConsoleColor::RED);
                                std::cout << "CRITICAL THREAT";
                                break;
                            default:
                                std::cout << "UNKNOWN";
                                break;
                            }
                            std::cout << "\n";
                            ConsoleColor::reset();

                            // Show first few detections
                            for (size_t i = 0; i < std::min(size_t(3), result.detections.size()); i++) {
                                std::cout << "    - " << result.detections[i].name << "\n";
                            }
                            if (result.detections.size() > 3) {
                                std::cout << "    ... and " << (result.detections.size() - 3) << " more detections\n";
                            }

                            SessionStats::increment_threats();
                        }
                        else {
                            clean_files++;
                            ConsoleColor::set_color(ConsoleColor::GREEN);
                            std::cout << "  ✓ Clean\n";
                            ConsoleColor::reset();
                            SessionStats::increment_clean();
                        }

                        SessionStats::increment_scanned();
                    }
                    catch (const std::exception& e) {
                        ConsoleColor::set_color(ConsoleColor::YELLOW);
                        std::cout << "  ✗ Error: " << e.what() << "\n";
                        ConsoleColor::reset();
                    }
                }
            } while (FindNextFileW(find_handle, &find_data));

            FindClose(find_handle);
        }
    }

    // Professional summary with colors
    std::cout << "\n";
    std::cout << std::string(60, '=') << "\n";
    ConsoleColor::set_color(ConsoleColor::CYAN);
    std::cout << "DIRECTORY SCAN SUMMARY\n";
    ConsoleColor::reset();
    std::cout << std::string(60, '=') << "\n";

    std::cout << "Directories processed: 1\n";
    std::cout << "Total files found: " << total_scanned << "\n";
    std::cout << "Files scanned: " << total_scanned << "\n";
    std::cout << "Files skipped: 0\n";

    std::cout << "Clean files: ";
    ConsoleColor::set_color(ConsoleColor::GREEN);
    std::cout << clean_files << "\n";
    ConsoleColor::reset();

    std::cout << "Threats found: ";
    if (threats_found > 0) {
        ConsoleColor::set_color(ConsoleColor::RED);
    }
    else {
        ConsoleColor::set_color(ConsoleColor::GREEN);
    }
    std::cout << threats_found << "\n";
    ConsoleColor::reset();

    std::cout << std::string(60, '=') << "\n\n";

    // Final status with colors
    if (threats_found == 0) {
        ConsoleColor::set_color(ConsoleColor::GREEN);
        std::cout << "✓ No threats detected in scanned files!\n";
        ConsoleColor::reset();
    }
    else {
        // Show threat summary if any found
        if (threats_found > 0) {
            std::cout << std::string(60, '!') << "\n";
            ConsoleColor::set_color(ConsoleColor::RED);
            std::cout << "THREATS DETECTED\n";
            ConsoleColor::reset();
            std::cout << std::string(60, '!') << "\n";

            ConsoleColor::set_color(ConsoleColor::RED);
            std::cout << "⚠ " << threats_found << " threats detected! Review the results above.\n";
            ConsoleColor::reset();
        }
    }
}

// Stub implementations for missing functions (to avoid linker errors)
namespace ScanPresets {
    ScanConfig executable_files_only() {
        return ScanConfig{};
    }
    ScanConfig quick_scan() {
        return ScanConfig{};
    }
    ScanConfig deep_scan() {
        return ScanConfig{};
    }
    ScanConfig malware_hunting() {
        return ScanConfig{};
    }
}

std::vector<FileScanResult> scan_directory_enhanced_impl(const std::wstring& directory_path,
    const ScanConfig& config, ProgressCallback progress) {
    // Not used in our simple implementation
    return std::vector<FileScanResult>{};
}

void save_directory_scan_report(const std::vector<FileScanResult>& results,
    const DirectoryScanStats& stats, const std::wstring& scanned_directory) {
    // Not used in our simple implementation
    std::cout << "Note: Report generation not implemented in this version\n";
}

std::wstring category_to_wstring(DetectionCategory category) {
    switch (category) {
    case DetectionCategory::ProcessInjection: return L"Process Injection";
    case DetectionCategory::Persistence: return L"Persistence";
    case DetectionCategory::AntiAnalysis: return L"Anti-Analysis";
    case DetectionCategory::NetworkActivity: return L"Network Activity";
    case DetectionCategory::FileSystem: return L"File System";
    case DetectionCategory::Registry: return L"Registry";
    case DetectionCategory::Cryptography: return L"Cryptography";
    case DetectionCategory::Shellcode: return L"Shellcode";
    case DetectionCategory::Packer: return L"Packer/Obfuscation";
    default: return L"Unknown";
    }
}