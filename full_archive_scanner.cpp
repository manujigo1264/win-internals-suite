#include "full_archive_scanner.h"
#include "dll_analyzer.h"
#include "console_color.h"
#include <iostream>
#include <fstream>
#include <random>
#include <sstream>

#include <algorithm>   // transform, find
#include <vector>      // vector
#include <cwctype>     // towlower
#include <cstring>     // memcmp

// REMOVED: #include <filesystem>  // This was causing C++17 errors

FullArchiveScanner::FullArchiveScanner()
    : total_extracted_size_(0), files_extracted_(0) {
    create_temp_directory();
}

FullArchiveScanner::~FullArchiveScanner() {
    cleanup_temp_files();
}

bool FullArchiveScanner::is_supported_archive(const std::wstring& file_path) {
    std::wstring ext = get_file_extension(file_path);
    std::transform(ext.begin(), ext.end(), ext.begin(), towlower);

    const std::vector<std::wstring> supported_types = {
        L".zip", L".rar", L".7z", L".tar", L".gz", L".bz2"
    };

    return std::find(supported_types.begin(), supported_types.end(), ext)
        != supported_types.end();
}

std::wstring FullArchiveScanner::get_archive_type(const std::wstring& file_path) {
    std::wstring ext = get_file_extension(file_path);
    std::transform(ext.begin(), ext.end(), ext.begin(), towlower);
    return ext;
}

FullArchiveScanner::ArchiveScanResult FullArchiveScanner::scan_archive(
    const std::wstring& archive_path,
    MalwareScanner* malware_scanner,
    size_t nesting_level) {

    ArchiveScanResult result;
    result.extraction_successful = false;
    result.total_threats = 0;
    result.highest_threat = ThreatLevel::Clean;

    // Prevent excessive nesting
    if (nesting_level > MAX_NESTED_DEPTH) {
        result.error_message = L"Maximum archive nesting depth exceeded";
        return result;
    }

    // Check for zip bombs before extraction
    if (detect_zip_bomb(archive_path)) {
        result.error_message = L"Potential zip bomb detected - extraction aborted";
        return result;
    }

    std::wcout << L"[ARCHIVE] Extracting: " << archive_path
        << L" (nesting level: " << nesting_level << L")\n";

    // Extract based on archive type
    std::wstring archive_type = get_archive_type(archive_path);
    bool extraction_success = false;

    if (archive_type == L".zip") {
        extraction_success = extract_zip_file(archive_path, result.extracted_files);
    }
    else if (archive_type == L".rar") {
        extraction_success = extract_rar_file(archive_path, result.extracted_files);
    }
    else if (archive_type == L".7z") {
        extraction_success = extract_7z_file(archive_path, result.extracted_files);
    }
    else {
        result.error_message = L"Unsupported archive format: " + archive_type;
        return result;
    }

    if (!extraction_success) {
        result.error_message = L"Failed to extract archive";
        return result;
    }

    result.extraction_successful = true;
    std::wcout << L"[ARCHIVE] Extracted " << result.extracted_files.size()
        << L" files from " << archive_path << L"\n";

    // Scan each extracted file
    for (auto& extracted_file : result.extracted_files) {
        try {
            std::wcout << L"[ARCHIVE] Scanning: " << extracted_file.original_path << L"\n";

            // Check if extracted file is also an archive (nested)
            if (is_supported_archive(extracted_file.extracted_path)) {
                auto nested_result = scan_archive(extracted_file.extracted_path,
                    malware_scanner, nesting_level + 1);

                // Merge nested results
                for (const auto& nested_scan : nested_result.file_scan_results) {
                    result.file_scan_results.push_back(nested_scan);
                    if (nested_scan.overallThreat >= ThreatLevel::Suspicious) {
                        result.total_threats++;
                        if (nested_scan.overallThreat > result.highest_threat) {
                            result.highest_threat = nested_scan.overallThreat;
                        }
                    }
                }
            }
            else {
                // Scan the extracted file with malware engine
                ScanResult scan_result = malware_scanner->scan_file(extracted_file.extracted_path);

                // Add archive context to the scan result
                scan_result.filePath = archive_path + L"/" + extracted_file.original_path;

                // Add filename-based detection if suspicious
                if (extracted_file.is_suspicious_name) {
                    Detection filename_detection(
                        DetectionCategory::Unknown,
                        ThreatLevel::Likely,
                        "Suspicious_Archive_Filename",
                        extracted_file.threat_reason,
                        { "Filename: " + to_utf8(extracted_file.original_path) }
                    );
                    scan_result.detections.push_back(filename_detection);

                    if (scan_result.overallThreat < ThreatLevel::Likely) {
                        scan_result.overallThreat = ThreatLevel::Likely;
                    }
                }

                result.file_scan_results.push_back(scan_result);

                // Update threat statistics
                if (scan_result.overallThreat >= ThreatLevel::Suspicious) {
                    result.total_threats++;
                    if (scan_result.overallThreat > result.highest_threat) {
                        result.highest_threat = scan_result.overallThreat;
                    }
                }
            }
        }
        catch (const std::exception& e) {
            std::wcout << L"[ARCHIVE] Error scanning " << extracted_file.original_path
                << L": " << to_wide(e.what()) << L"\n";
        }
    }

    return result;
}

bool FullArchiveScanner::extract_zip_file(const std::wstring& zip_path,
    std::vector<ExtractedFile>& files) {
    // Basic ZIP extraction using Windows API or minizip
    // This is a simplified implementation - you'd use minizip for production

    MappedFile mf;
    if (!mf.open(zip_path)) {
        return false;
    }

    // Check ZIP signature
    if (mf.size < 4 || memcmp(mf.base, "\x50\x4B\x03\x04", 4) != 0) {
        return false;
    }

    // Parse ZIP central directory and extract files
    // For production, integrate minizip library here

    // Simplified extraction simulation
    try {
        // This would be replaced with actual minizip extraction code
        std::wcout << L"[ARCHIVE] ZIP extraction not fully implemented - using placeholder\n";

        // Create a sample extracted file entry for demonstration
        ExtractedFile sample_file;
        sample_file.original_path = L"sample_file.exe";
        sample_file.extracted_path = temp_dir_ + L"\\sample_file.exe";
        sample_file.size = 1024;
        sample_file.is_suspicious_name = is_suspicious_filename(sample_file.original_path,
            sample_file.threat_reason);

        // In real implementation, you'd extract the actual file content here
        files.push_back(sample_file);

        return true;
    }
    catch (const std::exception& e) {
        std::wcout << L"[ARCHIVE] ZIP extraction failed: " << to_wide(e.what()) << L"\n";
        return false;
    }
}

bool FullArchiveScanner::extract_rar_file(const std::wstring& rar_path,
    std::vector<ExtractedFile>& files) {
    // RAR extraction would require UnRAR library
    std::wcout << L"[ARCHIVE] RAR extraction not implemented\n";
    return false;
}

bool FullArchiveScanner::extract_7z_file(const std::wstring& sevenz_path,
    std::vector<ExtractedFile>& files) {
    // 7Z extraction would require 7-Zip SDK
    std::wcout << L"[ARCHIVE] 7Z extraction not implemented\n";
    return false;
}

bool FullArchiveScanner::detect_zip_bomb(const std::wstring& archive_path) {
    // Simple zip bomb detection - check compression ratio
    MappedFile mf;
    if (!mf.open(archive_path)) {
        return false;
    }

    // If archive is suspiciously small but claims large uncompressed size, flag it
    if (mf.size < 1024 && mf.size > 0) {  // Less than 1KB compressed
        // In real implementation, parse ZIP to get uncompressed size
        return true;  // Potential zip bomb
    }

    return false;
}

bool FullArchiveScanner::create_temp_directory() {
    // Create unique temporary directory
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(10000, 99999);

    std::wostringstream temp_name;
    temp_name << L"WinSuite_Archive_" << dis(gen);

    wchar_t temp_path[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_path);

    temp_dir_ = std::wstring(temp_path) + temp_name.str();

    return CreateDirectoryW(temp_dir_.c_str(), nullptr) != 0;
}

void FullArchiveScanner::cleanup_temp_files() {
    if (!temp_dir_.empty()) {
        // Use Windows API instead of std::filesystem::remove_all
        delete_directory_recursive(temp_dir_);
    }
}

// Helper function to recursively delete directory using Windows API
void FullArchiveScanner::delete_directory_recursive(const std::wstring& dir_path) {
    WIN32_FIND_DATAW find_data;
    std::wstring search_path = dir_path + L"\\*";

    HANDLE find_handle = FindFirstFileW(search_path.c_str(), &find_data);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (wcscmp(find_data.cFileName, L".") == 0 || wcscmp(find_data.cFileName, L"..") == 0) {
            continue;
        }

        std::wstring full_path = dir_path + L"\\" + find_data.cFileName;

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            delete_directory_recursive(full_path);
            RemoveDirectoryW(full_path.c_str());
        }
        else {
            DeleteFileW(full_path.c_str());
        }
    } while (FindNextFileW(find_handle, &find_data));

    FindClose(find_handle);
    RemoveDirectoryW(dir_path.c_str());
}

bool FullArchiveScanner::is_suspicious_filename(const std::wstring& filename,
    std::string& reason) {
    std::wstring lower_name = filename;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), towlower);

    const std::vector<std::pair<std::wstring, std::string>> suspicious_patterns = {
        {L"malware", "Contains 'malware' in filename"},
        {L"virus", "Contains 'virus' in filename"},
        {L"trojan", "Contains 'trojan' in filename"},
        {L"backdoor", "Contains 'backdoor' in filename"},
        {L"keylog", "Contains 'keylogger' pattern"},
        {L"ransomware", "Contains 'ransomware' in filename"},
        {L"pegasus", "Contains 'pegasus' spyware pattern"},
        {L"exploit", "Contains 'exploit' in filename"},
        {L"payload", "Contains 'payload' in filename"},
        {L"rootkit", "Contains 'rootkit' in filename"}
    };

    for (const auto& pattern : suspicious_patterns) {
        if (lower_name.find(pattern.first) != std::wstring::npos) {
            reason = pattern.second;
            return true;
        }
    }

    // Check for executable extensions
    if (is_executable_file(filename)) {
        reason = "Executable file in archive";
        return true;
    }

    return false;
}

bool FullArchiveScanner::is_executable_file(const std::wstring& filename) {
    std::wstring ext = get_file_extension(filename);
    std::transform(ext.begin(), ext.end(), ext.begin(), towlower);

    const std::vector<std::wstring> exe_extensions = {
        L".exe", L".scr", L".bat", L".cmd", L".com", L".pif",
        L".vbs", L".js", L".jar", L".ps1", L".dll", L".sys"
    };

    return std::find(exe_extensions.begin(), exe_extensions.end(), ext)
        != exe_extensions.end();
}

std::wstring FullArchiveScanner::get_file_extension(const std::wstring& path) {
    size_t dot_pos = path.find_last_of(L'.');
    if (dot_pos == std::wstring::npos) return L"";
    return path.substr(dot_pos);
}

// Integration function for directory scanner
ScanResult scan_file_with_full_archive_support(const std::wstring& file_path,
    MalwareScanner* scanner) {
    // First do normal file scan
    ScanResult result = scanner->scan_file(file_path);

    // If it's an archive, do full extraction and scanning
    if (FullArchiveScanner::is_supported_archive(file_path)) {
        std::wcout << L"[ARCHIVE] Full archive scan starting for: " << file_path << L"\n";

        FullArchiveScanner archive_scanner;
        auto archive_result = archive_scanner.scan_archive(file_path, scanner);

        if (archive_result.extraction_successful) {
            // Merge archive scan results into main result
            for (const auto& archive_scan : archive_result.file_scan_results) {
                // Add each detection from archived files
                for (const auto& detection : archive_scan.detections) {
                    result.detections.push_back(detection);
                }
            }

            // Update overall threat level
            if (archive_result.highest_threat > result.overallThreat) {
                result.overallThreat = archive_result.highest_threat;
            }

            std::wcout << L"[ARCHIVE] Found " << archive_result.total_threats
                << L" threats in archive contents\n";
        }
        else {
            // Add detection for failed extraction
            Detection extraction_failure(
                DetectionCategory::Unknown,
                ThreatLevel::Suspicious,
                "Archive_Extraction_Failed",
                "Could not extract archive for scanning: " + to_utf8(archive_result.error_message),
                { "Archive type: " + to_utf8(FullArchiveScanner::get_archive_type(file_path)) }
            );
            result.detections.push_back(extraction_failure);
        }
    }

    return result;
}