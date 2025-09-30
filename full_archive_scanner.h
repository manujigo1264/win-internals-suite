#pragma once
#include "common.h"
#include "malware_types.h"
#include <vector>
#include <string>

// Forward declarations
class MalwareScanner;
struct ScanResult;

class FullArchiveScanner {
public:
    static const size_t MAX_NESTED_DEPTH = 5;
    static const size_t MAX_EXTRACT_SIZE = 100 * 1024 * 1024; // 100MB
    static const size_t MAX_FILES_PER_ARCHIVE = 1000;

    struct ExtractedFile {
        std::wstring original_path;
        std::wstring extracted_path;
        size_t size;
        bool is_suspicious_name;
        std::string threat_reason;
    };

    struct ArchiveScanResult {
        bool extraction_successful;
        std::wstring error_message;
        std::vector<ExtractedFile> extracted_files;
        std::vector<ScanResult> file_scan_results;
        size_t total_threats;
        ThreatLevel highest_threat;
    };

    FullArchiveScanner();
    ~FullArchiveScanner();

    // Main scanning function
    ArchiveScanResult scan_archive(const std::wstring& archive_path,
        MalwareScanner* malware_scanner,
        size_t nesting_level = 0);

    // Archive type detection
    static bool is_supported_archive(const std::wstring& file_path);
    static std::wstring get_archive_type(const std::wstring& file_path);

private:
    std::wstring temp_dir_;
    size_t total_extracted_size_;
    size_t files_extracted_;

    // Extraction methods for different formats (ONLY the ones that exist in .cpp)
    bool extract_zip_file(const std::wstring& zip_path, std::vector<ExtractedFile>& files);
    bool extract_rar_file(const std::wstring& rar_path, std::vector<ExtractedFile>& files);
    bool extract_7z_file(const std::wstring& sevenz_path, std::vector<ExtractedFile>& files);

    // Security and utility functions (ONLY the ones that exist in .cpp)
    bool detect_zip_bomb(const std::wstring& archive_path);
    bool create_temp_directory();
    void cleanup_temp_files();
    void delete_directory_recursive(const std::wstring& dir_path);

    // File analysis (ONLY the ones that exist in .cpp)
    bool is_suspicious_filename(const std::wstring& filename, std::string& reason);
    bool is_executable_file(const std::wstring& filename);
    static std::wstring get_file_extension(const std::wstring& path);  // Made static
};

// Integration function for directory scanner
ScanResult scan_file_with_full_archive_support(const std::wstring& file_path,
    MalwareScanner* scanner);