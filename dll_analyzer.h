#pragma once
#include "common.h"
#include "pe_parser.h"
#include "malware_types.h"
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <string>
#include <chrono>
#include <future>
#include <mutex>

// Forward declarations for directory scanner types
struct FileScanResult;
struct DirectoryScanStats;

// Enhanced signature system
class SignatureEngine {
private:
    struct HexSignature {
        std::string name;
        std::vector<uint8_t> pattern;
        std::vector<uint8_t> mask;  // For wildcard support
        DetectionCategory category;
        ThreatLevel level;
        std::string description;

        HexSignature(const std::string& n, const std::string& hex,
            DetectionCategory cat, ThreatLevel lvl, const std::string& desc);

    private:
        void parse_hex_pattern(const std::string& hex);
    };

    std::vector<HexSignature> signatures_;

public:
    SignatureEngine();
    void load_default_signatures();
    void add_signature(const std::string& name, const std::string& hex_pattern,
        DetectionCategory category, ThreatLevel level, const std::string& description);
    std::vector<Detection> scan_signatures(const uint8_t* data, size_t size) const;

private:
    bool search_pattern(const uint8_t* data, size_t data_size, const HexSignature& sig) const;
    std::string bytes_to_hex(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& mask) const;
};

// Enhanced import analysis
class ImportAnalyzer {
private:
    struct SuspiciousAPISet {
        std::string name;
        std::vector<std::string> apis;
        DetectionCategory category;
        ThreatLevel level;
        std::string description;
        bool requireAll;  // true = all APIs required, false = any API triggers
    };

    std::vector<SuspiciousAPISet> api_sets_;

public:
    ImportAnalyzer();
    void load_suspicious_apis();
    std::vector<Detection> analyze_imports(const std::vector<std::string>& imports) const;

private:
    std::string to_lowercase(const std::string& str) const;
};

// Entropy calculation for packed/encrypted file detection
class EntropyAnalyzer {
public:
    static double calculate_entropy(const uint8_t* data, size_t size);
    static bool is_likely_packed(double entropy);
};

// Enhanced hash calculation
class HashCalculator {
public:
    static bool calculate_hashes(const uint8_t* data, size_t size,
        std::string& sha256_out, std::string& md5_out);

private:
    static bool calculate_sha256(const uint8_t* data, size_t size, std::string& out);
    static bool calculate_md5(const uint8_t* data, size_t size, std::string& out);
};

// Main enhanced scanner
class MalwareScanner {
private:
    SignatureEngine signature_engine_;
    ImportAnalyzer import_analyzer_;
    mutable std::mutex scan_mutex_;

public:
    ScanResult scan_file(const std::wstring& path) const;

    // Asynchronous scanning for multiple files
    std::future<std::vector<ScanResult>> scan_files_async(const std::vector<std::wstring>& paths) const;

private:
    void analyze_pe_characteristics(const PEInfo& pe, ScanResult& result) const;
    ThreatLevel calculate_overall_threat(const std::vector<Detection>& detections) const;
};

// Enhanced reporting
class ScanReporter {
public:
    static void print_scan_result(const ScanResult& result);
    static void print_detection(const Detection& detection);
    static std::wstring threat_level_to_string(ThreatLevel level);
    static std::wstring category_to_string(DetectionCategory category);
};

// Directory scanner function declarations
void save_directory_scan_report(const std::vector<FileScanResult>& results,
    const DirectoryScanStats& stats,
    const std::wstring& scanned_directory);

std::wstring category_to_wstring(DetectionCategory category);

// Main scanning functions (improved versions)
void scan_file_enhanced(const std::wstring& path);
void scan_directory_enhanced(const std::wstring& directory_path);

// Original simple function (for compatibility)
void scan_file(const std::wstring& path);