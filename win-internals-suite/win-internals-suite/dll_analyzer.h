#pragma once
#include "common.h"
#include "pe_parser.h"
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <string>
#include <chrono>
#include <future>
#include <mutex>

// Forward declarations
class SignatureEngine;
class ImportAnalyzer;
class EntropyAnalyzer;
class HashCalculator;
class MalwareScanner;
class ScanReporter;

// Enhanced threat detection levels
enum class ThreatLevel {
    Clean = 0,
    Suspicious = 1,
    Likely = 2,
    High = 3,
    Critical = 4
};

// Detection categories for better classification
enum class DetectionCategory {
    ProcessInjection,
    Persistence,
    AntiAnalysis,
    NetworkActivity,
    FileSystem,
    Registry,
    Cryptography,
    Shellcode,
    Packer,
    Unknown
};

// Individual detection result
struct Detection {
    DetectionCategory category;
    ThreatLevel level;
    std::string name;
    std::string description;
    std::vector<std::string> indicators;

    Detection(DetectionCategory cat, ThreatLevel lvl, const std::string& n,
        const std::string& desc, const std::vector<std::string>& ind = {});
};

// Comprehensive scan result
struct ScanResult {
    std::wstring filePath;
    std::string sha256Hash;
    std::string md5Hash;
    size_t fileSize;
    ThreatLevel overallThreat;
    std::vector<Detection> detections;
    bool isPacked;
    bool isEncrypted;
    double entropy;
    std::chrono::milliseconds scanTime;

    ScanResult();
};

// Enhanced signature system
class SignatureEngine {
private:
    struct HexSignature;
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
    struct SuspiciousAPISet;
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

private:
    static std::wstring threat_level_to_string(ThreatLevel level);
    static std::wstring category_to_string(DetectionCategory category);
};

// Main scanning functions (improved versions)
void scan_file_enhanced(const std::wstring& path);
void scan_directory_enhanced(const std::wstring& directory_path);

// Original simple function (for compatibility)
void scan_file(const std::wstring& path);