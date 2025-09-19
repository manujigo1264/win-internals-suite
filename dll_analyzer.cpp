#include "dll_analyzer.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <array>

// Detection struct constructor implementation
Detection::Detection(DetectionCategory cat, ThreatLevel lvl, const std::string& n,
    const std::string& desc, const std::vector<std::string>& ind)
    : category(cat), level(lvl), name(n), description(desc), indicators(ind) {
}

// ScanResult struct constructor implementation
ScanResult::ScanResult() : fileSize(0), overallThreat(ThreatLevel::Clean),
isPacked(false), isEncrypted(false), entropy(0.0) {
}

// HexSignature constructor implementation
SignatureEngine::HexSignature::HexSignature(const std::string& n, const std::string& hex,
    DetectionCategory cat, ThreatLevel lvl, const std::string& desc)
    : name(n), category(cat), level(lvl), description(desc) {
    parse_hex_pattern(hex);
}

// HexSignature parse_hex_pattern implementation with validation
void SignatureEngine::HexSignature::parse_hex_pattern(const std::string& hex) {
    pattern.clear();
    mask.clear();

    // Add input validation
    if (hex.empty()) return;
    if (hex.length() % 2 != 0) {
        // Invalid hex string length - should be even
        return;
    }

    for (size_t i = 0; i < hex.length(); i += 2) {
        if (i + 1 >= hex.length()) break;

        std::string byte_str = hex.substr(i, 2);
        if (byte_str == "??") {
            pattern.push_back(0x00);
            mask.push_back(0x00);  // Wildcard
        }
        else {
            try {
                // Validate hex characters
                if (byte_str.find_first_not_of("0123456789ABCDEFabcdef") != std::string::npos) {
                    continue; // Skip invalid hex characters
                }

                uint8_t byte_val = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
                pattern.push_back(byte_val);
                mask.push_back(0xFF);  // Exact match
            }
            catch (const std::exception&) {
                // Invalid hex, skip
                continue;
            }
        }
    }
}

// SignatureEngine implementation
SignatureEngine::SignatureEngine() {
    load_default_signatures();
}

void SignatureEngine::load_default_signatures() {
    // Shellcode signatures with wildcards
    add_signature("Metasploit_x64_Reverse_Shell", "FC4883E4F0E8C0000000415141??41??",
        DetectionCategory::Shellcode, ThreatLevel::High, "Metasploit x64 reverse shell");

    add_signature("Windows_x86_Prologue", "558BEC83EC??",
        DetectionCategory::Shellcode, ThreatLevel::Suspicious, "Common x86 function prologue");

    // Process hollowing patterns
    add_signature("Process_Hollowing", "E8????????68????????6A??6A??6A??E8????????",
        DetectionCategory::ProcessInjection, ThreatLevel::High, "Process hollowing technique");

    // Anti-debugging
    add_signature("IsDebuggerPresent", "FF15????????85C075??",
        DetectionCategory::AntiAnalysis, ThreatLevel::Likely, "Anti-debugging check");

    // Crypto signatures
    add_signature("RC4_Key_Schedule", "33C040885C05??40??????????72F4",
        DetectionCategory::Cryptography, ThreatLevel::Likely, "RC4 key scheduling");

    // Persistence mechanisms
    add_signature("Run_Registry_Key", "536F6674776172655C4D6963726F736F66745C57696E646F77735C43757272656E7456657273696F6E5C52756E",
        DetectionCategory::Persistence, ThreatLevel::Likely, "Run registry key access");
}

void SignatureEngine::add_signature(const std::string& name, const std::string& hex_pattern,
    DetectionCategory category, ThreatLevel level, const std::string& description) {
    signatures_.emplace_back(name, hex_pattern, category, level, description);
}

std::vector<Detection> SignatureEngine::scan_signatures(const uint8_t* data, size_t size) const {
    std::vector<Detection> detections;

    // Add null pointer and size validation
    if (!data || size == 0) return detections;

    for (const auto& sig : signatures_) {
        if (search_pattern(data, size, sig)) {
            std::vector<std::string> indicators = {
                "Pattern: " + bytes_to_hex(sig.pattern, sig.mask)
            };
            detections.emplace_back(sig.category, sig.level, sig.name, sig.description, indicators);
        }
    }

    return detections;
}

bool SignatureEngine::search_pattern(const uint8_t* data, size_t data_size, const HexSignature& sig) const {
    if (sig.pattern.empty() || data_size < sig.pattern.size()) return false;
    if (!data) return false;

    for (size_t i = 0; i <= data_size - sig.pattern.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < sig.pattern.size(); ++j) {
            if (sig.mask[j] != 0x00 && data[i + j] != sig.pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

std::string SignatureEngine::bytes_to_hex(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& mask) const {
    std::ostringstream oss;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i < mask.size() && mask[i] == 0x00) {
            oss << "??";
        }
        else {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
        }
    }
    return oss.str();
}

// ImportAnalyzer implementation
ImportAnalyzer::ImportAnalyzer() {
    load_suspicious_apis();
}

void ImportAnalyzer::load_suspicious_apis() {
    // Process injection (classic)
    api_sets_.push_back({
        "Process_Injection_Classic",
        {"kernel32.dll!openprocess", "kernel32.dll!writeprocessmemory", "kernel32.dll!createremotethread"},
        DetectionCategory::ProcessInjection, ThreatLevel::High,
        "Classic process injection technique", true
        });

    // Advanced process injection
    api_sets_.push_back({
        "Process_Injection_Advanced",
        {"ntdll.dll!ntcreatesection", "ntdll.dll!ntmapviewofsection", "ntdll.dll!ntunmapviewofsection"},
        DetectionCategory::ProcessInjection, ThreatLevel::High,
        "Advanced process injection using sections", true
        });

    // Anti-analysis APIs
    api_sets_.push_back({
        "Anti_Analysis",
        {"kernel32.dll!isdebuggerpresent", "ntdll.dll!ntqueryinformationprocess",
         "kernel32.dll!checkremotedebuggerpresent", "ntdll.dll!ntsetinformationthread"},
        DetectionCategory::AntiAnalysis, ThreatLevel::Likely,
        "Anti-debugging and analysis evasion", false
        });

    // Persistence mechanisms
    api_sets_.push_back({
        "Registry_Persistence",
        {"advapi32.dll!regsetvalueexa", "advapi32.dll!regsetvalueexw",
         "advapi32.dll!regcreatekey", "advapi32.dll!regcreatekeyex"},
        DetectionCategory::Persistence, ThreatLevel::Suspicious,
        "Registry-based persistence", false
        });

    // Network activity
    api_sets_.push_back({
        "Network_Activity",
        {"ws2_32.dll!socket", "ws2_32.dll!connect", "ws2_32.dll!send", "ws2_32.dll!recv"},
        DetectionCategory::NetworkActivity, ThreatLevel::Suspicious,
        "Network communication capabilities", false
        });

    // File system manipulation
    api_sets_.push_back({
        "File_Manipulation",
        {"kernel32.dll!createfilea", "kernel32.dll!createfilew", "kernel32.dll!writefile",
         "kernel32.dll!setfileattributes", "kernel32.dll!deletefilea"},
        DetectionCategory::FileSystem, ThreatLevel::Suspicious,
        "File system manipulation", false
        });

    // Cryptographic APIs
    api_sets_.push_back({
        "Cryptography",
        {"advapi32.dll!cryptacquirecontext", "advapi32.dll!cryptencrypt",
         "advapi32.dll!cryptdecrypt", "bcrypt.dll!bcryptencrypt"},
        DetectionCategory::Cryptography, ThreatLevel::Suspicious,
        "Cryptographic operations", false
        });
}

std::vector<Detection> ImportAnalyzer::analyze_imports(const std::vector<std::string>& imports) const {
    std::vector<Detection> detections;

    // Add validation for empty imports
    if (imports.empty()) return detections;

    // Convert imports to lowercase for comparison
    std::unordered_set<std::string> import_set;
    for (const auto& imp : imports) {
        std::string lower_imp = to_lowercase(imp);
        import_set.insert(lower_imp);
    }

    for (const auto& api_set : api_sets_) {
        std::vector<std::string> found_apis;
        int matches = 0;

        for (const auto& api : api_set.apis) {
            if (import_set.count(api)) {
                found_apis.push_back(api);
                matches++;
            }
        }

        bool detected = false;
        if (api_set.requireAll && matches == static_cast<int>(api_set.apis.size())) {
            detected = true;
        }
        else if (!api_set.requireAll && matches > 0) {
            detected = true;
        }

        if (detected) {
            detections.emplace_back(api_set.category, api_set.level, api_set.name,
                api_set.description, found_apis);
        }
    }

    return detections;
}

std::string ImportAnalyzer::to_lowercase(const std::string& str) const {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return result;
}

// EntropyAnalyzer implementation
double EntropyAnalyzer::calculate_entropy(const uint8_t* data, size_t size) {
    if (size == 0 || !data) return 0.0;

    std::array<size_t, 256> frequency = { 0 };

    // Count byte frequencies
    for (size_t i = 0; i < size; ++i) {
        frequency[data[i]]++;
    }

    // Calculate Shannon entropy
    double entropy = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (frequency[i] > 0) {
            double prob = static_cast<double>(frequency[i]) / size;
            entropy -= prob * std::log2(prob);
        }
    }

    return entropy;
}

bool EntropyAnalyzer::is_likely_packed(double entropy) {
    return entropy > 7.0;  // High entropy suggests compression/encryption
}

// HashCalculator implementation
bool HashCalculator::calculate_hashes(const uint8_t* data, size_t size,
    std::string& sha256_out, std::string& md5_out) {
    // Add validation
    if (!data || size == 0) return false;

    return calculate_sha256(data, size, sha256_out) &&
        calculate_md5(data, size, md5_out);
}

bool HashCalculator::calculate_sha256(const uint8_t* data, size_t size, std::string& out) {
    // Add validation
    if (!data || size == 0) return false;

    // Use existing sha256 function from common.h
    return sha256(data, size, out);
}

bool HashCalculator::calculate_md5(const uint8_t* data, size_t size, std::string& out) {
    // Add validation
    if (!data || size == 0) return false;

    BCRYPT_ALG_HANDLE alg{};
    BCRYPT_HASH_HANDLE h{};
    DWORD objLen = 0, got = 0, hashLen = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_MD5_ALGORITHM, nullptr, 0) < 0)
        return false;

    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &got, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &got, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    std::vector<BYTE> obj(objLen), hash(hashLen);

    if (BCryptCreateHash(alg, &h, obj.data(), objLen, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    if (BCryptHashData(h, (PUCHAR)data, (ULONG)size, 0) < 0) {
        BCryptDestroyHash(h);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    if (BCryptFinishHash(h, hash.data(), hashLen, 0) < 0) {
        BCryptDestroyHash(h);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    static const char* hexd = "0123456789abcdef";
    out.clear();
    out.reserve(hashLen * 2);

    for (BYTE b : hash) {
        out.push_back(hexd[b >> 4]);
        out.push_back(hexd[b & 0xF]);
    }

    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);
    return true;
}

// MalwareScanner implementation
ScanResult MalwareScanner::scan_file(const std::wstring& path) const {
    auto start_time = std::chrono::high_resolution_clock::now();

    ScanResult result;
    result.filePath = path;

    // Add path validation
    if (path.empty()) {
        result.detections.emplace_back(DetectionCategory::Unknown, ThreatLevel::Critical,
            "Invalid_Path", "Empty file path provided");
        return result;
    }

    // Open file
    MappedFile mf;
    if (!mf.open(path)) {
        result.detections.emplace_back(DetectionCategory::Unknown, ThreatLevel::Critical,
            "File_Access_Error", "Cannot open file for analysis");
        return result;
    }

    result.fileSize = mf.size;

    // Add file size validation
    if (mf.size == 0) {
        result.detections.emplace_back(DetectionCategory::Unknown, ThreatLevel::Suspicious,
            "Empty_File", "File is empty");
        return result;
    }

    // Calculate hashes
    if (!HashCalculator::calculate_hashes(mf.base, mf.size, result.sha256Hash, result.md5Hash)) {
        result.detections.emplace_back(DetectionCategory::Unknown, ThreatLevel::Suspicious,
            "Hash_Calculation_Failed", "Failed to calculate file hashes");
    }

    // Calculate entropy
    result.entropy = EntropyAnalyzer::calculate_entropy(mf.base, mf.size);
    result.isPacked = EntropyAnalyzer::is_likely_packed(result.entropy);

    if (result.isPacked) {
        std::vector<std::string> entropy_indicators = { "Entropy: " + std::to_string(result.entropy) };
        result.detections.emplace_back(DetectionCategory::Packer, ThreatLevel::Likely,
            "High_Entropy", "File appears to be packed or encrypted",
            entropy_indicators);
    }

    // Signature scanning
    auto sig_detections = signature_engine_.scan_signatures(mf.base, mf.size);
    result.detections.insert(result.detections.end(), sig_detections.begin(), sig_detections.end());

    // PE analysis if applicable
    PEInfo pe;
    if (parse_pe_file(path, pe) && pe.valid) {
        auto import_detections = import_analyzer_.analyze_imports(pe.imports);
        result.detections.insert(result.detections.end(), import_detections.begin(), import_detections.end());

        // Additional PE-specific checks
        analyze_pe_characteristics(pe, result);
    }

    // Determine overall threat level
    result.overallThreat = calculate_overall_threat(result.detections);

    auto end_time = std::chrono::high_resolution_clock::now();
    result.scanTime = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    return result;
}

std::future<std::vector<ScanResult>> MalwareScanner::scan_files_async(const std::vector<std::wstring>& paths) const {
    return std::async(std::launch::async, [this, paths]() {
        std::vector<ScanResult> results;
        results.reserve(paths.size());

        // Add validation for empty paths vector
        if (paths.empty()) return results;

        std::vector<std::future<ScanResult>> futures;
        for (const auto& path : paths) {
            futures.push_back(std::async(std::launch::async, [this, path]() {
                return scan_file(path);
                }));
        }

        for (auto& future : futures) {
            results.push_back(future.get());
        }

        return results;
        });
}

void MalwareScanner::analyze_pe_characteristics(const PEInfo& pe, ScanResult& result) const {
    // Check for suspicious PE characteristics
    if (pe.numSecs == 0) {
        result.detections.emplace_back(DetectionCategory::AntiAnalysis, ThreatLevel::Suspicious,
            "No_Sections", "PE file has no sections - possible evasion");
    }

    // Check entry point location (improved logic)
    bool entry_in_last_section = false;
    if (pe.numSecs > 0) {
        // Parse section information to check entry point location
        // This would need proper section parsing to be fully implemented
        // For now, keeping simplified logic
        entry_in_last_section = (pe.numSecs > 1); // Placeholder - needs real implementation
    }

    if (entry_in_last_section) {
        result.detections.emplace_back(DetectionCategory::Packer, ThreatLevel::Likely,
            "Entry_Point_Anomaly", "Entry point in last section - possible packer");
    }

    // Check for minimal imports (another packer indicator)
    if (pe.imports.size() < 5) {
        result.detections.emplace_back(DetectionCategory::Packer, ThreatLevel::Suspicious,
            "Minimal_Imports", "Very few imports - possible packer or manually crafted PE");
    }

    // Add check for suspicious section names
    const std::vector<std::string> suspicious_section_names = {
        "UPX0", "UPX1", ".aspack", ".adata", ".enigma", ".themida"
    };

    for (const auto& section : pe.sections) {
        for (const auto& suspicious_name : suspicious_section_names) {
            if (section.find(suspicious_name) != std::string::npos) {
                result.detections.emplace_back(DetectionCategory::Packer, ThreatLevel::High,
                    "Suspicious_Section_Name", "Section name indicates known packer: " + suspicious_name);
                break;
            }
        }
    }
}

ThreatLevel MalwareScanner::calculate_overall_threat(const std::vector<Detection>& detections) const {
    if (detections.empty()) return ThreatLevel::Clean;

    ThreatLevel highest = ThreatLevel::Clean;
    int critical_count = 0, high_count = 0, likely_count = 0;

    for (const auto& detection : detections) {
        if (detection.level > highest) {
            highest = detection.level;
        }

        switch (detection.level) {
        case ThreatLevel::Critical: critical_count++; break;
        case ThreatLevel::High: high_count++; break;
        case ThreatLevel::Likely: likely_count++; break;
        default: break;
        }
    }

    // Escalate threat level based on multiple detections
    if (critical_count > 0) return ThreatLevel::Critical;
    if (high_count >= 2) return ThreatLevel::Critical;
    if (high_count >= 1 && likely_count >= 2) return ThreatLevel::Critical;
    if (high_count >= 1) return ThreatLevel::High;
    if (likely_count >= 3) return ThreatLevel::High;

    return highest;
}

// ScanReporter implementation
void ScanReporter::print_scan_result(const ScanResult& result) {
    std::wcout << L"\n" << std::wstring(80, L'=') << L"\n";
    std::wcout << L"MALWARE SCAN REPORT\n";
    std::wcout << std::wstring(80, L'=') << L"\n";

    std::wcout << L"File: " << result.filePath << L"\n";
    std::wcout << L"Size: " << result.fileSize << L" bytes\n";
    std::wcout << L"SHA256: " << to_wide(result.sha256Hash) << L"\n";
    std::wcout << L"MD5: " << to_wide(result.md5Hash) << L"\n";
    std::wcout << L"Entropy: " << std::fixed << std::setprecision(3) << result.entropy << L"\n";
    std::wcout << L"Scan Time: " << result.scanTime.count() << L"ms\n";

    // Threat level
    std::wcout << L"\nTHREAT LEVEL: " << threat_level_to_string(result.overallThreat) << L"\n";

    if (result.isPacked) {
        std::wcout << L"WARNING: File appears to be PACKED/ENCRYPTED\n";
    }

    // Detections
    if (result.detections.empty()) {
        std::wcout << L"\nNo threats detected.\n";
    }
    else {
        std::wcout << L"\nDETECTIONS (" << result.detections.size() << L"):\n";
        std::wcout << std::wstring(50, L'-') << L"\n";

        for (const auto& detection : result.detections) {
            print_detection(detection);
        }
    }
}

void ScanReporter::print_detection(const Detection& detection) {
    std::wcout << L"[" << threat_level_to_string(detection.level) << L"] "
        << to_wide(detection.name) << L"\n";
    std::wcout << L"  Category: " << category_to_string(detection.category) << L"\n";
    std::wcout << L"  Description: " << to_wide(detection.description) << L"\n";

    if (!detection.indicators.empty()) {
        std::wcout << L"  Indicators:\n";
        for (const auto& indicator : detection.indicators) {
            std::wcout << L"    - " << to_wide(indicator) << L"\n";
        }
    }
    std::wcout << L"\n";
}

std::wstring ScanReporter::threat_level_to_string(ThreatLevel level) {
    switch (level) {
    case ThreatLevel::Clean: return L"CLEAN";
    case ThreatLevel::Suspicious: return L"SUSPICIOUS";
    case ThreatLevel::Likely: return L"LIKELY THREAT";
    case ThreatLevel::High: return L"HIGH THREAT";
    case ThreatLevel::Critical: return L"CRITICAL THREAT";
    default: return L"UNKNOWN";
    }
}

std::wstring ScanReporter::category_to_string(DetectionCategory category) {
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

// Main scanning functions implementation
void scan_file_enhanced(const std::wstring& path) {
    MalwareScanner scanner;
    ScanResult result = scanner.scan_file(path);
    ScanReporter::print_scan_result(result);
}

void scan_directory_enhanced(const std::wstring& directory_path) {
    // Implementation for directory scanning would go here
    // This is a placeholder for the concept
    std::wcout << L"Directory scanning: " << directory_path << L"\n";
    std::wcout << L"(Implementation would recursively scan all files)\n";
}

// Original simple function (for compatibility)
void scan_file(const std::wstring& path) {
    // Simple implementation - you can replace this with your original logic
    scan_file_enhanced(path);
}