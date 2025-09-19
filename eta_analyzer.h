#pragma once

// Remove duplicate #pragma once
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <fstream>

// Required libraries
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

// ETW Provider GUIDs for system monitoring
namespace ETWProviders {
    // Microsoft-Windows-Kernel-Process
    static const GUID KERNEL_PROCESS_GUID = { 0x22fb2cd6, 0x0e7b, 0x422b, { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };

    // Microsoft-Windows-Kernel-File
    static const GUID KERNEL_FILE_GUID = { 0xedd08927, 0x9cc4, 0x4e65, { 0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89 } };

    // Microsoft-Windows-Kernel-Registry
    static const GUID KERNEL_REGISTRY_GUID = { 0x70eb4f03, 0xc1de, 0x4f73, { 0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x5e, 0x52, 0x6b } };

    // Microsoft-Windows-Kernel-Network
    static const GUID KERNEL_NETWORK_GUID = { 0x7dd42a49, 0x5329, 0x4832, { 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x2c } };

    // Additional providers for comprehensive monitoring
    static const GUID KERNEL_MEMORY_GUID = { 0xd1d93ef7, 0xe1f2, 0x4f45, { 0x99, 0x43, 0x03, 0xd2, 0x45, 0xfe, 0x6c, 0x00 } };
    static const GUID KERNEL_OBJECT_GUID = { 0x89497f50, 0xeffe, 0x4440, { 0x8c, 0xf2, 0xce, 0x6b, 0x1c, 0xdc, 0xac, 0xa7 } };
    static const GUID POWERSHELL_PROVIDER_GUID = { 0xa0c1853b, 0x5c40, 0x4b15, { 0x8b, 0x66, 0xd0, 0x1e, 0x55, 0xc8, 0xd7, 0x00 } };
}

// Event types for behavioral analysis
enum class SuspiciousEventType {
    ProcessInjection,
    PrivilegeEscalation,
    FileSystemTampering,
    RegistryPersistence,
    NetworkBeaconing,
    DLLHijacking,
    HollowProcessCreation,
    SuspiciousFileAccess,
    AntiAnalysisEvasion,
    TokenManipulation,
    MemoryAllocation,
    CodeInjection,
    PowerShellExecution,
    Unknown
};

// Convert enum to string for logging/display
const char* suspicious_event_type_to_string(SuspiciousEventType type);

// ETW Event data structure
struct ETWEvent {
    std::chrono::system_clock::time_point timestamp;
    DWORD processId;
    DWORD threadId;
    std::wstring processName;
    std::wstring eventName;
    std::wstring details;  // Additional event details
    SuspiciousEventType eventType;
    std::unordered_map<std::string, std::string> properties;
    int threatScore;  // 0-100 threat level
    GUID providerId;  // Source provider

    // Constructors
    ETWEvent();
    ETWEvent(DWORD pid, DWORD tid, const std::wstring& procName, SuspiciousEventType type);

    // Utility methods
    std::wstring to_string() const;
    bool is_high_threat(int threshold = 70) const;
};

// Behavioral analysis rules
struct BehaviorPattern {
    std::string patternName;
    std::string description;
    std::vector<SuspiciousEventType> eventSequence;
    std::chrono::seconds timeWindow;
    int minOccurrences;
    int severity;  // 1-10 severity level
    std::function<bool(const std::vector<ETWEvent>&)> validator;

    BehaviorPattern();
    BehaviorPattern(const std::string& name, const std::vector<SuspiciousEventType>& sequence);
};

// Forward declarations
class ThreatMonitor;

// ETW Consumer class for real-time monitoring
class ETWAnalyzer {
private:
    TRACEHANDLE sessionHandle_;
    TRACEHANDLE consumerHandle_;
    std::atomic<bool> isRunning_;
    std::thread consumerThread_;
    std::vector<ETWEvent> eventBuffer_;
    std::vector<BehaviorPattern> patterns_;
    std::function<void(const ETWEvent&)> eventCallback_;
    std::function<void(const std::string&, const std::vector<ETWEvent>&)> alertCallback_;

    // Thread safety
    mutable std::mutex eventBufferMutex_;
    mutable std::mutex patternsMutex_;

    // Session management
    std::wstring sessionName_;
    EVENT_TRACE_PROPERTIES* sessionProperties_;

public:
    ETWAnalyzer(const std::wstring& sessionName = L"WinSuiteETWSession");
    ~ETWAnalyzer();

    // Copy/move operations (disabled for safety)
    ETWAnalyzer(const ETWAnalyzer&) = delete;
    ETWAnalyzer& operator=(const ETWAnalyzer&) = delete;
    ETWAnalyzer(ETWAnalyzer&&) = delete;
    ETWAnalyzer& operator=(ETWAnalyzer&&) = delete;

    // Session control
    bool start_monitoring();
    void stop_monitoring();
    bool is_running() const { return isRunning_; }
    const std::wstring& get_session_name() const { return sessionName_; }

    // Event callbacks
    void set_event_callback(std::function<void(const ETWEvent&)> callback) {
        eventCallback_ = std::move(callback);
    }

    void set_alert_callback(std::function<void(const std::string&, const std::vector<ETWEvent>&)> callback) {
        alertCallback_ = std::move(callback);
    }

    // Provider management
    bool enable_process_monitoring();
    bool enable_file_monitoring();
    bool enable_registry_monitoring();
    bool enable_network_monitoring();
    bool enable_advanced_detection();

    // Analysis functions
    void analyze_process_behavior(DWORD pid, std::chrono::minutes duration);
    std::vector<ETWEvent> get_process_events(DWORD pid, std::chrono::minutes lookback);
    std::vector<ETWEvent> query_events_by_process_name(const std::wstring& processName);
    std::vector<std::string> detect_suspicious_patterns();

    // Behavioral analysis
    void add_behavior_pattern(const BehaviorPattern& pattern);
    void add_custom_pattern(const BehaviorPattern& pattern);
    void load_default_patterns();
    void load_advanced_patterns();

    // Threat scoring
    int calculate_threat_score(const std::vector<ETWEvent>& events);
    std::vector<ETWEvent> get_high_threat_events(int minScore = 70);

    // Statistics and monitoring
    size_t get_event_count() const;
    size_t get_pattern_count() const;
    std::chrono::system_clock::time_point get_last_event_time() const;

private:
    // ETW callback functions
    static ULONG WINAPI BufferEventCallback(PEVENT_TRACE_LOGFILE buffer);
    static VOID WINAPI ProcessEvent(PEVENT_RECORD eventRecord);

    // Event processing
    void process_kernel_event(PEVENT_RECORD eventRecord);
    void process_process_event(PEVENT_RECORD eventRecord);
    void process_file_event(PEVENT_RECORD eventRecord);
    void process_registry_event(PEVENT_RECORD eventRecord);
    void process_network_event(PEVENT_RECORD eventRecord);

    // Analysis helpers
    SuspiciousEventType classify_event(const ETWEvent& event);
    bool is_suspicious_process_creation(const ETWEvent& event);
    bool is_suspicious_file_access(const ETWEvent& event);
    bool is_suspicious_registry_access(const ETWEvent& event);
    bool is_suspicious_dll_load(const ETWEvent& event);
    bool is_process_injection_attempt(const std::vector<ETWEvent>& events);
    bool is_privilege_escalation(const std::vector<ETWEvent>& events);

    // Utility functions
    std::wstring get_process_name(DWORD pid);
    std::string get_property_string(PEVENT_RECORD eventRecord, const std::wstring& propertyName);
    void check_behavior_patterns();
    void cleanup_old_events();

    // Session management helpers
    bool create_trace_session();
    bool enable_provider(const GUID& providerId, UCHAR level = TRACE_LEVEL_INFORMATION);
    void cleanup_session();
};

// Specialized analyzers for different attack vectors
class ProcessInjectionDetector {
public:
    static bool detect_dll_injection(const std::vector<ETWEvent>& events);
    static bool detect_process_hollowing(const std::vector<ETWEvent>& events);
    static bool detect_atom_bombing(const std::vector<ETWEvent>& events);
    static bool detect_manual_dll_loading(const std::vector<ETWEvent>& events);
    static bool detect_reflective_dll_loading(const std::vector<ETWEvent>& events);
    static bool detect_thread_execution_hijacking(const std::vector<ETWEvent>& events);

private:
    static const std::vector<std::wstring> INJECTION_INDICATORS;
    static bool has_injection_sequence(const std::vector<ETWEvent>& events);
};

class PersistenceDetector {
public:
    static bool detect_registry_persistence(const std::vector<ETWEvent>& events);
    static bool detect_service_persistence(const std::vector<ETWEvent>& events);
    static bool detect_scheduled_task_persistence(const std::vector<ETWEvent>& events);
    static bool detect_startup_folder_persistence(const std::vector<ETWEvent>& events);
    static bool detect_com_hijacking(const std::vector<ETWEvent>& events);
    static bool detect_dll_search_order_hijacking(const std::vector<ETWEvent>& events);

private:
    static const std::vector<std::wstring> PERSISTENCE_REGISTRY_KEYS;
    static const std::vector<std::wstring> AUTOSTART_LOCATIONS;
    static bool check_autostart_modification(const ETWEvent& event);
};

class PrivilegeEscalationDetector {
public:
    static bool detect_token_manipulation(const std::vector<ETWEvent>& events);
    static bool detect_uac_bypass(const std::vector<ETWEvent>& events);
    static bool detect_process_token_theft(const std::vector<ETWEvent>& events);
    static bool detect_dll_hijacking_escalation(const std::vector<ETWEvent>& events);
    static bool detect_service_exploitation(const std::vector<ETWEvent>& events);

private:
    static const std::vector<std::wstring> UAC_BYPASS_INDICATORS;
    static const std::vector<std::wstring> PRIVILEGED_PROCESSES;
    static bool is_privileged_process(const std::wstring& processName);
};

// Real-time threat monitoring dashboard
class ThreatMonitor {
private:
    ETWAnalyzer analyzer_;
    std::vector<ETWEvent> activeThreats_;
    std::atomic<int> totalEvents_;
    std::atomic<int> suspiciousEvents_;
    std::atomic<int> criticalAlerts_;

    // Thread safety
    mutable std::mutex threatsMutex_;

public:
    ThreatMonitor();
    ~ThreatMonitor();

    // Copy/move operations (disabled for safety)
    ThreatMonitor(const ThreatMonitor&) = delete;
    ThreatMonitor& operator=(const ThreatMonitor&) = delete;

    void start_monitoring();
    void stop_monitoring();

    // Access to analyzer
    ETWAnalyzer& get_analyzer() { return analyzer_; }
    const ETWAnalyzer& get_analyzer() const { return analyzer_; }

    // Real-time statistics
    struct ThreatStats {
        int totalEvents;
        int suspiciousEvents;
        int criticalAlerts;
        std::chrono::system_clock::time_point lastUpdate;
        std::vector<std::pair<SuspiciousEventType, int>> threatBreakdown;

        ThreatStats();
    };

    ThreatStats get_current_stats();
    std::vector<ETWEvent> get_recent_alerts(std::chrono::minutes timeFrame = std::chrono::minutes(10));
    const std::vector<ETWEvent>& get_active_threats() const;

    // Export and reporting
    bool export_threat_report(const std::wstring& filename);
    std::wstring generate_threat_summary();

    // Threat response
    void add_threat_response_rule(SuspiciousEventType threatType,
        std::function<void(const ETWEvent&)> response);

private:
    void on_event_received(const ETWEvent& event);
    void on_pattern_detected(const std::string& patternName, const std::vector<ETWEvent>& events);
    void generate_alert(const ETWEvent& event);
    void update_statistics();
    void cleanup_old_threats();
};

// Usage example and integration functions
namespace ETWIntegration {
    // Initialize ETW monitoring for the security toolkit
    bool initialize_etw_monitoring();
    void shutdown_etw_monitoring();

    // Get real-time process behavior analysis
    std::vector<ETWEvent> analyze_process_realtime(DWORD pid, int durationMinutes = 5);

    // Check if a process is currently exhibiting suspicious behavior
    bool is_process_suspicious(DWORD pid);

    // Get threat intelligence for a specific process
    struct ProcessThreatIntel {
        DWORD pid;
        std::wstring processName;
        std::wstring imagePath;
        int threatScore;
        std::vector<SuspiciousEventType> detectedThreats;
        std::vector<ETWEvent> recentEvents;
        std::chrono::system_clock::time_point lastActivity;
        std::chrono::system_clock::time_point creationTime;

        ProcessThreatIntel();
        ProcessThreatIntel(DWORD processId);
        bool is_high_risk(int threshold = 70) const;
        std::wstring get_threat_summary() const;
    };

    ProcessThreatIntel get_process_threat_intel(DWORD pid);

    // Query functions
    std::vector<ETWEvent> query_events_by_process(const std::wstring& processName);
    bool export_threat_report(const std::wstring& filename);

    // Integration with existing malware scanner
    void enhance_scan_with_etw(const std::wstring& filePath);

    // Export functions for the interactive menu
    void display_etw_dashboard();
    void monitor_process_interactive();
    void show_threat_alerts();
    void display_threat_statistics();
    void export_current_threats();

    // Configuration
    struct ETWConfig {
        bool enableProcessMonitoring = true;
        bool enableFileMonitoring = true;
        bool enableRegistryMonitoring = true;
        bool enableNetworkMonitoring = false;  // Can be resource intensive
        bool enableAdvancedDetection = true;
        int threatScoreThreshold = 70;
        std::chrono::minutes eventRetentionTime = std::chrono::minutes(60);

        ETWConfig() = default;
    };

    void configure_etw_monitoring(const ETWConfig& config);
    ETWConfig get_current_config();
}

// Exception classes for error handling
class ETWException : public std::runtime_error {
public:
    explicit ETWException(const std::string& message) : std::runtime_error(message) {}
    explicit ETWException(const char* message) : std::runtime_error(message) {}
};

class ETWSessionException : public ETWException {
public:
    explicit ETWSessionException(const std::string& message) : ETWException("ETW Session Error: " + message) {}
    explicit ETWSessionException(ULONG errorCode) : ETWException("ETW Session Error: " + std::to_string(errorCode)) {}
};

class ETWProviderException : public ETWException {
public:
    explicit ETWProviderException(const std::string& message) : ETWException("ETW Provider Error: " + message) {}
};

// Global utility functions
namespace ETWUtils {
    std::wstring guid_to_string(const GUID& guid);
    std::string wide_to_narrow(const std::wstring& wide);
    std::wstring narrow_to_wide(const std::string& narrow);
    bool is_admin_process();
    std::wstring get_current_timestamp();

    // System information helpers
    std::wstring get_system_info();
    bool is_process_running(DWORD pid);
    std::vector<DWORD> get_all_process_ids();
}