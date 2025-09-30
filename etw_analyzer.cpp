// Target SDK before Windows headers
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#define NOMINMAX

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <strsafe.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <algorithm>


#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Tdh.lib")

// System Process Provider (manifest-based)
static const GUID SystemProcessProviderGuid =
{ 0x151f55dc, 0x467d, 0x471f, {0x83, 0xb5, 0x5f, 0x88, 0x9d, 0x46, 0xff, 0x66} };

// Fallback for older SDKs that lack some TDH_OUTTYPE_* macros
#ifndef TDH_OUTTYPE_UNICODESTRING
#define TDH_OUTTYPE_UNICODESTRING    23
#endif
#ifndef TDH_OUTTYPE_ANSISTRING
#define TDH_OUTTYPE_ANSISTRING       24
#endif
#ifndef TDH_OUTTYPE_UINT16
#define TDH_OUTTYPE_UINT16           25
#endif
#ifndef TDH_OUTTYPE_UINT32
#define TDH_OUTTYPE_UINT32           26
#endif
#ifndef TDH_OUTTYPE_UINT64
#define TDH_OUTTYPE_UINT64           27
#endif

// ---- TDH INTYPE fallbacks ----
#ifndef TDH_INTYPE_ANSISTRING
#define TDH_INTYPE_ANSISTRING 2
#endif
#ifndef TDH_INTYPE_UNICODESTRING
#define TDH_INTYPE_UNICODESTRING 20
#endif

// Registry keyword masks
#define SYSTEM_REGISTRY_KW_CREATE     0x0000000000000001ULL
#define SYSTEM_REGISTRY_KW_SET        0x0000000000000002ULL
#define SYSTEM_REGISTRY_KW_DELETE     0x0000000000000004ULL
#define SYSTEM_REGISTRY_KW_QUERY      0x0000000000000008ULL
#define SYSTEM_REGISTRY_KW_ENUMERATE  0x0000000000000010ULL
#define SYSTEM_REGISTRY_KW_NOTIFY     0x0000000000000020ULL
#define SYSTEM_REGISTRY_KW_RUN        0x0000000000000040ULL

// IO keyword masks
#define SYSTEM_IO_KW_READ    0x10ULL
#define SYSTEM_IO_KW_WRITE   0x20ULL
#define SYSTEM_IO_KW_FLUSH   0x40ULL

// Registry & IO provider GUIDs
const GUID SystemRegistryProviderGuid =
{ 0x16156bd9, 0xfab4, 0x4cfa, {0xa2,0x32,0x89,0xd1,0x09,0x90,0x58,0xe3} };

const GUID SystemIoProviderGuid =
{ 0x3d5c43e3, 0x0f1c, 0x4202, {0xb8,0x17,0x17,0x4c,0x00,0x70,0xdc,0x79} };

//----------------------------------------------------------------------------
// Globals
//----------------------------------------------------------------------------
static TRACEHANDLE g_session = 0;
static TRACEHANDLE g_trace = 0;
static const wchar_t* SESSION_NAME = L"WinInternalsSuite-ETW";

//----------------------------------------------------------------------------
// Helpers
//----------------------------------------------------------------------------
static void filetime_to_utc(const LARGE_INTEGER& ts, SYSTEMTIME& outUtc) {
    FILETIME ft{ (DWORD)ts.LowPart, (DWORD)ts.HighPart };
    FileTimeToSystemTime(&ft, &outUtc);
}

static std::wstring wide_from_utf16(const wchar_t* ws, size_t lenChars) {
    if (!ws || !lenChars) return L"";
    return std::wstring(ws, ws + lenChars);
}

// --- property decoding helpers ---
static bool is_textual_name(PCWSTR name) {
    static const wchar_t* kTextProps[] = {
        L"FileName", L"ImageFileName", L"CommandLine",
        L"PackageFullName", L"ApplicationId", L"ProcessName", L"Description"
    };
    for (auto p : kTextProps) if (_wcsicmp(name, p) == 0) return true;
    return false;
}

static bool is_u32_name(PCWSTR name) {
    static const wchar_t* kU32Props[] = {
        L"ProcessId", L"ThreadId", L"SessionId", L"ExitStatus",
        L"ImageSize", L"ImageChecksum", L"SignatureLevel", L"SignatureType",
        L"BasePriority", L"PagePriority", L"IoPriority", L"Flags"
    };
    for (auto p : kU32Props) if (_wcsicmp(name, p) == 0) return true;
    return false;
}

static bool is_u64_name(PCWSTR name) {
    static const wchar_t* kU64Props[] = {
        L"ImageBase", L"DefaultBase", L"DirectoryTableBase",
        L"UniqueProcessKey", L"StackBase", L"StackLimit",
        L"UserStackBase", L"UserStackLimit", L"TebBase", L"Affinity",
        L"TimeDateStamp"
    };
    for (auto p : kU64Props) if (_wcsicmp(name, p) == 0) return true;
    return false;
}

static std::wstring read_wstring_from_buffer(PBYTE buffer, ULONG sizeBytes) {
    if (!buffer || sizeBytes < sizeof(wchar_t)) return L"";
    const wchar_t* ws = reinterpret_cast<const wchar_t*>(buffer);
    size_t chars = sizeBytes / sizeof(wchar_t);
    size_t len = 0;
    while (len < chars && ws[len] != L'\0') ++len;
    return std::wstring(ws, ws + len);
}

static std::wstring read_wstring_from_ansi(PBYTE buffer, ULONG sizeBytes) {
    if (!buffer || sizeBytes == 0) return L"";
    const char* s = reinterpret_cast<const char*>(buffer);
    int need = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
    if (need <= 0) return L"";
    std::vector<wchar_t> wbuf(static_cast<size_t>(need));
    MultiByteToWideChar(CP_ACP, 0, s, -1, wbuf.data(), need);
    return std::wstring(wbuf.data());
}

static void print_prop_value(PCWSTR name, PBYTE buffer, ULONG size, USHORT tdhInType, USHORT tdhOutType) {
    std::wcout << L"    " << name << L": ";
    if (size == 0) { std::wcout << L"(empty)\n"; return; }

    if (is_textual_name(name) || tdhOutType == TDH_OUTTYPE_UNICODESTRING || tdhInType == TDH_INTYPE_UNICODESTRING) {
        std::wcout << read_wstring_from_buffer(buffer, size) << L"\n"; return;
    }
    if (tdhOutType == TDH_OUTTYPE_ANSISTRING || tdhInType == TDH_INTYPE_ANSISTRING) {
        std::wcout << read_wstring_from_ansi(buffer, size) << L"\n"; return;
    }
    if (is_u32_name(name)) { std::wcout << *(ULONG*)buffer << L"\n"; return; }
    if (is_u64_name(name)) { std::wcout << L"0x" << std::hex << *(ULONGLONG*)buffer << std::dec << L"\n"; return; }

    switch (tdhOutType) {
    case TDH_OUTTYPE_UINT16:
        std::wcout << *(USHORT*)buffer << L"\n"; break;
    case TDH_OUTTYPE_UINT32:
        std::wcout << *(ULONG*)buffer << L"\n"; break;
    case TDH_OUTTYPE_UINT64:
        std::wcout << *(ULONGLONG*)buffer << L"\n"; break;
    default:
        std::wcout << L"<" << size << L" bytes>\n"; break;
    }
}

static void dump_event_properties(PEVENT_RECORD rec) {
    ULONG infoSize = 0;
    DWORD status = TdhGetEventInformation(rec, 0, nullptr, nullptr, &infoSize);
    if (status != ERROR_INSUFFICIENT_BUFFER) return;

    std::unique_ptr<BYTE[]> infoBuf(new (std::nothrow) BYTE[infoSize]);
    if (!infoBuf) return;

    auto pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuf.get());
    status = TdhGetEventInformation(rec, 0, nullptr, pInfo, &infoSize);
    if (status != ERROR_SUCCESS) return;

    ULONG propCount = pInfo->TopLevelPropertyCount;
    for (ULONG i = 0; i < propCount; ++i) {
        auto& prop = pInfo->EventPropertyInfoArray[i];
        PWSTR name = (PWSTR)((PBYTE)pInfo + prop.NameOffset);

        PROPERTY_DATA_DESCRIPTOR pdd{};
        pdd.PropertyName = (ULONGLONG)name;
        pdd.ArrayIndex = ULONG_MAX;

        ULONG needed = 0;
        status = TdhGetPropertySize(rec, 0, nullptr, 1, &pdd, &needed);
        if (status != ERROR_SUCCESS) continue;

        std::vector<BYTE> val(needed);
        status = TdhGetProperty(rec, 0, nullptr, 1, &pdd, needed, val.data());
        if (status != ERROR_SUCCESS) continue;

        USHORT inType = prop.nonStructType.InType;
        USHORT outType = prop.nonStructType.OutType;
        print_prop_value(name, val.data(), needed, inType, outType);
    }
}

// Safely read a UTF-16 string from a TRACE_EVENT_INFO offset
static std::wstring tdh_name_from_offset(PTRACE_EVENT_INFO info, ULONG offset) {
    if (offset == 0 || offset == 0xFFFFFFFF) return L"";
    return std::wstring(reinterpret_cast<const wchar_t*>((PBYTE)info + offset));
}

// Heuristic: skip ETW control events that only contain GroupMask1..8 / KernelEventVersion
static bool is_groupmask_control_event(PTRACE_EVENT_INFO info) {
    if (!info) return false;
    if (info->TopLevelPropertyCount < 1) return false;

    // Look at the first few property names
    bool sawGroupMask = false, sawKernelVer = false;
    ULONG count = (std::min)(info->TopLevelPropertyCount, (ULONG)9);
    for (ULONG i = 0; i < count; ++i) {
        auto& prop = info->EventPropertyInfoArray[i];
        auto name = tdh_name_from_offset(info, prop.NameOffset);
        if (name == L"GroupMask1" || name == L"GroupMask2" || name == L"GroupMask3" ||
            name == L"GroupMask4" || name == L"GroupMask5" || name == L"GroupMask6" ||
            name == L"GroupMask7" || name == L"GroupMask8") {
            sawGroupMask = true;
        }
        if (name == L"KernelEventVersion") {
            sawKernelVer = true;
        }
    }
    return sawGroupMask || sawKernelVer;
}

//----------------------------------------------------------------------------
// Callback
//----------------------------------------------------------------------------
static VOID WINAPI on_event(PEVENT_RECORD rec) {
    // First, query TDH metadata so we can print nice names
    ULONG infoSize = 0;
    DWORD s = TdhGetEventInformation(rec, 0, nullptr, nullptr, &infoSize);
    std::unique_ptr<BYTE[]> infoBuf;
    PTRACE_EVENT_INFO info = nullptr;
    if (s == ERROR_INSUFFICIENT_BUFFER) {
        infoBuf.reset(new (std::nothrow) BYTE[infoSize]);
        if (infoBuf) {
            info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuf.get());
            if (TdhGetEventInformation(rec, 0, nullptr, info, &infoSize) != ERROR_SUCCESS) {
                info = nullptr;
            }
        }
    }

    // Heuristic filter: drop ETW control “GroupMask* / KernelEventVersion” events
    if (info && is_groupmask_control_event(info)) {
        return;
    }

    // Timestamp
    SYSTEMTIME utc{};
    LARGE_INTEGER ts;
    ts.LowPart = rec->EventHeader.TimeStamp.LowPart;
    ts.HighPart = rec->EventHeader.TimeStamp.HighPart;
    filetime_to_utc(ts, utc);

    // Pretty names if available
    std::wstring provName = info ? tdh_name_from_offset(info, info->ProviderNameOffset) : L"";
    std::wstring taskName = info ? tdh_name_from_offset(info, info->TaskNameOffset) : L"";
    std::wstring opcName = info ? tdh_name_from_offset(info, info->OpcodeNameOffset) : L"";

    // Fallbacks
    if (provName.empty()) {
        // Show GUID low-part if we couldn’t resolve a name
        wchar_t tmp[64];
        StringCchPrintfW(tmp, 64, L"Provider=%u", rec->EventHeader.ProviderId.Data1);
        provName = tmp;
    }
    if (opcName.empty()) {
        wchar_t tmp[32];
        StringCchPrintfW(tmp, 32, L"Opcode=%u", (unsigned)rec->EventHeader.EventDescriptor.Opcode);
        opcName = tmp;
    }
    if (taskName.empty()) {
        wchar_t tmp[32];
        StringCchPrintfW(tmp, 32, L"Task=%u", (unsigned)rec->EventHeader.EventDescriptor.Task);
        taskName = tmp;
    }
    // Skip control events (DCStart/RDComplete/etc.)
    if (provName == L"MSNT_SystemTrace" && taskName == L"EventTrace") {
        return;
    }

    // Header line
    std::wcout << L"["
        << utc.wHour << L":" << utc.wMinute << L":" << utc.wSecond
        << L'.' << utc.wMilliseconds
        << L"] " << provName
        << L"  EID=" << (unsigned)rec->EventHeader.EventDescriptor.Id
        << L"  " << taskName
        << L"  " << opcName
        << L"  PID=" << rec->EventHeader.ProcessId
        << L"\n";

    // Properties
    dump_event_properties(rec);
}


//----------------------------------------------------------------------------
// Start/Stop
//----------------------------------------------------------------------------
bool etw_start() {
    const ULONG propsSize = sizeof(EVENT_TRACE_PROPERTIES)
        + (DWORD)((wcslen(SESSION_NAME) + 1) * sizeof(wchar_t))
        + (MAX_PATH + 1) * sizeof(wchar_t);

    auto props = (PEVENT_TRACE_PROPERTIES)calloc(1, propsSize);
    if (!props) return false;

    props->Wnode.BufferSize = propsSize;
    props->Wnode.Guid = GUID{};
    props->Wnode.ClientContext = 1;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    props->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + (DWORD)((wcslen(SESSION_NAME) + 1) * sizeof(wchar_t));

    ULONG status = StartTraceW(&g_session, SESSION_NAME, props);
    if (status == ERROR_ALREADY_EXISTS) {
        ControlTraceW(g_session, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        status = StartTraceW(&g_session, SESSION_NAME, props);
    }
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"[ETW] StartTrace failed: " << status << L"\n";
        free(props);
        return false;
    }

    ENABLE_TRACE_PARAMETERS en{};
    en.Version = ENABLE_TRACE_PARAMETERS_VERSION;

    // System Process provider
    {
        ULONGLONG kw = 0x1ULL | 0x2ULL | 0x8ULL; // general, thread, loader
        status = EnableTraceEx2(g_session, &SystemProcessProviderGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
            kw, 0, 0, &en);
    }

    // Registry provider
    {
        ULONGLONG kw = SYSTEM_REGISTRY_KW_CREATE | SYSTEM_REGISTRY_KW_SET |
            SYSTEM_REGISTRY_KW_DELETE | SYSTEM_REGISTRY_KW_QUERY |
            SYSTEM_REGISTRY_KW_ENUMERATE | SYSTEM_REGISTRY_KW_NOTIFY |
            SYSTEM_REGISTRY_KW_RUN;
        EnableTraceEx2(g_session, &SystemRegistryProviderGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
            kw, 0, 0, &en);
    }

    // IO provider
    {
        ULONGLONG kw = SYSTEM_IO_KW_READ | SYSTEM_IO_KW_WRITE | SYSTEM_IO_KW_FLUSH;
        EnableTraceEx2(g_session, &SystemIoProviderGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE,
            kw, 0, 0, &en);
    }

    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = (LPWSTR)SESSION_NAME;
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = (PEVENT_RECORD_CALLBACK)on_event;

    g_trace = OpenTraceW(&log);
    if (g_trace == INVALID_PROCESSTRACE_HANDLE) {
        std::wcerr << L"[ETW] OpenTrace failed\n";
        ControlTraceW(g_session, SESSION_NAME, props, EVENT_TRACE_CONTROL_STOP);
        g_session = 0;
        free(props);
        return false;
    }

    free(props);
    return true;
}

void etw_stop() {
    if (g_trace && g_trace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_trace);
        g_trace = 0;
    }
    if (g_session) {
        EVENT_TRACE_PROPERTIES props{};
        ControlTraceW(g_session, SESSION_NAME, &props, EVENT_TRACE_CONTROL_STOP);
        g_session = 0;
    }
}

//----------------------------------------------------------------------------
// Entry
//----------------------------------------------------------------------------
int run_etw_analyzer() {
    if (!etw_start()) return 1;
    std::wcout << L"[+] ETW started (proc/thread/image/registry/io). Press Ctrl+C to stop.\n";
    ULONG status = ProcessTrace(&g_trace, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        std::wcerr << L"[ETW] ProcessTrace returned: " << status << L"\n";
    }
    etw_stop();
    return 0;
}
