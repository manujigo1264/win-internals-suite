#include "common.h"
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <bcrypt.h>

using namespace std;

#pragma comment(lib, "bcrypt.lib")

int main() {
    cout << "=== Testing SHA-256 Function ===" << endl;

    // Test SHA-256 with simple strings
    string input = "Hello World";
    string hash_result;

    if (sha256(input.c_str(), input.length(), hash_result)) {
        cout << "Input: " << input << endl;
        cout << "SHA-256: " << hash_result << endl;
    }
    else {
        cout << "SHA-256 failed" << endl;
    }

    // Test with empty string
    string empty = "";
    string empty_hash;
    if (sha256(empty.c_str(), empty.length(), empty_hash)) {
        cout << "Empty string SHA-256: " << empty_hash << endl;
    }

    cout << "\n=== Testing RVA Function ===" << endl;

    // Get current executable path
    wchar_t module_path[MAX_PATH];
    GetModuleFileName(nullptr, module_path, MAX_PATH);

    // Open and map the current executable
    HANDLE file = CreateFile(module_path, GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        DWORD file_size = GetFileSize(file, nullptr);
        BYTE* buffer = new BYTE[file_size];
        DWORD bytes_read;

        if (ReadFile(file, buffer, file_size, &bytes_read, nullptr)) {
            // Parse PE headers
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buffer;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(buffer + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                    cout << "PE file loaded successfully" << endl;
                    cout << "Entry point RVA: 0x" << hex << nt->OptionalHeader.AddressOfEntryPoint << dec << endl;

                    // Test RVA conversion
                    DWORD entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
                    BYTE* entry_ptr = rva_to_ptr(buffer, nt, entry_rva);

                    if (entry_ptr) {
                        cout << "Entry point converted to file offset: 0x" << hex << (entry_ptr - buffer) << dec << endl;
                    }
                    else {
                        cout << "RVA conversion failed" << endl;
                    }
                }
            }
        }
        delete[] buffer;
        CloseHandle(file);
    }
    else {
        cout << "Failed to open current executable for testing" << endl;
    }

    cout << "Press Enter to exit..." << endl;
    cin.get();
    return 0;
}