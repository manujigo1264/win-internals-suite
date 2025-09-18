// winsuite.cpp - Windows Internals Suite (single-file, no external deps)
// Build: x64, C++17+, Link with Psapi.lib; Bcrypt.lib

#define NOMINMAX
#include <Windows.h>
#include <tlhelp32.h> // process/module snapshots
#include <psapi.h> // process/module info utils
#include <bcrypt.h> // SHA-256 hashing
#pragma comment(lib, "Psapi.lib") // ensures linker pulls Psapi.lib
#pragma comment(lib, "Bcrypt.lib") // ensures linker pulls Bcrypt.lib
#include <cstdio>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>

using std::string; using std::wstring; using std::vector;

// Static functions to perform string encoding
// Cinvert UTF-8 to UTF-16
static wstring to_wide(const string& s) {
	int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
	wstring w(n ? n - 1 : 0, L'\0');
	if (n) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, const_cast<wchar_t*>(w.data()), n);
	return w;
}

// Convert UTF-16 to UTF-8
static string to_utf8(const wstring& s) {
	int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
	string o(n ? n - 1 : 0, '\0');
	if (n) WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, const_cast<char*>(o.data()), n, nullptr, nullptr);
	return o;
}

// RVA file mapping (Concert Relative Virtual Address to a raw file pointer)
inline BYTE* rva_to_ptr(BYTE* base, IMAGE_NT_HEADERS* nt, DWORD rva) {
	//Get pointer to the first section header in the PE file
	auto sec = IMAGE_FIRST_SECTION(nt);
	//Iterate throughall sections in the PE file
	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
		//Get the virtual address where this section is loaded in memory
		DWORD va = sec->VirtualAddress;
		//Get the actual size of the section in memory
		//use VirtualSize if available, otherwise fall back to SizeOfRawData
		DWORD sz = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
		//Check if the target RVA falls within this sections virtual address range
		if (rva >= va && rva < va + sz) {
			// Calculate the raw file pointer:
			// 1. (rva - va) = offset within the section
			// 2. + sec->PointerToRawData = add section's file offset
			// 3. + base = add base pointer to get absolute file pointer
			return base + (rva - va) + sec->PointerToRawData;
		}
	}

	// If RVA points to PE headers (before first section), its not relocated, so we can directly add it to the base pointer
	if (rva < nt->OptionalHeader.SizeOfHeaders) {
		return base + rva;
	}
	// RVA dosn't map to any valid section or header - invalid address
	return nullptr;
}


// SHA-256 via CNG (bcrypt)
inline bool sha256(const void* data, size_t len, string& out_hex) {
    // Initialize handles for the algorithm provider and hash object
    BCRYPT_ALG_HANDLE alg{};
    BCRYPT_HASH_HANDLE h{};

    // Variables to store buffer sizes and bytes read
    DWORD objLen = 0, got = 0, hashLen = 0;

    // Open the SHA-256 algorithm provider from Windows CNG
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        return false;

    // Get the required size for the hash object buffer
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &got, 0);

    // Get the size of the final hash output (32 bytes for SHA-256)
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &got, 0);

    // Allocate buffers: one for the hash object, one for the final hash result
    vector<BYTE> obj(objLen), hash(hashLen);

    // Create a hash object instance using the allocated buffer
    if (BCryptCreateHash(alg, &h, obj.data(), objLen, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    // Feed the input data into the hash function
    if (BCryptHashData(h, (PUCHAR)data, (ULONG)len, 0) < 0) {
        BCryptDestroyHash(h);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    // Finalize the hash computation and retrieve the 32-byte result
    if (BCryptFinishHash(h, hash.data(), hashLen, 0) < 0) {
        BCryptDestroyHash(h);
        BCryptCloseAlgorithmProvider(alg, 0);
        return false;
    }

    // Hex conversion lookup table for fast byte-to-hex conversion
    static const char* hexd = "0123456789abcdef";

    // Prepare output string (clear and reserve space for 64 hex characters)
    out_hex.clear();
    out_hex.reserve(hashLen * 2);

    // Convert each byte of the hash to two hexadecimal characters
    for (BYTE b : hash) {
        out_hex.push_back(hexd[b >> 4]);    // Upper 4 bits -> first hex digit
        out_hex.push_back(hexd[b & 0xF]);   // Lower 4 bits -> second hex digit
    }

    // Clean up Windows CNG resources
    BCryptDestroyHash(h);
    BCryptCloseAlgorithmProvider(alg, 0);

    return true; // Success - hash is now in out_hex as lowercase hex string
}