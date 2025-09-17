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
inline bool sha256() {
	return 0;
}