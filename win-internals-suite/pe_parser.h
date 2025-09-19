#pragma once
#include "common.h"

struct PEInfo {
    bool valid = false, is64 = false;
    WORD numSecs = 0;
    DWORD entryRva = 0;  // Changed from entryRVA to match implementation
    ULONGLONG imageBase = 0;
    DWORD sizeOfImage = 0;
    std::vector<std::string> imports;
    std::vector<std::string> exports;  // Fixed typo from "exposrts"
    std::vector<std::string> sections; // Added missing sections member
    std::string sha256;
};

bool parse_pe_file(const wstring& path, PEInfo& out);
void print_pe(const PEInfo& pe, const wstring& path); // Changed return type to void to match implementation