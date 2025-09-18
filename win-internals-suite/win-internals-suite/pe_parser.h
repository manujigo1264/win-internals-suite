#pragma once
#include "common.h"

struct PEInfo {
	bool valid = false, is64 = false;
	WORD numSecs = 0; DWORD entryRVA = 0; ULONGLONG imageBase = 0; DWORD sizeOfImage = 0;
	vector<string> imports;
	vector<string> exposrts;
	string sha256;
};

bool parse_pe_file(const wstring& path, PEInfo& out);
bool print_pe(const PEInfo& pe, const wstring& path);