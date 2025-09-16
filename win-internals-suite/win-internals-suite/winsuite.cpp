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

int main() {
	return 0;
}