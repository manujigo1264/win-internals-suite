#pragma once
#include "common.h"
#include <string>
#include <iostream>

void print_banner();
void usage();

class ProgressIndicator {
public:
    static void show_scanning(const std::wstring& filename);
    static void show_complete(bool success);
    static void show_progress(size_t current, size_t total);
    static void clear_line();
};