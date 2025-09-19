#pragma once
#include "common.h"
#include <chrono>
#include <iostream>

class SessionStats {
public:
    static void initialize();
    static void increment_scanned();
    static void increment_threats();
    static void increment_clean();
    static void increment_errors();
    static void print_summary();
    static void reset();

private:
    static int files_scanned;
    static int threats_found;
    static int clean_files;
    static int error_count;
    static std::chrono::steady_clock::time_point start_time;
};