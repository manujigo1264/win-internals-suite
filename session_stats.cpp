#include "session_stats.h"
#include "console_color.h"
#include <iostream>
#include <iomanip>

int SessionStats::files_scanned = 0;
int SessionStats::threats_found = 0;
int SessionStats::clean_files = 0;
int SessionStats::error_count = 0;
std::chrono::steady_clock::time_point SessionStats::start_time;

void SessionStats::initialize() {
    start_time = std::chrono::steady_clock::now();
    reset();
}

void SessionStats::increment_scanned() {
    files_scanned++;
}

void SessionStats::increment_threats() {
    threats_found++;
}

void SessionStats::increment_clean() {
    clean_files++;
}

void SessionStats::increment_errors() {
    error_count++;
}

void SessionStats::print_summary() {
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    std::wcout << L"\n═══ SESSION SUMMARY ═══\n";

    std::wcout << L"Files scanned: ";
    ConsoleColor::set_color(ConsoleColor::CYAN);
    std::wcout << files_scanned << L"\n";
    ConsoleColor::reset();

    std::wcout << L"Threats found: ";
    if (threats_found > 0) {
        ConsoleColor::set_color(ConsoleColor::RED);
    }
    else {
        ConsoleColor::set_color(ConsoleColor::GREEN);
    }
    std::wcout << threats_found << L"\n";
    ConsoleColor::reset();

    std::wcout << L"Clean files: ";
    ConsoleColor::set_color(ConsoleColor::GREEN);
    std::wcout << clean_files << L"\n";
    ConsoleColor::reset();

    if (error_count > 0) {
        std::wcout << L"Errors: ";
        ConsoleColor::set_color(ConsoleColor::YELLOW);
        std::wcout << error_count << L"\n";
        ConsoleColor::reset();
    }

    std::wcout << L"Total time: ";
    ConsoleColor::set_color(ConsoleColor::CYAN);

    double seconds = duration.count() / 1000.0;
    if (seconds < 1.0) {
        std::wcout << duration.count() << L"ms\n";
    }
    else if (seconds < 60.0) {
        std::wcout << std::fixed << std::setprecision(2) << seconds << L"s\n";
    }
    else {
        int minutes = static_cast<int>(seconds / 60);
        seconds = seconds - (minutes * 60);
        std::wcout << minutes << L"m " << std::fixed << std::setprecision(1) << seconds << L"s\n";
    }

    ConsoleColor::reset();
    std::wcout << L"═══════════════════════\n\n";
}

void SessionStats::reset() {
    files_scanned = 0;
    threats_found = 0;
    clean_files = 0;
    error_count = 0;
}