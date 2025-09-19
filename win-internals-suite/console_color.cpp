#include "console_color.h"
#include <iostream>
#include <string>

HANDLE ConsoleColor::hConsole = nullptr;
bool ConsoleColor::color_enabled = true;

void ConsoleColor::initialize() {
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // Enable virtual terminal processing for better color support
    DWORD dwMode = 0;
    GetConsoleMode(hConsole, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hConsole, dwMode);
}

void ConsoleColor::set_color(Color color) {
    if (!color_enabled || !hConsole) return;
    SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
}

void ConsoleColor::reset() {
    set_color(WHITE);
}

void ConsoleColor::enable_color(bool enabled) {
    color_enabled = enabled;
}

bool ConsoleColor::is_color_enabled() {
    return color_enabled;
}

void ConsoleColor::print_success(const std::wstring& text) {
    set_color(GREEN);
    std::wcout << text;
    reset();
}

void ConsoleColor::print_warning(const std::wstring& text) {
    set_color(YELLOW);
    std::wcout << text;
    reset();
}

void ConsoleColor::print_error(const std::wstring& text) {
    set_color(RED);
    std::wcout << text;
    reset();
}

void ConsoleColor::print_info(const std::wstring& text) {
    set_color(CYAN);
    std::wcout << text;
    reset();
}