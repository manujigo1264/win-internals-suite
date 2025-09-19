#pragma once
#include <Windows.h>
#include <string>

class ConsoleColor {
private:
    static HANDLE hConsole;
    static bool color_enabled;

public:
    enum Color {
        BLACK = 0,
        DARK_BLUE = 1,
        DARK_GREEN = 2,
        DARK_CYAN = 3,
        DARK_RED = 4,
        DARK_MAGENTA = 5,
        DARK_YELLOW = 6,
        GRAY = 7,
        DARK_GRAY = 8,
        BLUE = 9,
        GREEN = 10,
        CYAN = 11,
        RED = 12,
        MAGENTA = 13,
        YELLOW = 14,
        WHITE = 15
    };

    static void initialize();
    static void set_color(Color color);
    static void reset();
    static void enable_color(bool enabled);
    static bool is_color_enabled();

    // Convenience methods for common use cases
    static void print_success(const std::wstring& text);
    static void print_warning(const std::wstring& text);
    static void print_error(const std::wstring& text);
    static void print_info(const std::wstring& text);
};