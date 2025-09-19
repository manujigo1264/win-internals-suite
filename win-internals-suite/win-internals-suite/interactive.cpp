#include "interactive.h"
#include "ui_helpers.h"
#include "console_color.h"
#include "session_stats.h"
#include "proc_enum.h"
#include "pe_parser.h"
#include "dll_analyzer.h"
#include <iostream>
#include <limits>

int InteractiveMode::run() {
    ConsoleColor::initialize();
    SessionStats::initialize();

    print_banner();
    std::cout << "Welcome to WinSuite Interactive Mode!\n";
    std::cout << "Type your choice to continue.\n\n";

    while (true) {
        show_main_menu();

        int choice = get_user_choice(0, 6);

        switch (choice) {
        case 1:
            handle_process_list();
            break;
        case 2:
            handle_module_analysis();
            break;
        case 3:
            handle_pe_analysis();
            break;
        case 4:
            handle_malware_scan();
            break;
        case 5:
            handle_batch_scan();
            break;
        case 6:
            handle_settings();
            break;
        case 0:
            std::cout << "\nGoodbye!\n";
            return 0;
        default:
            std::cout << "Invalid choice. Please try again.\n";
        }

        std::cout << "\nPress Enter to continue...";
        std::cin.get();
    }
}

/*int InteractiveMode::run() {
    std::cout << "DEBUG: Starting InteractiveMode::run()\n";

    std::cout << "DEBUG: Calling ConsoleColor::initialize()\n";
    ConsoleColor::initialize();
    std::cout << "DEBUG: ConsoleColor initialized\n";

    std::cout << "DEBUG: Calling SessionStats::initialize()\n";
    SessionStats::initialize();
    std::cout << "DEBUG: SessionStats initialized\n";

    std::cout << "DEBUG: Calling print_banner()\n";
    print_banner();
    std::cout << "DEBUG: print_banner() completed\n";

    std::cout << "DEBUG: Calling ConsoleColor::print_info()\n";
    ConsoleColor::print_info(L"Welcome to WinSuite Interactive Mode!\n");
    std::cout << "DEBUG: print_info completed\n";

    std::cout << "DEBUG: About to start main loop\n";
    std::wcout << L"Type your choice or 'q' to quit at any time.\n\n";

    while (true) {
        std::cout << "DEBUG: Calling show_main_menu()\n";
        show_main_menu();
        std::cout << "DEBUG: show_main_menu() completed\n";

        std::cout << "DEBUG: Calling get_user_choice()\n";
        int choice = get_user_choice(0, 6);
        std::cout << "DEBUG: User chose: " << choice << "\n";

        // Rest of switch statement...
        if (choice == 0) {
            std::cout << "DEBUG: Exiting\n";
            return 0;
        }
        else {
            std::cout << "DEBUG: Choice " << choice << " - not implemented in debug mode\n";
            std::cout << "Press Enter to continue...";
            std::cin.get();
        }
    }
}*/

void InteractiveMode::show_main_menu() {
    std::cout << "\n=== MAIN MENU ===\n\n";
    std::cout << "1. List Processes\n";
    std::cout << "2. Analyze Process Modules\n";
    std::cout << "3. Parse PE File\n";
    std::cout << "4. Scan for Malware\n";
    std::cout << "5. Batch Scan Directory\n";
    std::cout << "6. Settings\n";
    std::cout << "0. Exit\n\n";
    std::cout << "Enter your choice (0-6): ";
}

int InteractiveMode::get_user_choice(int min, int max) {
    int choice;
    while (true) {
        std::cin >> choice;

        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            ConsoleColor::print_error(L"Invalid input. Please enter a number: ");
            continue;
        }

        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (choice >= min && choice <= max) {
            return choice;
        }

        ConsoleColor::print_error(L"Invalid choice. Please enter a number between ");
        std::wcout << min << L" and " << max << L": ";
    }
}

std::string InteractiveMode::get_user_input(const std::string& prompt) {
    std::cout << prompt;
    std::string input;
    std::getline(std::cin, input);
    return input;
}

DWORD InteractiveMode::get_pid_input() {
    while (true) {
        std::string input = get_user_input("Enter PID: ");
        try {
            DWORD pid = std::stoul(input);
            if (pid > 0) {
                return pid;
            }
            ConsoleColor::print_error(L"PID must be greater than 0. ");
        }
        catch (const std::exception&) {
            ConsoleColor::print_error(L"Invalid PID. Please enter a valid number: ");
        }
    }
}

std::wstring InteractiveMode::get_path_input(const std::string& prompt) {
    std::string input = get_user_input(prompt);
    return to_wide(input);
}

void InteractiveMode::handle_process_list() {
    clear_screen();
    ConsoleColor::set_color(ConsoleColor::CYAN);
    std::wcout << L"═══ PROCESS ANALYSIS ═══\n\n";
    ConsoleColor::reset();

    std::string filter = get_user_input("Filter (optional, press Enter for all): ");

    std::wcout << L"\n";
    if (filter.empty()) {
        cmd_ps_improved();
    }
    else {
        cmd_ps_improved(to_wide(filter));
    }
}

void InteractiveMode::handle_module_analysis() {
    clear_screen();
    ConsoleColor::set_color(ConsoleColor::CYAN);
    std::wcout << L"═══ MODULE ANALYSIS ═══\n\n";
    ConsoleColor::reset();

    DWORD pid = get_pid_input();

    std::wcout << L"\n";
    cmd_mods_improved(pid);
}

void InteractiveMode::handle_pe_analysis() {
    clear_screen();
    ConsoleColor::set_color(ConsoleColor::CYAN);
    std::wcout << L"═══ PE FILE ANALYSIS ═══\n\n";
    ConsoleColor::reset();

    std::wstring path = get_path_input("Enter file path: ");

    std::wcout << L"\n";
    PEInfo pe;
    if (parse_pe_file(path, pe)) {
        print_pe(pe, path);
        SessionStats::increment_scanned();
    }
    else {
        ConsoleColor::print_error(L"Failed to parse PE file.\n");
        SessionStats::increment_errors();
    }
}

void InteractiveMode::handle_malware_scan() {
    clear_screen();
    ConsoleColor::set_color(ConsoleColor::CYAN);
    std::wcout << L"═══ MALWARE SCAN ═══\n\n";
    ConsoleColor::reset();

    std::wstring path = get_path_input("Enter file path: ");

    std::wcout << L"\n";

    // Use enhanced scanning
    MalwareScanner scanner;
    ScanResult result = scanner.scan_file(path);
    ScanReporter::print_scan_result(result);

    SessionStats::increment_scanned();
    if (result.overallThreat >= ThreatLevel::Suspicious) {
        SessionStats::increment_threats();
    }
    else {
        SessionStats::increment_clean();
    }
}

void InteractiveMode::handle_batch_scan() {
    clear_screen();
    ConsoleColor::set_color(ConsoleColor::CYAN);
    std::wcout << L"═══ BATCH SCAN ═══\n\n";
    ConsoleColor::reset();

    std::wstring dir_path = get_path_input("Enter directory path: ");

    std::wcout << L"\n";
    scan_directory_enhanced(dir_path);
}

void InteractiveMode::handle_settings() {
    clear_screen();
    ConsoleColor::set_color(ConsoleColor::CYAN);
    std::wcout << L"═══ SETTINGS ═══\n\n";
    ConsoleColor::reset();

    std::wcout << L"1. Toggle color output (currently: ";
    if (ConsoleColor::is_color_enabled()) {
        ConsoleColor::print_success(L"ENABLED");
    }
    else {
        ConsoleColor::print_error(L"DISABLED");
    }
    std::wcout << L")\n";

    std::wcout << L"2. View session statistics\n";
    std::wcout << L"3. Reset session statistics\n";
    std::wcout << L"0. Back to main menu\n\n";

    int choice = get_user_choice(0, 3);

    switch (choice) {
    case 1:
        ConsoleColor::enable_color(!ConsoleColor::is_color_enabled());
        if (ConsoleColor::is_color_enabled()) {
            ConsoleColor::print_success(L"Color output enabled.\n");
        }
        else {
            std::wcout << L"Color output disabled.\n";
        }
        break;
    case 2:
        SessionStats::print_summary();
        break;
    case 3:
        SessionStats::reset();
        ConsoleColor::print_info(L"Session statistics reset.\n");
        break;
    case 0:
        break;
    }
}

void InteractiveMode::pause() {
    ConsoleColor::set_color(ConsoleColor::GRAY);
    std::wcout << L"\nPress Enter to continue...";
    ConsoleColor::reset();
    std::cin.get();
}

void InteractiveMode::clear_screen() {
    system("cls");
}