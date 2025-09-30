#include "interactive.h"
#include "ui_helpers.h"
#include "console_color.h"
#include "session_stats.h"
#include "proc_enum.h"
#include "pe_parser.h"
#include "dll_analyzer.h"
#include <iostream>
#include <limits>
#include "directory_scanner.h"

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
    std::wcout << L"═══ DIRECTORY SCANNING ═══\n\n";
    ConsoleColor::reset();

    std::wstring dir_path = get_path_input("Enter directory path: ");

    // Validate directory exists
    DWORD attributes = GetFileAttributesW(dir_path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        ConsoleColor::print_error(L"Error: Directory does not exist.\n");
        return;
    }

    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        ConsoleColor::print_error(L"Error: Path is not a directory.\n");
        return;
    }

    std::wcout << L"\nSelect scan configuration:\n";
    std::wcout << L"1. Quick scan (executables only, depth 5)\n";
    std::wcout << L"2. Standard scan (executables only, depth 10)\n";
    std::wcout << L"3. Deep scan (all files, depth 20)\n";
    std::wcout << L"4. Malware hunting (comprehensive scan)\n";
    std::wcout << L"5. Custom configuration\n";
    std::wcout << L"Enter choice (1-5, default 2): ";

    int scan_choice = get_user_choice(1, 5);

    ScanConfig config;
    std::wstring config_name;

    switch (scan_choice) {
    case 1:
        config = ScanPresets::quick_scan();
        config_name = L"Quick Scan";
        break;
    case 3:
        config = ScanPresets::deep_scan();
        config_name = L"Deep Scan";
        break;
    case 4:
        config = ScanPresets::malware_hunting();
        config_name = L"Malware Hunting";
        break;
    case 5:
        config = configure_custom_scan();
        config_name = L"Custom Configuration";
        break;
    default:
        config = ScanPresets::executable_files_only();
        config_name = L"Standard Scan";
        break;
    }

    std::wcout << L"\nUsing configuration: " << config_name << L"\n";
    std::wcout << L"  Recursive: " << (config.recursive ? L"Yes" : L"No") << L"\n";
    std::wcout << L"  Max depth: " << config.max_depth << L"\n";
    std::wcout << L"  Max file size: " << (config.max_file_size / (1024 * 1024)) << L" MB\n";
    std::wcout << L"  File extensions: ";
    if (config.file_extensions.empty()) {
        std::wcout << L"All files\n";
    }
    else {
        bool first = true;
        for (const auto& ext : config.file_extensions) {
            if (!first) std::wcout << L", ";
            std::wcout << ext;
            first = false;
        }
        std::wcout << L"\n";
    }

    std::wcout << L"\nPress Enter to start scan, or 'q' to cancel: ";
    std::string confirm;
    std::getline(std::cin, confirm);

    if (confirm == "q" || confirm == "Q") {
        std::wcout << L"Scan cancelled.\n";
        return;
    }

    std::wcout << L"\nStarting scan...\n";
    std::wcout << L"Press Ctrl+C to cancel\n\n";

    try {
        // Set up progress callback for interactive mode
        auto progress_callback = [](size_t current, size_t total, const std::wstring& current_file) {
            if (total == 0) return;

            // Update progress every 5 files or at completion
            if (current % 5 == 0 || current == total) {
                ProgressIndicator::show_progress(current, total);

                // Show current file (truncated)
                if (current < total && !current_file.empty()) {
                    std::wstring display_file = current_file;
                    if (display_file.length() > 40) {
                        display_file = L"..." + display_file.substr(display_file.length() - 37);
                    }
                    std::wcout << L" - " << display_file;
                }
                std::wcout.flush();
            }

            if (current == total) {
                ProgressIndicator::clear_line();
                ConsoleColor::print_success(L"Scan completed successfully!\n\n");
            }
            };

        // Perform the scan
        auto results = scan_directory_enhanced_impl(dir_path, config, progress_callback);

        // Update session statistics
        SessionStats::increment_scanned();
        for (const auto& result : results) {
            if (result.scan_successful) {
                if (result.scan_result.overallThreat >= ThreatLevel::Suspicious) {
                    SessionStats::increment_threats();
                }
                else {
                    SessionStats::increment_clean();
                }
            }
            else {
                SessionStats::increment_errors();
            }
        }

        // Offer to save detailed report
        if (!results.empty()) {
            std::wcout << L"Would you like to save a detailed report? (y/N): ";
            std::string save_choice;
            std::getline(std::cin, save_choice);

            if (save_choice == "y" || save_choice == "Y") {
                // Create a scanner to get stats for the report
                DirectoryScanner scanner(config);
                save_directory_scan_report(results, scanner.get_stats(), dir_path);
            }
        }

    }
    catch (const std::exception& e) {
        ConsoleColor::print_error(L"Scan failed: ");
        std::wcout << to_wide(e.what()) << L"\n";
        SessionStats::increment_errors();
    }
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

ScanConfig InteractiveMode::configure_custom_scan() {
    ScanConfig config;

    std::wcout << L"\n=== Custom Scan Configuration ===\n";

    // Recursive scanning
    std::wcout << L"Enable recursive scanning? (Y/n): ";
    std::string input;
    std::getline(std::cin, input);
    config.recursive = (input != "n" && input != "N");

    if (config.recursive) {
        // Max depth
        std::wcout << L"Maximum directory depth (1-50, default 10): ";
        std::getline(std::cin, input);
        if (!input.empty()) {
            try {
                int depth = std::stoi(input);
                config.max_depth = std::max(1, std::min(50, depth));
            }
            catch (...) {
                config.max_depth = 10;
            }
        }
    }

    // File size limit
    std::wcout << L"Maximum file size in MB (1-1000, default 100): ";
    std::getline(std::cin, input);
    if (!input.empty()) {
        try {
            int size_mb = std::stoi(input);
            size_mb = std::max(1, std::min(1000, size_mb));
            config.max_file_size = size_mb * 1024 * 1024;
        }
        catch (...) {
            config.max_file_size = 100 * 1024 * 1024;
        }
    }

    // File extensions
    std::wcout << L"File extensions to scan (comma-separated, e.g., .exe,.dll,.sys):\n";
    std::wcout << L"Leave empty for all files: ";
    std::getline(std::cin, input);

    if (!input.empty()) {
        config.file_extensions.clear();
        std::istringstream iss(input);
        std::string ext;

        while (std::getline(iss, ext, ',')) {
            // Trim whitespace
            ext.erase(0, ext.find_first_not_of(" \t"));
            ext.erase(ext.find_last_not_of(" \t") + 1);

            // Add dot if missing
            if (!ext.empty() && ext[0] != '.') {
                ext = "." + ext;
            }

            if (!ext.empty()) {
                std::wstring wext = to_wide(ext);
                std::transform(wext.begin(), wext.end(), wext.begin(), towlower);
                config.file_extensions.insert(wext);
            }
        }
    }
    else {
        config.file_extensions.clear(); // Scan all files
    }

    // Include hidden files
    std::wcout << L"Include hidden files? (y/N): ";
    std::getline(std::cin, input);
    config.include_hidden = (input == "y" || input == "Y");

    // Include system files
    std::wcout << L"Include system files? (y/N): ";
    std::getline(std::cin, input);
    config.include_system = (input == "y" || input == "Y");

    return config;
}