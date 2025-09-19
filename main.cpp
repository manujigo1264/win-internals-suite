#include "common.h"
#include "proc_enum.h"
#include "pe_parser.h"
#include "dll_analyzer.h"
#include "ui_helpers.h"
#include "interactive.h"
#include "options.h"
#include "console_color.h"
#include "session_stats.h"
#include <iostream>
#include <fstream>
#include <io.h>
#include <fcntl.h>

// Function to redirect output to file if specified
class OutputRedirector {
private:
    std::wofstream file_stream;
    std::streambuf* original_cout;
    std::wstreambuf* original_wcout;

public:
    OutputRedirector(const std::string& filename) {
        if (!filename.empty()) {
            file_stream.open(filename);
            if (file_stream.is_open()) {
                original_cout = std::cout.rdbuf();
                original_wcout = std::wcout.rdbuf();
                std::wcout.rdbuf(file_stream.rdbuf());
            }
        }
    }

    ~OutputRedirector() {
        if (file_stream.is_open()) {
            std::cout.rdbuf(original_cout);
            std::wcout.rdbuf(original_wcout);
            file_stream.close();
        }
    }

    bool is_redirecting() const {
        return file_stream.is_open();
    }
};

int execute_command(const Options& opts) {
    // Setup output redirection if specified
    OutputRedirector redirector(opts.output_file);

    // Initialize UI components
    ConsoleColor::initialize();
    ConsoleColor::enable_color(!opts.no_color && !redirector.is_redirecting());
    SessionStats::initialize();

    const std::string& cmd = opts.command;
    const auto& args = opts.args;

    try {
        if (cmd == "ps") {
            if (opts.verbose) {
                ConsoleColor::print_info(L"Starting enhanced process enumeration...\n");
            }
            cmd_ps_improved();
            return 0;
        }
        else if (cmd == "ps-enhanced") {
            if (args.empty()) {
                cmd_ps_improved();
            }
            else {
                cmd_ps_improved(to_wide(args[0]));
            }
            return 0;
        }
        else if (cmd == "mods") {
            if (args.empty()) {
                ConsoleColor::print_error(L"usage: winsuite mods <pid>\n");
                return 1;
            }
            DWORD pid = static_cast<DWORD>(std::stoul(args[0]));
            cmd_mods(pid);
            return 0;
        }
        else if (cmd == "mods-enhanced") {
            if (args.empty()) {
                ConsoleColor::print_error(L"usage: winsuite mods-enhanced <pid>\n");
                return 1;
            }
            DWORD pid = static_cast<DWORD>(std::stoul(args[0]));
            cmd_mods_improved(pid);
            return 0;
        }
        else if (cmd == "pe") {
            if (args.empty()) {
                ConsoleColor::print_error(L"usage: winsuite pe <path>\n");
                return 1;
            }
            PEInfo pe;
            if (!parse_pe_file(to_wide(args[0]), pe)) {
                ConsoleColor::print_error(L"parse failed\n");
                return 2;
            }
            print_pe(pe, to_wide(args[0]));
            SessionStats::increment_scanned();
            return 0;
        }
        else if (cmd == "scan") {
            if (args.empty()) {
                ConsoleColor::print_error(L"usage: winsuite scan <path>\n");
                return 1;
            }
            scan_file(to_wide(args[0]));
            SessionStats::increment_scanned();
            return 0;
        }
        else if (cmd == "scan-enhanced") {
            if (args.empty()) {
                ConsoleColor::print_error(L"usage: winsuite scan-enhanced <path>\n");
                return 1;
            }

            if (opts.verbose) {
                ConsoleColor::print_info(L"Starting advanced malware scan...\n");
            }

            MalwareScanner scanner;
            ScanResult result = scanner.scan_file(to_wide(args[0]));
            ScanReporter::print_scan_result(result);

            SessionStats::increment_scanned();
            if (result.overallThreat >= ThreatLevel::Suspicious) {
                SessionStats::increment_threats();
            }
            else {
                SessionStats::increment_clean();
            }
            return 0;
        }
        else if (cmd == "batch-scan") {
            if (args.empty()) {
                ConsoleColor::print_error(L"usage: winsuite batch-scan <directory>\n");
                return 1;
            }
            scan_directory_enhanced(to_wide(args[0]));
            return 0;
        }
        else {
            ConsoleColor::print_error(L"Unknown command: ");
            std::wcout << to_wide(cmd) << L"\n\n";
            usage();
            return 1;
        }
    }
    catch (const std::exception& e) {
        ConsoleColor::print_error(L"Error: ");
        std::wcout << to_wide(e.what()) << L"\n";
        return 1;
    }
}

int main(int argc, char** argv) {
    // Allocate a console for this application if running from double-click
    if (!GetConsoleWindow()) {
        if (AllocConsole()) {
            // Redirect stdin, stdout, stderr to console
            freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
            freopen_s((FILE**)stderr, "CONOUT$", "w", stderr);
            freopen_s((FILE**)stdin, "CONIN$", "r", stdin);

            // Make cout, wcout, cin, wcin work with console
            std::ios::sync_with_stdio(true);
        }
    }

    // Set console title
    SetConsoleTitleA("WinSuite Security Toolkit");

    // Enable Unicode console output
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    // Parse command line options
    Options opts = Options::parse_args(argc, argv);

    // Handle help request
    if (opts.help) {
        opts.print_help();
        return 0;
    }

    // Handle interactive mode or no arguments
    if (opts.interactive || !opts.is_valid()) {
        return InteractiveMode::run();
    }

    // Execute the specified command
    int result = execute_command(opts);

    // Show session summary if verbose mode
    if (opts.verbose) {
        SessionStats::print_summary();
    }

    return result;
}