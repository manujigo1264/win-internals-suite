#include "options.h"
#include "ui_helpers.h"
#include <iostream>

Options Options::parse_args(int argc, char** argv) {
    Options opts;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            opts.help = true;
        }
        else if (arg == "-v" || arg == "--verbose") {
            opts.verbose = true;
        }
        else if (arg == "--json") {
            opts.json_output = true;
        }
        else if (arg == "--no-color") {
            opts.no_color = true;
        }
        else if (arg == "-i" || arg == "--interactive") {
            opts.interactive = true;
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) {
                opts.output_file = argv[++i];
            }
            else {
                std::cerr << "Error: -o requires a filename\n";
                opts = Options(); // Reset to invalid state
                return opts;
            }
        }
        else if (arg.length() > 0 && arg[0] == '-') {
            std::cerr << "Error: Unknown option '" << arg << "'\n";
            opts = Options(); // Reset to invalid state
            return opts;
        }
        else {
            // First non-option argument is the command
            if (opts.command.empty()) {
                opts.command = arg;
            }
            else {
                opts.args.push_back(arg);
            }
        }
    }

    return opts;
}

void Options::print_help() const {
    usage();
}

bool Options::is_valid() const {
    // If help is requested, it's always valid
    if (help) return true;

    // If interactive mode requested, it's valid
    if (interactive) return true;

    // Otherwise, we need a command
    return !command.empty();
}