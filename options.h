#pragma once
#include <string>
#include <vector>

struct Options {
    bool verbose = false;
    bool json_output = false;
    bool no_color = false;
    bool help = false;
    bool interactive = false;
    std::string output_file;
    std::string command;
    std::vector<std::string> args;

    static Options parse_args(int argc, char** argv);
    void print_help() const;
    bool is_valid() const;
};