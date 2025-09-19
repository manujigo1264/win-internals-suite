#pragma once
#include "common.h"
#include <string>
#include <iostream>

class InteractiveMode {
public:
    static int run();

private:
    static void show_main_menu();
    static int get_user_choice(int min, int max);
    static std::string get_user_input(const std::string& prompt);
    static DWORD get_pid_input();
    static std::wstring get_path_input(const std::string& prompt);

    // Menu handlers
    static void handle_process_list();
    static void handle_module_analysis();
    static void handle_pe_analysis();
    static void handle_malware_scan();
    static void handle_batch_scan();
    static void handle_settings();

    // Utility functions
    static void pause();
    static void clear_screen();
};