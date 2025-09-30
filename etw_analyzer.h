#pragma once
#include <string>
#include <tdh.h>


// Starts a real-time kernel ETW session (proc/thread/image) and blocks until stopped.
// Returns 0 on success, non-zero on error. Requires Administrator.
int run_etw_analyzer();

// Optional convenience wrappers if you want explicit start/stop in the future.
bool etw_start();
void etw_stop();
