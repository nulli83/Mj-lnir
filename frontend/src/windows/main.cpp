#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <windows.h>
#include "memory.hpp"
#include "config.hpp"
#include "modules.hpp"
#include "overlay.hpp"

const std::wstring TARGET_PROCESS = L"game.exe";

// Unified logging function writing to console and log/sample.log
void WriteLog(const std::string& level, const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << "[" << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S") << "] "
       << "[" << level << "] " << message;

    // 1. Output to console
    std::cout << ss.str() << "\n";

    // 2. Append to log file
    std::ofstream logFile("log/sample.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << ss.str() << "\n";
    }
}

void PrintBanner() {
    WriteLog("INFO", "[Mjölnir v1.0.0-alpha] - User-Mode Security Daemon Initialized.");
    WriteLog("INFO", "[+] Monitoring process vectors, modules, and overlays... [ACTIVE]");
    WriteLog("INFO", "------------------------------------------------------------");
}

int main() {
    PrintBanner();

    DWORD targetPid = 0;
    Mjolnir::ConfigManager config;
    
    // Load whitelist configuration
    if (config.LoadConfig("whitelist.json")) {
        WriteLog("INFO", "Successfully loaded whitelist.json configuration.");
    } else {
        WriteLog("WARN", "Failed to load whitelist.json. Running with default rules.");
    }

    while (true) {
        if (targetPid == 0) {
            targetPid = Mjolnir::MemoryManager::GetProcessIdByName(TARGET_PROCESS);
            if (targetPid != 0) {
                WriteLog("INFO", "Target process detected. PID: " + std::to_string(targetPid));
            }
        } else {
            // Open handle with query and read permissions
            HANDLE hProcess = Mjolnir::MemoryManager::OpenTargetProcess(
                targetPid, 
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
            );
            
            if (!hProcess) {
                WriteLog("WARN", "Lost connection to target process. Resetting PID tracking.");
                targetPid = 0;
            } else {
                // 1. Audit loaded DLL modules inside the target process
                auto modules = Mjolnir::ModuleScanner::GetLoadedModules(targetPid);
                // Optional: Iterate and evaluate modules against rules here

                // 2. Audit active windows/overlays across the environment
                auto activeWindows = Mjolnir::OverlayDetector::GetActiveWindows();
                for (const auto& win : activeWindows) {
                    if (win.processId == targetPid) {
                        // Handle windows belonging to the target process if needed
                    }
                }

                CloseHandle(hProcess);
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    return 0;
}
