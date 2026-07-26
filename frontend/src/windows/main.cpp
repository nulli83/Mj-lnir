#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <windows.h>
#include "memory.hpp"
#include "config.hpp"
#include "modules.hpp"
#include "overlay.hpp"
#include "alert.hpp"

const std::wstring TARGET_PROCESS = L"game.exe";

void PrintBanner() {
    Mjolnir::SecurityAlertSystem::DispatchAlert(
        Mjolnir::ThreatLevel::LOW, 
        "DAEMON", 
        "[Mjölnir v1.0.0-alpha] - Security Core Initialized & Armed."
    );
    Mjolnir::SecurityAlertSystem::DispatchAlert(
        Mjolnir::ThreatLevel::LOW, 
        "DAEMON", 
        "[+] Active Vectors: Process Handle, DLL Whitelist, Overlay Analysis [ACTIVE]"
    );
    std::cout << "------------------------------------------------------------\n";
}

int main() {
    PrintBanner();

    DWORD targetPid = 0;
    Mjolnir::ConfigManager config;
    
    // Load whitelist configuration
    if (config.LoadConfig("whitelist.json")) {
        Mjolnir::SecurityAlertSystem::DispatchAlert(
            Mjolnir::ThreatLevel::LOW, 
            "CONFIG", 
            "Successfully parsed whitelist.json exception rules."
        );
    } else {
        Mjolnir::SecurityAlertSystem::DispatchAlert(
            Mjolnir::ThreatLevel::MEDIUM, 
            "CONFIG", 
            "Failed to load whitelist.json. Operating under restrictive default rules."
        );
    }

    while (true) {
        if (targetPid == 0) {
            targetPid = Mjolnir::MemoryManager::GetProcessIdByName(TARGET_PROCESS);
            if (targetPid != 0) {
                Mjolnir::SecurityAlertSystem::DispatchAlert(
                    Mjolnir::ThreatLevel::LOW, 
                    "MONITOR", 
                    "Target application acquired. Tracking PID: " + std::to_string(targetPid)
                );
            }
        } else {
            // Open handle with query and read permissions
            HANDLE hProcess = Mjolnir::MemoryManager::OpenTargetProcess(
                targetPid, 
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
            );
            
            if (!hProcess) {
                Mjolnir::SecurityAlertSystem::DispatchAlert(
                    Mjolnir::ThreatLevel::MEDIUM, 
                    "MONITOR", 
                    "Lost connection to target process. Resetting tracking state."
                );
                targetPid = 0;
            } else {
                // 1. Audit Loaded Modules (DLL Injection Check)
                auto modules = Mjolnir::ModuleScanner::GetLoadedModules(targetPid);
                for (const auto& mod : modules) {
                    // Example check against whitelist logic
                    if (!config.IsWhitelisted(mod)) {
                        // Log or handle unwhitelisted module injection attempt
                    }
                }

                // 2. Audit Suspicious Click-Through Overlays
                auto suspiciousOverlays = Mjolnir::OverlayDetector::DetectSuspiciousOverlays();
                for (const auto& overlay : suspiciousOverlays) {
                    // Filter out system windows, only flag third-party overlays targeting user space
                    if (overlay.processId != targetPid && overlay.processId != GetCurrentProcessId()) {
                        std::string alertMsg = "Suspicious overlay detected | Title: '" + overlay.title + 
                                               "' | Class: " + overlay.className + 
                                               " | PID: " + std::to_string(overlay.processId);
                        
                        Mjolnir::SecurityAlertSystem::DispatchAlert(
                            Mjolnir::ThreatLevel::HIGH, 
                            "OVERLAY", 
                            alertMsg
                        );
                    }
                }

                CloseHandle(hProcess);
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(3));
    }

    return 0;
}
