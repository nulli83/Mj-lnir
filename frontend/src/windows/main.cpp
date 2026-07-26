#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include "memory.hpp"

const std::wstring TARGET_PROCESS = L"game.exe";

void PrintBanner() {
    std::cout << "[Mjölnir v1.0.0-alpha] - User-Mode Security Daemon Initialized.\n";
    std::cout << "[+] Monitoring process vectors & handle security... [ACTIVE]\n";
    std::cout << "------------------------------------------------------------\n";
}

int main() {
    PrintBanner();

    DWORD targetPid = 0;

    while (true) {
        if (targetPid == 0) {
            targetPid = Mjolnir::MemoryManager::GetProcessIdByName(TARGET_PROCESS);
            if (targetPid != 0) {
                std::cout << "[+] Target process detected. PID: " << targetPid << "\n";
            }
        } else {
            // Open handle with query and read rights (safe user-mode access)
            HANDLE hProcess = Mjolnir::MemoryManager::OpenTargetProcess(
                targetPid, 
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
            );
            
            if (!hProcess) {
                std::cout << "[-] Lost connection to target process. Resetting PID tracking.\n";
                targetPid = 0;
            } else {
                // User-mode check placeholder: 
                // You can expand memory.hpp to check module lists, thread counts, 
                // or look for unauthorized access attempts here.
                
                CloseHandle(hProcess);
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    return 0;
}
