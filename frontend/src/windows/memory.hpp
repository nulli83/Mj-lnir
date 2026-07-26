#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

namespace Mjolnir {

    class MemoryManager {
    public:
        // Find a Process ID by its executable name (e.g., "game.exe")
        static DWORD GetProcessIdByName(const std::wstring& processName) {
            DWORD processId = 0;
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            
            if (snapshot == INVALID_HANDLE_VALUE) {
                return 0;
            }

            PROCESSENTRY32W processEntry;
            processEntry.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(snapshot, &processEntry)) {
                do {
                    if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0) {
                        processId = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(snapshot, &processEntry));
            }

            CloseHandle(snapshot);
            return processId;
        }

        // Open a handle to a target process with specified access rights
        static HANDLE OpenTargetProcess(DWORD processId, DWORD desiredAccess) {
            HANDLE hProcess = OpenProcess(desiredAccess, FALSE, processId);
            if (!hProcess) {
                std::cerr << "[-] Failed to open process handle. Error: " << GetLastError() << "\n";
                return nullptr;
            }
            return hProcess;
        }

        // Basic memory safety check: Verify if a region is accessible and not unbacked/suspicious
        static bool IsMemoryRegionValid(HANDLE hProcess, void* address) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                // Check if memory is committed and not guard/free pages
                if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS)) {
                    return true;
                }
            }
            return false;
        }

        // Template function to read process memory safely
        template <typename T>
        static T ReadMemory(HANDLE hProcess, uintptr_t address) {
            T buffer{};
            if (!IsMemoryRegionValid(hProcess, reinterpret_cast<void*>(address))) {
                return buffer;
            }
            ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), &buffer, sizeof(T), nullptr);
            return buffer;
        }
    };

} // namespace Mjolnir
