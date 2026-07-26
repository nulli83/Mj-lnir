#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

namespace Mjolnir {

    class MemoryManager {
    public:
        // Find a process ID by its executable name
        static DWORD GetProcessIdByName(const std::wstring& processName) {
            DWORD processId = 0;
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return 0;
            }

            PROCESSENTRY32W processEntry;
            processEntry.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(hSnapshot, &processEntry)) {
                do {
                    if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0) {
                        processId = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(hSnapshot, &processEntry));
            }

            CloseHandle(hSnapshot);
            return processId;
        }

        // Open a target process handle with specified access rights
        static HANDLE OpenTargetProcess(DWORD pid, DWORD desiredAccess) {
            return OpenProcess(desiredAccess, FALSE, pid);
        }

        // Safe template wrapper to read structured memory from the target process
        template <typename T>
        static bool ReadMemory(HANDLE hProcess, uintptr_t address, T& buffer) {
            SIZE_T bytesRead = 0;
            return ReadProcessMemory(
                hProcess, 
                reinterpret_cast<LPCVOID>(address), 
                &buffer, 
                sizeof(T), 
                &bytesRead
            ) && bytesRead == sizeof(T);
        }

        // Byte pattern signature scanner within virtual address space
        static uintptr_t ScanPattern(HANDLE hProcess, const unsigned char* signature, const char* mask, uintptr_t startAddress, size_t searchSize) {
            std::vector<unsigned char> buffer(searchSize);
            SIZE_T bytesRead = 0;

            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(startAddress), buffer.data(), searchSize, &bytesRead)) {
                return 0;
            }

            for (size_t i = 0; i < bytesRead; ++i) {
                bool found = true;
                for (size_t j = 0; mask[j] != '\0'; ++j) {
                    if (mask[j] == 'x' && buffer[i + j] != signature[j]) {
                        found = false;
                        break;
                    }
                }
                if (found) {
                    return startAddress + i;
                }
            }
            return 0;
        }
    };

} // namespace Mjolnir
