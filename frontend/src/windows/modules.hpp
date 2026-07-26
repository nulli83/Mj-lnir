#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <algorithm>

namespace Mjolnir {

    class ModuleScanner {
    public:
        // Enumerates all loaded modules/DLLs in the target process
        static std::vector<std::string> GetLoadedModules(DWORD pid) {
            std::vector<std::string> modules;
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return modules;
            }

            MODULEENTRY32W modEntry;
            modEntry.dwSize = sizeof(MODULEENTRY32W);

            if (Module32FirstW(hSnapshot, &modEntry)) {
                do {
                    std::wstring wModName(modEntry.szModule);
                    std::string modName(wModName.begin(), wModName.end());
                    modules.push_back(modName);
                } while (Module32NextW(hSnapshot, &modEntry));
            }

            CloseHandle(hSnapshot);
            return modules;
        }
    };

} // namespace Mjolnir
