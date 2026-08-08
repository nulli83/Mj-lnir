#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <psapi.h>

#include <cstdint>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace Mjolnir {

    struct WritableImageFinding {
        std::string moduleName;
        std::uintptr_t address = 0;
        std::size_t regionSize = 0;
        DWORD protect = 0;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct WritableImageScanResult {
        std::vector<WritableImageFinding> findings;
        std::size_t regionsScanned = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    /*
     * Letar efter MEM_IMAGE-regioner som är writable+executable —
     * typiskt tecken på code caves / in-image patches.
     */
    class WritableImageScanner {
    private:
        static bool IsWritableExecutable(DWORD protect) {
            const DWORD base = protect & 0xFF;
            return
                base == PAGE_EXECUTE_READWRITE ||
                base == PAGE_EXECUTE_WRITECOPY;
        }

        static bool IsExecutable(DWORD protect) {
            const DWORD base = protect & 0xFF;
            return
                base == PAGE_EXECUTE ||
                base == PAGE_EXECUTE_READ ||
                base == PAGE_EXECUTE_READWRITE ||
                base == PAGE_EXECUTE_WRITECOPY;
        }

        static std::string ModuleNameForAddress(
            HANDLE process,
            std::uintptr_t address
        ) {
            HMODULE modules[512] = {};
            DWORD needed = 0;
            if (
                !EnumProcessModulesEx(
                    process,
                    modules,
                    sizeof(modules),
                    &needed,
                    LIST_MODULES_ALL
                )
            ) {
                return {};
            }

            MODULEINFO info{};
            const DWORD count = needed / sizeof(HMODULE);
            for (DWORD index = 0; index < count; ++index) {
                if (
                    !GetModuleInformation(
                        process,
                        modules[index],
                        &info,
                        sizeof(info)
                    )
                ) {
                    continue;
                }

                const auto base =
                    reinterpret_cast<std::uintptr_t>(info.lpBaseOfDll);
                const auto end = base + info.SizeOfImage;
                if (address < base || address >= end) {
                    continue;
                }

                wchar_t path[MAX_PATH] = {};
                if (
                    GetModuleFileNameExW(
                        process,
                        modules[index],
                        path,
                        MAX_PATH
                    ) == 0
                ) {
                    return {};
                }

                const wchar_t* file = path;
                for (wchar_t* cursor = path; *cursor != L'\0'; ++cursor) {
                    if (*cursor == L'\\' || *cursor == L'/') {
                        file = cursor + 1;
                    }
                }

                char narrow[MAX_PATH] = {};
                WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    file,
                    -1,
                    narrow,
                    sizeof(narrow),
                    nullptr,
                    nullptr
                );
                return narrow;
            }

            return {};
        }

    public:
        static WritableImageScanResult Scan(
            HANDLE process,
            int baseWeight = 55
        ) {
            WritableImageScanResult result{};

            if (process == nullptr) {
                result.errorCode = ERROR_INVALID_HANDLE;
                return result;
            }

            SYSTEM_INFO systemInfo{};
            GetSystemInfo(&systemInfo);

            std::uintptr_t address =
                reinterpret_cast<std::uintptr_t>(
                    systemInfo.lpMinimumApplicationAddress
                );
            const std::uintptr_t maximum =
                reinterpret_cast<std::uintptr_t>(
                    systemInfo.lpMaximumApplicationAddress
                );

            while (address < maximum) {
                MEMORY_BASIC_INFORMATION mbi{};
                const SIZE_T queried = VirtualQueryEx(
                    process,
                    reinterpret_cast<LPCVOID>(address),
                    &mbi,
                    sizeof(mbi)
                );

                if (queried == 0) {
                    break;
                }

                const std::uintptr_t regionBase =
                    reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
                const std::size_t regionSize = mbi.RegionSize;

                if (
                    mbi.State == MEM_COMMIT &&
                    mbi.Type == MEM_IMAGE &&
                    IsExecutable(mbi.Protect)
                ) {
                    ++result.regionsScanned;

                    if (IsWritableExecutable(mbi.Protect)) {
                        WritableImageFinding finding{};
                        finding.address = regionBase;
                        finding.regionSize = regionSize;
                        finding.protect = mbi.Protect;
                        finding.moduleName =
                            ModuleNameForAddress(process, regionBase);
                        finding.riskScore = baseWeight;
                        finding.reasons.push_back(
                            "MEM_IMAGE region is writable and executable"
                        );
                        result.findings.push_back(std::move(finding));
                    }
                }

                if (regionSize == 0) {
                    break;
                }

                address = regionBase + regionSize;
            }

            return result;
        }
    };

} // namespace Mjolnir
