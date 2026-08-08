#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <psapi.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace Mjolnir {

    struct ExceptionDispatchFinding {
        std::string functionName;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct ExceptionDispatchScanResult {
        std::vector<ExceptionDispatchFinding> findings;
        std::size_t functionsChecked = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    /*
     * Detekterar patchade exception/VEH-dispatcher exports.
     * Cheats och anti-anti-debug hookar ofta KiUserExceptionDispatcher
     * eller RtlAddVectoredExceptionHandler för att dölja breakpoints.
     */
    class ExceptionDispatchScanner {
    private:
        static bool ReadRemoteBytes(
            HANDLE process,
            std::uintptr_t address,
            void* buffer,
            std::size_t size
        ) {
            SIZE_T read = 0;
            return ReadProcessMemory(
                       process,
                       reinterpret_cast<LPCVOID>(address),
                       buffer,
                       size,
                       &read
                   ) != FALSE &&
                   read == size;
        }

        static std::uintptr_t FindRemoteModule(
            HANDLE process,
            const wchar_t* moduleName
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
                return 0;
            }

            const DWORD count = needed / sizeof(HMODULE);
            for (DWORD index = 0; index < count; ++index) {
                wchar_t path[MAX_PATH] = {};
                if (
                    GetModuleFileNameExW(
                        process,
                        modules[index],
                        path,
                        MAX_PATH
                    ) == 0
                ) {
                    continue;
                }

                const wchar_t* file = path;
                for (wchar_t* cursor = path; *cursor != L'\0'; ++cursor) {
                    if (*cursor == L'\\' || *cursor == L'/') {
                        file = cursor + 1;
                    }
                }

                if (_wcsicmp(file, moduleName) == 0) {
                    return reinterpret_cast<std::uintptr_t>(modules[index]);
                }
            }

            return 0;
        }

        static std::uintptr_t RemoteProcAddress(
            HANDLE process,
            std::uintptr_t moduleBase,
            const char* name
        ) {
            IMAGE_DOS_HEADER dos{};
            if (
                !ReadRemoteBytes(process, moduleBase, &dos, sizeof(dos)) ||
                dos.e_magic != IMAGE_DOS_SIGNATURE
            ) {
                return 0;
            }

            IMAGE_NT_HEADERS64 nt{};
            if (
                !ReadRemoteBytes(
                    process,
                    moduleBase + static_cast<std::uintptr_t>(dos.e_lfanew),
                    &nt,
                    sizeof(nt)
                ) ||
                nt.Signature != IMAGE_NT_SIGNATURE
            ) {
                return 0;
            }

            const auto& dir =
                nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (dir.VirtualAddress == 0) {
                return 0;
            }

            IMAGE_EXPORT_DIRECTORY exports{};
            if (
                !ReadRemoteBytes(
                    process,
                    moduleBase + dir.VirtualAddress,
                    &exports,
                    sizeof(exports)
                )
            ) {
                return 0;
            }

            for (DWORD index = 0; index < exports.NumberOfNames; ++index) {
                DWORD nameRva = 0;
                if (
                    !ReadRemoteBytes(
                        process,
                        moduleBase + exports.AddressOfNames + index * sizeof(DWORD),
                        &nameRva,
                        sizeof(nameRva)
                    )
                ) {
                    continue;
                }

                char remoteName[96] = {};
                if (
                    !ReadRemoteBytes(
                        process,
                        moduleBase + nameRva,
                        remoteName,
                        sizeof(remoteName) - 1
                    )
                ) {
                    continue;
                }

                if (std::strcmp(remoteName, name) != 0) {
                    continue;
                }

                WORD ordinal = 0;
                if (
                    !ReadRemoteBytes(
                        process,
                        moduleBase +
                            exports.AddressOfNameOrdinals +
                            index * sizeof(WORD),
                        &ordinal,
                        sizeof(ordinal)
                    )
                ) {
                    return 0;
                }

                DWORD funcRva = 0;
                if (
                    !ReadRemoteBytes(
                        process,
                        moduleBase +
                            exports.AddressOfFunctions +
                            ordinal * sizeof(DWORD),
                        &funcRva,
                        sizeof(funcRva)
                    )
                ) {
                    return 0;
                }

                return moduleBase + funcRva;
            }

            return 0;
        }

        static bool LooksHooked(
            const std::uint8_t* remote,
            const std::uint8_t* local
        ) {
            if (std::memcmp(remote, local, 8) == 0) {
                return false;
            }

            /*
             * JMP / FF25 trampoline / INT3 / ret stub.
             */
            if (
                remote[0] == 0xE9 ||
                remote[0] == 0xE8 ||
                remote[0] == 0xCC ||
                remote[0] == 0xC3 ||
                remote[0] == 0xC2 ||
                (remote[0] == 0xFF && remote[1] == 0x25) ||
                (remote[0] == 0x48 && remote[1] == 0xB8) ||
                (remote[0] == 0x48 && remote[1] == 0xFF && remote[2] == 0x25)
            ) {
                return true;
            }

            /*
             * Generic divergence from local ntdll copy.
             */
            std::size_t mismatch = 0;
            for (std::size_t index = 0; index < 8; ++index) {
                if (remote[index] != local[index]) {
                    ++mismatch;
                }
            }

            return mismatch >= 3;
        }

    public:
        static ExceptionDispatchScanResult Scan(
            HANDLE process,
            int baseWeight = 65
        ) {
            ExceptionDispatchScanResult result{};

            if (process == nullptr) {
                result.errorCode = ERROR_INVALID_HANDLE;
                return result;
            }

            const std::uintptr_t remoteNtdll =
                FindRemoteModule(process, L"ntdll.dll");
            HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");
            if (remoteNtdll == 0 || localNtdll == nullptr) {
                result.errorCode = ERROR_MOD_NOT_FOUND;
                return result;
            }

            static const char* kTargets[] = {
                "KiUserExceptionDispatcher",
                "RtlDispatchException",
                "RtlAddVectoredExceptionHandler",
                "RtlRemoveVectoredExceptionHandler",
                "RtlAddVectoredContinueHandler",
                "KiUserApcDispatcher",
            };

            for (const char* name : kTargets) {
                const std::uintptr_t remoteAddress =
                    RemoteProcAddress(process, remoteNtdll, name);
                FARPROC localAddress = GetProcAddress(localNtdll, name);
                if (remoteAddress == 0 || localAddress == nullptr) {
                    continue;
                }

                ++result.functionsChecked;

                std::uint8_t remoteBytes[8] = {};
                std::uint8_t localBytes[8] = {};
                if (
                    !ReadRemoteBytes(
                        process,
                        remoteAddress,
                        remoteBytes,
                        sizeof(remoteBytes)
                    )
                ) {
                    continue;
                }

                std::memcpy(
                    localBytes,
                    reinterpret_cast<const void*>(localAddress),
                    sizeof(localBytes)
                );

                if (!LooksHooked(remoteBytes, localBytes)) {
                    continue;
                }

                ExceptionDispatchFinding finding{};
                finding.functionName = name;
                finding.riskScore = baseWeight;
                if (
                    std::strcmp(name, "KiUserExceptionDispatcher") == 0 ||
                    std::strcmp(name, "KiUserApcDispatcher") == 0
                ) {
                    finding.riskScore = baseWeight + 10;
                }
                finding.reasons.push_back(
                    "Exception/VEH/APC dispatcher prologue diverges from local ntdll"
                );
                result.findings.push_back(std::move(finding));
            }

            return result;
        }
    };

} // namespace Mjolnir
