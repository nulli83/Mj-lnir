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

    struct EtwFinding {
        std::string functionName;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct EtwScanResult {
        std::vector<EtwFinding> findings;
        std::size_t functionsChecked = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    /*
     * Detekterar patchade ETW-relaterade exports (vanlig anti-telemetry
     * / cheat-bypass teknik: ret 0 / xor eax,eax;ret på EtwEventWrite).
     */
    class EtwPatchScanner {
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

                char remoteName[64] = {};
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

        static bool LooksPatched(const std::uint8_t* bytes) {
            /*
             * ret / ret 0 / xor eax,eax ; ret / mov eax,0 ; ret
             */
            if (bytes[0] == 0xC3) {
                return true;
            }
            if (bytes[0] == 0xC2) {
                return true;
            }
            if (bytes[0] == 0x33 && bytes[1] == 0xC0 && bytes[2] == 0xC3) {
                return true;
            }
            if (
                bytes[0] == 0x31 && bytes[1] == 0xC0 && bytes[2] == 0xC3
            ) {
                return true;
            }
            if (
                bytes[0] == 0xB8 &&
                bytes[1] == 0x00 &&
                bytes[2] == 0x00 &&
                bytes[3] == 0x00 &&
                bytes[4] == 0x00 &&
                bytes[5] == 0xC3
            ) {
                return true;
            }
            if (bytes[0] == 0xE9 || (bytes[0] == 0xFF && bytes[1] == 0x25)) {
                return true;
            }

            return false;
        }

    public:
        static EtwScanResult Scan(HANDLE process, int baseWeight = 70) {
            EtwScanResult result{};

            if (process == nullptr) {
                result.errorCode = ERROR_INVALID_HANDLE;
                return result;
            }

            const std::uintptr_t ntdll =
                FindRemoteModule(process, L"ntdll.dll");
            if (ntdll == 0) {
                result.errorCode = ERROR_MOD_NOT_FOUND;
                return result;
            }

            static const char* kTargets[] = {
                "EtwEventWrite",
                "EtwEventWriteFull",
                "NtTraceEvent",
                "EtwWrite",
            };

            for (const char* name : kTargets) {
                const std::uintptr_t address =
                    RemoteProcAddress(process, ntdll, name);
                if (address == 0) {
                    continue;
                }

                ++result.functionsChecked;

                std::uint8_t bytes[8] = {};
                if (!ReadRemoteBytes(process, address, bytes, sizeof(bytes))) {
                    continue;
                }

                if (!LooksPatched(bytes)) {
                    continue;
                }

                EtwFinding finding{};
                finding.functionName = name;
                finding.riskScore = baseWeight;
                finding.reasons.push_back(
                    "ETW/trace export prologue looks patched (ret/jmp/zeroed)"
                );
                result.findings.push_back(std::move(finding));
            }

            return result;
        }
    };

} // namespace Mjolnir
