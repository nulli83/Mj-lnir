#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <winternl.h>
#include <psapi.h>

#include <cstdint>
#include <string>
#include <vector>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

namespace Mjolnir {

    struct HollowingFinding {
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct HollowingScanResult {
        std::vector<HollowingFinding> findings;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    /*
     * Process hollowing / section remap heuristics:
     * - main image region is MEM_PRIVATE instead of MEM_IMAGE
     * - PEB ImagePathName disagrees with QueryFullProcessImageName
     * - entry-point page is private memory
     */
    class HollowingScanner {
    private:
        struct Pbi {
            NTSTATUS ExitStatus;
            PVOID PebBaseAddress;
            ULONG_PTR AffinityMask;
            LONG BasePriority;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR InheritedFromUniqueProcessId;
        };

        using NtQueryInformationProcessFn =
            NTSTATUS(NTAPI*)(
                HANDLE,
                PROCESSINFOCLASS,
                PVOID,
                ULONG,
                PULONG
            );

        template <typename T>
        static bool ReadRemote(HANDLE process, std::uintptr_t address, T& value) {
            SIZE_T read = 0;
            return ReadProcessMemory(
                       process,
                       reinterpret_cast<LPCVOID>(address),
                       &value,
                       sizeof(T),
                       &read
                   ) != FALSE &&
                   read == sizeof(T);
        }

        static std::wstring ReadRemoteUnicodeString(
            HANDLE process,
            std::uintptr_t unicodeStringAddress
        ) {
            struct UNICODE_STRING_LOCAL {
                USHORT Length;
                USHORT MaximumLength;
                PVOID Buffer;
            };

            UNICODE_STRING_LOCAL remote{};
            if (!ReadRemote(process, unicodeStringAddress, remote)) {
                return {};
            }

            if (remote.Buffer == nullptr || remote.Length == 0) {
                return {};
            }

            std::wstring value(remote.Length / sizeof(wchar_t), L'\0');
            SIZE_T read = 0;
            if (
                !ReadProcessMemory(
                    process,
                    remote.Buffer,
                    value.data(),
                    remote.Length,
                    &read
                )
            ) {
                return {};
            }

            value.resize(read / sizeof(wchar_t));
            return value;
        }

        static std::string WideToUtf8(const std::wstring& value) {
            if (value.empty()) {
                return {};
            }

            const int size = WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                nullptr,
                0,
                nullptr,
                nullptr
            );

            if (size <= 0) {
                return {};
            }

            std::string utf8(static_cast<std::size_t>(size), '\0');
            WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                utf8.data(),
                size,
                nullptr,
                nullptr
            );
            return utf8;
        }

        static std::string ToLower(std::string value) {
            for (char& character : value) {
                character = static_cast<char>(
                    std::tolower(static_cast<unsigned char>(character))
                );
            }
            return value;
        }

        static std::string QueryImagePath(HANDLE process) {
            wchar_t buffer[MAX_PATH * 2] = {};
            DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(wchar_t));
            if (!QueryFullProcessImageNameW(process, 0, buffer, &size)) {
                return {};
            }
            return WideToUtf8(buffer);
        }

    public:
        static HollowingScanResult Scan(
            HANDLE process,
            int baseWeight = 70
        ) {
            HollowingScanResult result{};

            if (process == nullptr) {
                result.errorCode = ERROR_INVALID_HANDLE;
                return result;
            }

            HollowingFinding finding{};

            HMODULE modules[8] = {};
            DWORD needed = 0;
            std::uintptr_t mainBase = 0;

            if (
                EnumProcessModulesEx(
                    process,
                    modules,
                    sizeof(modules),
                    &needed,
                    LIST_MODULES_ALL
                ) &&
                needed >= sizeof(HMODULE)
            ) {
                mainBase = reinterpret_cast<std::uintptr_t>(modules[0]);
            }

            if (mainBase != 0) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (
                    VirtualQueryEx(
                        process,
                        reinterpret_cast<LPCVOID>(mainBase),
                        &mbi,
                        sizeof(mbi)
                    ) != 0
                ) {
                    if (mbi.Type == MEM_PRIVATE) {
                        finding.riskScore += baseWeight;
                        finding.reasons.push_back(
                            "Primary image base is MEM_PRIVATE (possible hollowing/manual map)"
                        );
                    }

                    const DWORD protect = mbi.Protect & 0xFF;
                    if (
                        mbi.Type == MEM_PRIVATE &&
                        (
                            protect == PAGE_EXECUTE_READWRITE ||
                            protect == PAGE_EXECUTE_WRITECOPY
                        )
                    ) {
                        finding.riskScore += 20;
                        finding.reasons.push_back(
                            "Primary image page is private and writable+executable"
                        );
                    }
                }

                IMAGE_DOS_HEADER dos{};
                if (ReadRemote(process, mainBase, dos) && dos.e_magic == IMAGE_DOS_SIGNATURE) {
                    IMAGE_NT_HEADERS64 nt{};
                    if (
                        ReadRemote(
                            process,
                            mainBase + static_cast<std::uintptr_t>(dos.e_lfanew),
                            nt
                        ) &&
                        nt.Signature == IMAGE_NT_SIGNATURE
                    ) {
                        const std::uintptr_t entry =
                            mainBase + nt.OptionalHeader.AddressOfEntryPoint;

                        MEMORY_BASIC_INFORMATION entryMbi{};
                        if (
                            VirtualQueryEx(
                                process,
                                reinterpret_cast<LPCVOID>(entry),
                                &entryMbi,
                                sizeof(entryMbi)
                            ) != 0 &&
                            entryMbi.Type == MEM_PRIVATE
                        ) {
                            finding.riskScore += baseWeight / 2;
                            finding.reasons.push_back(
                                "Entry point resides in private memory"
                            );
                        }
                    }
                }
            }

            auto* ntQuery = reinterpret_cast<NtQueryInformationProcessFn>(
                GetProcAddress(
                    GetModuleHandleW(L"ntdll.dll"),
                    "NtQueryInformationProcess"
                )
            );

            if (ntQuery != nullptr) {
                Pbi pbi{};
                if (
                    NT_SUCCESS(
                        ntQuery(
                            process,
                            ProcessBasicInformation,
                            &pbi,
                            sizeof(pbi),
                            nullptr
                        )
                    ) &&
                    pbi.PebBaseAddress != nullptr
                ) {
                    /*
                     * PEB offsets (x64):
                     * ProcessParameters @ 0x20
                     * RTL_USER_PROCESS_PARAMETERS.ImagePathName @ 0x60
                     */
                    const std::uintptr_t peb =
                        reinterpret_cast<std::uintptr_t>(pbi.PebBaseAddress);

                    std::uintptr_t processParameters = 0;
                    if (
                        ReadRemote(process, peb + 0x20, processParameters) &&
                        processParameters != 0
                    ) {
                        const std::wstring pebPath = ReadRemoteUnicodeString(
                            process,
                            processParameters + 0x60
                        );
                        const std::string osPath = QueryImagePath(process);

                        if (!pebPath.empty() && !osPath.empty()) {
                            const std::string left = ToLower(WideToUtf8(pebPath));
                            const std::string right = ToLower(osPath);

                            if (left != right) {
                                finding.riskScore += baseWeight;
                                finding.reasons.push_back(
                                    "PEB ImagePathName disagrees with OS image path"
                                );
                            }
                        }
                    }
                }
            }

            if (!finding.reasons.empty()) {
                result.findings.push_back(std::move(finding));
            }

            return result;
        }
    };

} // namespace Mjolnir
