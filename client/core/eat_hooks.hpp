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

    struct EatHookFinding {
        std::string moduleName;
        std::string functionName;
        std::uintptr_t localAddress = 0;
        std::uintptr_t remoteEatAddress = 0;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct EatHookScanResult {
        std::vector<EatHookFinding> findings;
        std::size_t exportsChecked = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class EatHookScanner {
    private:
        template <typename T>
        static bool ReadRemote(
            HANDLE process,
            std::uintptr_t address,
            T& value
        ) {
            SIZE_T bytesRead = 0;
            return ReadProcessMemory(
                       process,
                       reinterpret_cast<LPCVOID>(address),
                       &value,
                       sizeof(T),
                       &bytesRead
                   ) != FALSE &&
                   bytesRead == sizeof(T);
        }

        static std::string ReadRemoteAnsi(
            HANDLE process,
            std::uintptr_t address,
            std::size_t maxLength = 128
        ) {
            if (address == 0) {
                return {};
            }

            std::string buffer(maxLength, '\0');
            SIZE_T bytesRead = 0;

            if (
                !ReadProcessMemory(
                    process,
                    reinterpret_cast<LPCVOID>(address),
                    buffer.data(),
                    maxLength,
                    &bytesRead
                ) ||
                bytesRead == 0
            ) {
                return {};
            }

            buffer.resize(bytesRead);
            const auto end = buffer.find('\0');
            if (end != std::string::npos) {
                buffer.resize(end);
            }

            return buffer;
        }

        static bool ResolveRemoteModuleBase(
            HANDLE process,
            const wchar_t* moduleName,
            std::uintptr_t& outBase
        ) {
            outBase = 0;

            HMODULE modules[512] = {};
            DWORD bytesNeeded = 0;

            if (
                !EnumProcessModulesEx(
                    process,
                    modules,
                    sizeof(modules),
                    &bytesNeeded,
                    LIST_MODULES_ALL
                )
            ) {
                return false;
            }

            const DWORD count = bytesNeeded / sizeof(HMODULE);

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

                const wchar_t* fileName = path;
                for (wchar_t* cursor = path; *cursor != L'\0'; ++cursor) {
                    if (*cursor == L'\\' || *cursor == L'/') {
                        fileName = cursor + 1;
                    }
                }

                if (_wcsicmp(fileName, moduleName) == 0) {
                    outBase = reinterpret_cast<std::uintptr_t>(
                        modules[index]
                    );
                    return outBase != 0;
                }
            }

            return false;
        }

        static bool ReadRemoteEatAddress(
            HANDLE process,
            std::uintptr_t moduleBase,
            const char* functionName,
            std::uintptr_t& outAddress
        ) {
            outAddress = 0;

            IMAGE_DOS_HEADER dos{};
            if (!ReadRemote(process, moduleBase, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
                return false;
            }

            IMAGE_NT_HEADERS64 nt{};
            if (
                !ReadRemote(
                    process,
                    moduleBase + static_cast<std::uintptr_t>(dos.e_lfanew),
                    nt
                ) ||
                nt.Signature != IMAGE_NT_SIGNATURE
            ) {
                return false;
            }

            const auto& exportDir =
                nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            if (exportDir.VirtualAddress == 0 || exportDir.Size == 0) {
                return false;
            }

            IMAGE_EXPORT_DIRECTORY exports{};
            if (
                !ReadRemote(
                    process,
                    moduleBase + exportDir.VirtualAddress,
                    exports
                )
            ) {
                return false;
            }

            for (DWORD index = 0; index < exports.NumberOfNames; ++index) {
                DWORD nameRva = 0;
                if (
                    !ReadRemote(
                        process,
                        moduleBase +
                            exports.AddressOfNames +
                            index * sizeof(DWORD),
                        nameRva
                    )
                ) {
                    continue;
                }

                const std::string name = ReadRemoteAnsi(
                    process,
                    moduleBase + nameRva
                );

                if (name != functionName) {
                    continue;
                }

                WORD ordinal = 0;
                if (
                    !ReadRemote(
                        process,
                        moduleBase +
                            exports.AddressOfNameOrdinals +
                            index * sizeof(WORD),
                        ordinal
                    )
                ) {
                    return false;
                }

                DWORD functionRva = 0;
                if (
                    !ReadRemote(
                        process,
                        moduleBase +
                            exports.AddressOfFunctions +
                            ordinal * sizeof(DWORD),
                        functionRva
                    )
                ) {
                    return false;
                }

                /*
                 * Forwarded exports live inside the export directory.
                 */
                if (
                    functionRva >= exportDir.VirtualAddress &&
                    functionRva < exportDir.VirtualAddress + exportDir.Size
                ) {
                    return false;
                }

                outAddress = moduleBase + functionRva;
                return true;
            }

            return false;
        }

        static void CheckExport(
            HANDLE process,
            const wchar_t* moduleName,
            const char* functionName,
            int baseWeight,
            EatHookScanResult& result
        ) {
            HMODULE localModule = GetModuleHandleW(moduleName);
            if (localModule == nullptr) {
                return;
            }

            const FARPROC localProc = GetProcAddress(
                localModule,
                functionName
            );

            if (localProc == nullptr) {
                return;
            }

            ++result.exportsChecked;

            std::uintptr_t remoteBase = 0;
            if (!ResolveRemoteModuleBase(process, moduleName, remoteBase)) {
                return;
            }

            std::uintptr_t remoteEat = 0;
            if (
                !ReadRemoteEatAddress(
                    process,
                    remoteBase,
                    functionName,
                    remoteEat
                )
            ) {
                return;
            }

            const auto localAddress =
                reinterpret_cast<std::uintptr_t>(localProc);

            /*
             * ASLR makes absolute addresses differ across processes.
             * Compare RVAs instead.
             */
            const std::uintptr_t localRva =
                localAddress -
                reinterpret_cast<std::uintptr_t>(localModule);
            const std::uintptr_t remoteRva = remoteEat - remoteBase;

            if (localRva == remoteRva) {
                return;
            }

            EatHookFinding finding{};
            {
                char narrow[64] = {};
                WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    moduleName,
                    -1,
                    narrow,
                    sizeof(narrow),
                    nullptr,
                    nullptr
                );
                finding.moduleName = narrow;
            }
            finding.functionName = functionName;
            finding.localAddress = localAddress;
            finding.remoteEatAddress = remoteEat;
            finding.riskScore = baseWeight;
            finding.reasons.push_back(
                "Remote EAT RVA differs from local export RVA"
            );
            result.findings.push_back(std::move(finding));
        }

    public:
        static EatHookScanResult ScanCriticalExports(
            HANDLE process,
            int baseWeight = 55
        ) {
            EatHookScanResult result{};

            if (process == nullptr) {
                result.errorCode = ERROR_INVALID_HANDLE;
                return result;
            }

            static const wchar_t* kNtdll = L"ntdll.dll";
            static const wchar_t* kKernel32 = L"kernel32.dll";
            static const wchar_t* kKernelBase = L"kernelbase.dll";

            const char* ntdllExports[] = {
                "NtProtectVirtualMemory",
                "NtReadVirtualMemory",
                "NtWriteVirtualMemory",
                "NtOpenProcess",
                "NtCreateThreadEx",
                "NtMapViewOfSection",
                "NtQueryInformationProcess",
                "NtQuerySystemInformation",
                "NtSetInformationThread",
            };

            const char* kernelExports[] = {
                "VirtualProtect",
                "VirtualProtectEx",
                "ReadProcessMemory",
                "WriteProcessMemory",
                "OpenProcess",
                "CreateRemoteThread",
                "LoadLibraryW",
                "LoadLibraryA",
                "GetProcAddress",
            };

            for (const char* name : ntdllExports) {
                CheckExport(process, kNtdll, name, baseWeight, result);
            }

            for (const char* name : kernelExports) {
                CheckExport(process, kKernel32, name, baseWeight, result);
                CheckExport(
                    process,
                    kKernelBase,
                    name,
                    baseWeight,
                    result
                );
            }

            return result;
        }
    };

} // namespace Mjolnir
