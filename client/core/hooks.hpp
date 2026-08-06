#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>

#include <cctype>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Mjolnir {

    struct HookFinding {
        std::string moduleName;
        std::string importedFrom;
        std::string functionName;

        std::uintptr_t iatAddress = 0;
        std::uintptr_t resolvedAddress = 0;
        std::uintptr_t expectedModuleBase = 0;
        std::uintptr_t expectedModuleEnd = 0;

        bool pointsOutsideExporter = false;
        bool pointsToPrivateMemory = false;

        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct HookScanResult {
        std::vector<HookFinding> hooks;
        std::size_t importsChecked = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class HookDetector {
    private:
        struct ModuleRange {
            std::uintptr_t base = 0;
            std::uintptr_t end = 0;
        };

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

        static std::string ReadRemoteAnsiString(
            HANDLE process,
            std::uintptr_t address,
            std::size_t maxLength = 256
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
            const std::size_t end = buffer.find('\0');

            if (end != std::string::npos) {
                buffer.resize(end);
            }

            return buffer;
        }

        static std::string ToLower(std::string value) {
            for (char& character : value) {
                character = static_cast<char>(
                    std::tolower(
                        static_cast<unsigned char>(character)
                    )
                );
            }

            return value;
        }

        static std::string WideToUtf8(const std::wstring& value) {
            if (value.empty()) {
                return {};
            }

            const int requiredSize = WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                nullptr,
                0,
                nullptr,
                nullptr
            );

            if (requiredSize <= 0) {
                return {};
            }

            std::string result(
                static_cast<std::size_t>(requiredSize),
                '\0'
            );

            WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                result.data(),
                requiredSize,
                nullptr,
                nullptr
            );

            return result;
        }

        static std::unordered_map<std::string, ModuleRange>
        BuildRemoteModuleMap(DWORD pid) {
            std::unordered_map<std::string, ModuleRange> modules;

            HANDLE snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                pid
            );

            if (snapshot == INVALID_HANDLE_VALUE) {
                return modules;
            }

            MODULEENTRY32W entry{};
            entry.dwSize = sizeof(entry);

            if (Module32FirstW(snapshot, &entry)) {
                do {
                    ModuleRange range{};
                    range.base =
                        reinterpret_cast<std::uintptr_t>(
                            entry.modBaseAddr
                        );
                    range.end =
                        range.base +
                        static_cast<std::uintptr_t>(
                            entry.modBaseSize
                        );

                    modules.emplace(
                        ToLower(WideToUtf8(entry.szModule)),
                        range
                    );

                    entry.dwSize = sizeof(entry);
                } while (Module32NextW(snapshot, &entry));
            }

            CloseHandle(snapshot);
            return modules;
        }

        static bool IsPrivateExecutable(
            HANDLE process,
            std::uintptr_t address
        ) {
            MEMORY_BASIC_INFORMATION information{};

            if (
                VirtualQueryEx(
                    process,
                    reinterpret_cast<LPCVOID>(address),
                    &information,
                    sizeof(information)
                ) == 0
            ) {
                return false;
            }

            if (
                information.State != MEM_COMMIT ||
                information.Type != MEM_PRIVATE
            ) {
                return false;
            }

            const DWORD protect = information.Protect & 0xFF;

            return
                protect == PAGE_EXECUTE ||
                protect == PAGE_EXECUTE_READ ||
                protect == PAGE_EXECUTE_READWRITE ||
                protect == PAGE_EXECUTE_WRITECOPY;
        }

        struct CriticalImport {
            const char* module;
            const char* function;
        };

    public:
        /*
         * Kontrollerar att IAT-poster för kritiska API:er i
         * target-modulen fortfarande pekar in i rätt remote DLL.
         */
        static HookScanResult ScanCriticalImports(
            HANDLE processHandle,
            DWORD targetPid,
            std::uintptr_t moduleBase,
            int baseRiskWeight = 45
        ) {
            HookScanResult result{};

            if (
                processHandle == nullptr ||
                processHandle == INVALID_HANDLE_VALUE ||
                targetPid == 0 ||
                moduleBase == 0
            ) {
                result.errorCode = ERROR_INVALID_PARAMETER;
                return result;
            }

            IMAGE_DOS_HEADER dosHeader{};

            if (
                !ReadRemote(processHandle, moduleBase, dosHeader) ||
                dosHeader.e_magic != IMAGE_DOS_SIGNATURE
            ) {
                result.errorCode = ERROR_BAD_FORMAT;
                return result;
            }

            IMAGE_NT_HEADERS64 ntHeaders{};

            if (
                !ReadRemote(
                    processHandle,
                    moduleBase +
                        static_cast<std::uintptr_t>(
                            dosHeader.e_lfanew
                        ),
                    ntHeaders
                ) ||
                ntHeaders.Signature != IMAGE_NT_SIGNATURE
            ) {
                result.errorCode = ERROR_BAD_FORMAT;
                return result;
            }

            if (
                ntHeaders.OptionalHeader.Magic !=
                IMAGE_NT_OPTIONAL_HDR64_MAGIC
            ) {
                result.errorCode = ERROR_NOT_SUPPORTED;
                return result;
            }

            const auto& importDirectory =
                ntHeaders.OptionalHeader
                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

            if (
                importDirectory.VirtualAddress == 0 ||
                importDirectory.Size == 0
            ) {
                result.errorCode = ERROR_SUCCESS;
                return result;
            }

            const auto remoteModules =
                BuildRemoteModuleMap(targetPid);

            if (remoteModules.empty()) {
                result.errorCode = ERROR_PARTIAL_COPY;
                return result;
            }

            static const CriticalImport criticalImports[] = {
                {"kernel32.dll", "ReadProcessMemory"},
                {"kernel32.dll", "WriteProcessMemory"},
                {"kernel32.dll", "VirtualProtect"},
                {"kernel32.dll", "VirtualProtectEx"},
                {"kernel32.dll", "VirtualAlloc"},
                {"kernel32.dll", "VirtualAllocEx"},
                {"kernel32.dll", "CreateRemoteThread"},
                {"kernel32.dll", "OpenProcess"},
                {"kernel32.dll", "LoadLibraryA"},
                {"kernel32.dll", "LoadLibraryW"},
                {"kernel32.dll", "GetProcAddress"},
                {"kernel32.dll", "IsDebuggerPresent"},
                {"kernel32.dll", "CheckRemoteDebuggerPresent"},
                {"ntdll.dll", "NtQueryInformationProcess"},
                {"ntdll.dll", "NtReadVirtualMemory"},
                {"ntdll.dll", "NtWriteVirtualMemory"},
                {"ntdll.dll", "LdrLoadDll"},
                {"user32.dll", "GetAsyncKeyState"},
                {"user32.dll", "GetForegroundWindow"},
                {"ws2_32.dll", "send"},
                {"ws2_32.dll", "recv"}
            };

            std::uintptr_t descriptorAddress =
                moduleBase + importDirectory.VirtualAddress;

            for (;;) {
                IMAGE_IMPORT_DESCRIPTOR descriptor{};

                if (
                    !ReadRemote(
                        processHandle,
                        descriptorAddress,
                        descriptor
                    )
                ) {
                    break;
                }

                if (descriptor.Name == 0) {
                    break;
                }

                const std::string importedModule = ToLower(
                    ReadRemoteAnsiString(
                        processHandle,
                        moduleBase + descriptor.Name
                    )
                );

                if (importedModule.empty()) {
                    descriptorAddress +=
                        sizeof(IMAGE_IMPORT_DESCRIPTOR);
                    continue;
                }

                const auto exporterIterator =
                    remoteModules.find(importedModule);

                const bool haveExporterRange =
                    exporterIterator != remoteModules.end();

                std::uintptr_t thunkAddress =
                    moduleBase +
                    (
                        descriptor.OriginalFirstThunk != 0
                            ? descriptor.OriginalFirstThunk
                            : descriptor.FirstThunk
                    );

                std::uintptr_t iatAddress =
                    moduleBase + descriptor.FirstThunk;

                for (;;) {
                    IMAGE_THUNK_DATA64 originalThunk{};
                    IMAGE_THUNK_DATA64 iatThunk{};

                    if (
                        !ReadRemote(
                            processHandle,
                            thunkAddress,
                            originalThunk
                        ) ||
                        !ReadRemote(
                            processHandle,
                            iatAddress,
                            iatThunk
                        )
                    ) {
                        break;
                    }

                    if (originalThunk.u1.AddressOfData == 0) {
                        break;
                    }

                    ++result.importsChecked;

                    std::string functionName;

                    if (
                        (originalThunk.u1.Ordinal &
                         IMAGE_ORDINAL_FLAG64) == 0
                    ) {
                        const std::uintptr_t ibnAddress =
                            moduleBase +
                            static_cast<std::uintptr_t>(
                                originalThunk.u1.AddressOfData
                            );

                        functionName = ReadRemoteAnsiString(
                            processHandle,
                            ibnAddress +
                                offsetof(
                                    IMAGE_IMPORT_BY_NAME,
                                    Name
                                )
                        );
                    }

                    bool isCritical = false;

                    for (const CriticalImport& item :
                         criticalImports) {
                        if (
                            importedModule == item.module &&
                            functionName == item.function
                        ) {
                            isCritical = true;
                            break;
                        }
                    }

                    if (isCritical && iatThunk.u1.Function != 0) {
                        const std::uintptr_t resolved =
                            static_cast<std::uintptr_t>(
                                iatThunk.u1.Function
                            );

                        HookFinding finding{};
                        finding.moduleName = "main";
                        finding.importedFrom = importedModule;
                        finding.functionName = functionName;
                        finding.iatAddress = iatAddress;
                        finding.resolvedAddress = resolved;

                        if (haveExporterRange) {
                            finding.expectedModuleBase =
                                exporterIterator->second.base;
                            finding.expectedModuleEnd =
                                exporterIterator->second.end;

                            if (
                                resolved < finding.expectedModuleBase ||
                                resolved >= finding.expectedModuleEnd
                            ) {
                                finding.pointsOutsideExporter = true;
                                finding.riskScore += baseRiskWeight;
                                finding.reasons.push_back(
                                    "IAT target is outside the exporting module in the remote process"
                                );
                            }
                        }

                        if (
                            IsPrivateExecutable(
                                processHandle,
                                resolved
                            )
                        ) {
                            finding.pointsToPrivateMemory = true;
                            finding.riskScore += baseRiskWeight;
                            finding.reasons.push_back(
                                "IAT target points into private executable memory"
                            );
                        }

                        if (finding.riskScore > 0) {
                            result.hooks.push_back(
                                std::move(finding)
                            );
                        }
                    }

                    thunkAddress += sizeof(IMAGE_THUNK_DATA64);
                    iatAddress += sizeof(IMAGE_THUNK_DATA64);
                }

                descriptorAddress +=
                    sizeof(IMAGE_IMPORT_DESCRIPTOR);
            }

            result.errorCode = ERROR_SUCCESS;
            return result;
        }
    };

} // namespace Mjolnir
