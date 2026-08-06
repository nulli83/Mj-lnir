#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#endif

namespace Mjolnir {

    struct InlineHookFinding {
        std::string moduleName;
        std::string functionName;

        std::uintptr_t remoteAddress = 0;
        std::string prologueHex;

        bool looksHooked = false;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct InlineHookScanResult {
        std::vector<InlineHookFinding> hooks;
        std::size_t functionsChecked = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class InlineHookDetector {
    private:
        struct ModuleRange {
            std::uintptr_t base = 0;
            std::uintptr_t end = 0;
        };

        struct CriticalExport {
            const char* module;
            const char* function;
        };

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

        static std::string BytesToHex(
            const std::uint8_t* data,
            std::size_t length
        ) {
            static const char* digits = "0123456789abcdef";
            std::string hex;
            hex.reserve(length * 2);

            for (std::size_t index = 0; index < length; ++index) {
                hex.push_back(digits[(data[index] >> 4) & 0x0F]);
                hex.push_back(digits[data[index] & 0x0F]);
            }

            return hex;
        }

        static bool LooksLikeHookPrologue(
            const std::uint8_t* bytes,
            std::size_t length,
            std::vector<std::string>& reasons
        ) {
            if (length < 5) {
                return false;
            }

            bool hooked = false;

            /*
             * E9 xx xx xx xx  — relative JMP
             * FF 25 xx xx xx xx — JMP [rip+disp]
             * EB xx — short JMP
             * 48 B8 ... FF E0 — mov rax, imm64 ; jmp rax
             * 68 xx xx xx xx C3 — push imm32 ; ret
             */
            if (bytes[0] == 0xE9) {
                hooked = true;
                reasons.push_back("Prologue starts with relative JMP (E9)");
            }

            if (bytes[0] == 0xEB) {
                hooked = true;
                reasons.push_back("Prologue starts with short JMP (EB)");
            }

            if (bytes[0] == 0xFF && bytes[1] == 0x25) {
                hooked = true;
                reasons.push_back("Prologue starts with JMP [rip+disp] (FF25)");
            }

            if (
                length >= 12 &&
                bytes[0] == 0x48 &&
                bytes[1] == 0xB8 &&
                bytes[10] == 0xFF &&
                bytes[11] == 0xE0
            ) {
                hooked = true;
                reasons.push_back("Prologue uses mov rax + jmp rax trampoline");
            }

            if (
                length >= 6 &&
                bytes[0] == 0x68 &&
                bytes[5] == 0xC3
            ) {
                hooked = true;
                reasons.push_back("Prologue uses push+ret trampoline");
            }

            if (bytes[0] == 0xCC && bytes[1] == 0xCC) {
                hooked = true;
                reasons.push_back("Prologue patched with INT3");
            }

            return hooked;
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

    public:
        static InlineHookScanResult ScanCriticalPrologues(
            HANDLE processHandle,
            DWORD targetPid,
            int baseRiskWeight = 50
        ) {
            InlineHookScanResult result{};

            if (
                processHandle == nullptr ||
                processHandle == INVALID_HANDLE_VALUE ||
                targetPid == 0
            ) {
                result.errorCode = ERROR_INVALID_PARAMETER;
                return result;
            }

            const auto remoteModules =
                BuildRemoteModuleMap(targetPid);

            if (remoteModules.empty()) {
                result.errorCode = ERROR_PARTIAL_COPY;
                return result;
            }

            static const CriticalExport exports[] = {
                {"kernel32.dll", "IsDebuggerPresent"},
                {"kernel32.dll", "CheckRemoteDebuggerPresent"},
                {"kernel32.dll", "ReadProcessMemory"},
                {"kernel32.dll", "WriteProcessMemory"},
                {"kernel32.dll", "VirtualProtect"},
                {"kernel32.dll", "VirtualAllocEx"},
                {"kernel32.dll", "CreateRemoteThread"},
                {"kernel32.dll", "OpenProcess"},
                {"kernel32.dll", "LoadLibraryW"},
                {"kernel32.dll", "GetProcAddress"},
                {"ntdll.dll", "NtQueryInformationProcess"},
                {"ntdll.dll", "NtReadVirtualMemory"},
                {"ntdll.dll", "NtWriteVirtualMemory"},
                {"ntdll.dll", "NtProtectVirtualMemory"},
                {"ntdll.dll", "LdrLoadDll"},
                {"user32.dll", "GetAsyncKeyState"},
                {"user32.dll", "GetForegroundWindow"}
            };

            for (const CriticalExport& item : exports) {
                HMODULE localModule =
                    GetModuleHandleA(item.module);

                if (localModule == nullptr) {
                    continue;
                }

                FARPROC localFunction =
                    GetProcAddress(localModule, item.function);

                if (localFunction == nullptr) {
                    continue;
                }

                MODULEINFO localInfo{};

                if (
                    !GetModuleInformation(
                        GetCurrentProcess(),
                        localModule,
                        &localInfo,
                        sizeof(localInfo)
                    )
                ) {
                    continue;
                }

                const std::uintptr_t localBase =
                    reinterpret_cast<std::uintptr_t>(
                        localInfo.lpBaseOfDll
                    );

                const std::uintptr_t localAddress =
                    reinterpret_cast<std::uintptr_t>(
                        localFunction
                    );

                if (localAddress < localBase) {
                    continue;
                }

                const std::uintptr_t rva =
                    localAddress - localBase;

                const auto remoteIterator =
                    remoteModules.find(item.module);

                if (remoteIterator == remoteModules.end()) {
                    continue;
                }

                const std::uintptr_t remoteAddress =
                    remoteIterator->second.base + rva;

                std::uint8_t prologue[16]{};
                SIZE_T bytesRead = 0;

                if (
                    !ReadProcessMemory(
                        processHandle,
                        reinterpret_cast<LPCVOID>(remoteAddress),
                        prologue,
                        sizeof(prologue),
                        &bytesRead
                    ) ||
                    bytesRead < 5
                ) {
                    continue;
                }

                ++result.functionsChecked;

                InlineHookFinding finding{};
                finding.moduleName = item.module;
                finding.functionName = item.function;
                finding.remoteAddress = remoteAddress;
                finding.prologueHex =
                    BytesToHex(prologue, bytesRead);

                if (
                    LooksLikeHookPrologue(
                        prologue,
                        bytesRead,
                        finding.reasons
                    )
                ) {
                    finding.looksHooked = true;
                    finding.riskScore = baseRiskWeight;
                    result.hooks.push_back(std::move(finding));
                }
            }

            result.errorCode = ERROR_SUCCESS;
            return result;
        }
    };

} // namespace Mjolnir
