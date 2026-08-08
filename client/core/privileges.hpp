#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cctype>
#include <string>
#include <unordered_set>
#include <vector>

namespace Mjolnir {

    struct PrivilegeFinding {
        DWORD processId = 0;
        std::string processName;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct PrivilegeScanResult {
        std::vector<PrivilegeFinding> findings;
        std::size_t processesInspected = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class PrivilegeScanner {
    private:
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

        static std::string WideToUtf8(const wchar_t* value) {
            if (value == nullptr || value[0] == L'\0') {
                return {};
            }

            const int size = WideCharToMultiByte(
                CP_UTF8,
                0,
                value,
                -1,
                nullptr,
                0,
                nullptr,
                nullptr
            );

            if (size <= 1) {
                return {};
            }

            std::string utf8(static_cast<std::size_t>(size - 1), '\0');
            WideCharToMultiByte(
                CP_UTF8,
                0,
                value,
                -1,
                utf8.data(),
                size,
                nullptr,
                nullptr
            );
            return utf8;
        }

        static bool TokenHasEnabledPrivilege(
            HANDLE token,
            const wchar_t* privilegeName
        ) {
            LUID luid{};
            if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
                return false;
            }

            DWORD length = 0;
            GetTokenInformation(
                token,
                TokenPrivileges,
                nullptr,
                0,
                &length
            );

            if (length == 0) {
                return false;
            }

            std::vector<std::uint8_t> buffer(length);
            if (
                !GetTokenInformation(
                    token,
                    TokenPrivileges,
                    buffer.data(),
                    length,
                    &length
                )
            ) {
                return false;
            }

            const auto* privileges =
                reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.data());

            for (DWORD index = 0; index < privileges->PrivilegeCount; ++index) {
                const LUID_AND_ATTRIBUTES& entry =
                    privileges->Privileges[index];

                if (
                    entry.Luid.LowPart == luid.LowPart &&
                    entry.Luid.HighPart == luid.HighPart &&
                    (entry.Attributes & SE_PRIVILEGE_ENABLED) != 0
                ) {
                    return true;
                }
            }

            return false;
        }

        static bool IsExpectedSystemProcess(const std::string& name) {
            static const std::unordered_set<std::string> expected = {
                "csrss.exe",
                "lsass.exe",
                "services.exe",
                "smss.exe",
                "wininit.exe",
                "winlogon.exe",
                "svchost.exe",
                "system",
                "registry",
                "memory compression",
                "secure system",
                "mjolnir_core.exe",
                "mjolnir_watchdog.exe",
            };

            return expected.find(name) != expected.end();
        }

    public:
        static PrivilegeScanResult ScanDangerousPrivileges(
            const std::unordered_set<std::string>& whitelistedProcesses,
            int baseWeight = 45
        ) {
            PrivilegeScanResult result{};

            HANDLE snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPPROCESS,
                0
            );

            if (snapshot == INVALID_HANDLE_VALUE) {
                result.errorCode = GetLastError();
                return result;
            }

            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);

            if (!Process32FirstW(snapshot, &entry)) {
                result.errorCode = GetLastError();
                CloseHandle(snapshot);
                return result;
            }

            do {
                ++result.processesInspected;

                if (
                    entry.th32ProcessID == 0 ||
                    entry.th32ProcessID == 4
                ) {
                    continue;
                }

                const std::string name = ToLower(
                    WideToUtf8(entry.szExeFile)
                );

                if (
                    whitelistedProcesses.find(name) !=
                        whitelistedProcesses.end() ||
                    IsExpectedSystemProcess(name)
                ) {
                    continue;
                }

                HANDLE process = OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    entry.th32ProcessID
                );

                if (process == nullptr) {
                    continue;
                }

                HANDLE token = nullptr;
                if (
                    !OpenProcessToken(
                        process,
                        TOKEN_QUERY,
                        &token
                    )
                ) {
                    CloseHandle(process);
                    continue;
                }

                PrivilegeFinding finding{};
                finding.processId = entry.th32ProcessID;
                finding.processName = name;
                finding.riskScore = 0;

                if (TokenHasEnabledPrivilege(token, SE_DEBUG_NAME)) {
                    finding.riskScore += baseWeight;
                    finding.reasons.push_back(
                        "SeDebugPrivilege is enabled"
                    );
                }

                if (
                    TokenHasEnabledPrivilege(
                        token,
                        SE_LOAD_DRIVER_NAME
                    )
                ) {
                    finding.riskScore += baseWeight + 10;
                    finding.reasons.push_back(
                        "SeLoadDriverPrivilege is enabled"
                    );
                }

                if (
                    TokenHasEnabledPrivilege(
                        token,
                        SE_TCB_NAME
                    )
                ) {
                    finding.riskScore += baseWeight + 15;
                    finding.reasons.push_back(
                        "SeTcbPrivilege is enabled"
                    );
                }

                CloseHandle(token);
                CloseHandle(process);

                if (!finding.reasons.empty()) {
                    result.findings.push_back(std::move(finding));
                }
            } while (Process32NextW(snapshot, &entry));

            CloseHandle(snapshot);
            return result;
        }
    };

} // namespace Mjolnir
