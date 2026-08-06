#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "alert.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <cctype>
#include <string>
#include <unordered_set>

namespace Mjolnir {

    struct EnforcementResult {
        bool attempted = false;
        bool succeeded = false;
        std::string action;
        std::string details;
        DWORD errorCode = ERROR_SUCCESS;
        std::size_t terminatedTools = 0;
    };

    class EnforcementOfficer {
    private:
        static bool TerminatePid(
            DWORD pid,
            std::string& details
        ) {
            HANDLE process = OpenProcess(
                PROCESS_TERMINATE |
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                pid
            );

            if (process == nullptr) {
                details =
                    "OpenProcess failed with error " +
                    std::to_string(GetLastError());
                return false;
            }

            const BOOL ok = TerminateProcess(process, 1);
            const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
            CloseHandle(process);

            if (!ok) {
                details =
                    "TerminateProcess failed with error " +
                    std::to_string(error);
                return false;
            }

            details =
                "Terminated PID " + std::to_string(pid);
            return true;
        }

    public:
        static EnforcementResult MaybeTerminateTarget(
            DWORD targetPid,
            int highestRisk,
            int riskThreshold,
            bool observeOnly
        ) {
            EnforcementResult result{};

            if (observeOnly) {
                result.action = "observe_only";
                result.details =
                    "Enforcement skipped because observe_only=true";
                return result;
            }

            if (targetPid == 0) {
                result.action = "no_target";
                result.details =
                    "No target process to enforce against";
                return result;
            }

            if (highestRisk < riskThreshold) {
                result.action = "below_threshold";
                result.details =
                    "Highest risk " +
                    std::to_string(highestRisk) +
                    " is below enforce threshold " +
                    std::to_string(riskThreshold);
                return result;
            }

            result.attempted = true;
            result.action = "terminate_target";

            std::string details;

            if (TerminatePid(targetPid, details)) {
                result.succeeded = true;
                result.details =
                    details +
                    " due to risk score " +
                    std::to_string(highestRisk);

                SecurityAlertSystem::DispatchAlert(
                    ThreatLevel::CRITICAL,
                    "ENFORCE",
                    result.details,
                    targetPid,
                    highestRisk
                );
            } else {
                result.errorCode = GetLastError();
                result.details = details;

                SecurityAlertSystem::DispatchAlert(
                    ThreatLevel::CRITICAL,
                    "ENFORCE",
                    result.details,
                    targetPid,
                    highestRisk
                );
            }

            return result;
        }

        /*
         * När enforce är på, stäng även kända cheat/debug-verktyg.
         */
        static EnforcementResult MaybeTerminateWatchedTools(
            const std::unordered_set<std::string>&
                monitorOnlyProcesses,
            bool observeOnly,
            int minimumScore = 50
        ) {
            EnforcementResult result{};
            result.action = "terminate_watched_tools";

            if (observeOnly) {
                result.details =
                    "Tool enforcement skipped because observe_only=true";
                return result;
            }

            static const std::unordered_set<std::string>
                killList = {
                    "cheatengine.exe",
                    "cheatengine-x86_64.exe",
                    "x64dbg.exe",
                    "x32dbg.exe",
                    "x96dbg.exe",
                    "ollydbg.exe",
                    "processhacker.exe",
                    "systeminformer.exe",
                    "reclass.exe",
                    "reclass.net.exe"
                };

            HANDLE snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPPROCESS,
                0
            );

            if (snapshot == INVALID_HANDLE_VALUE) {
                result.errorCode = GetLastError();
                result.details = "CreateToolhelp32Snapshot failed";
                return result;
            }

            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);

            if (Process32FirstW(snapshot, &entry)) {
                do {
                    char narrowName[MAX_PATH]{};

                    WideCharToMultiByte(
                        CP_UTF8,
                        0,
                        entry.szExeFile,
                        -1,
                        narrowName,
                        static_cast<int>(sizeof(narrowName)),
                        nullptr,
                        nullptr
                    );

                    std::string processName = narrowName;

                    for (char& character : processName) {
                        character = static_cast<char>(
                            ::tolower(
                                static_cast<unsigned char>(
                                    character
                                )
                            )
                        );
                    }

                    const bool monitored =
                        monitorOnlyProcesses.find(processName) !=
                        monitorOnlyProcesses.end();

                    const bool killable =
                        killList.find(processName) !=
                        killList.end();

                    if (!monitored && !killable) {
                        continue;
                    }

                    if (!killable) {
                        continue;
                    }

                    result.attempted = true;

                    std::string details;

                    if (
                        TerminatePid(
                            entry.th32ProcessID,
                            details
                        )
                    ) {
                        ++result.terminatedTools;
                        result.succeeded = true;

                        SecurityAlertSystem::DispatchAlert(
                            ThreatLevel::CRITICAL,
                            "ENFORCE",
                            "Terminated watched tooling: " +
                                processName + " / " + details,
                            entry.th32ProcessID,
                            minimumScore
                        );
                    }

                    entry.dwSize = sizeof(entry);

                } while (Process32NextW(snapshot, &entry));
            }

            CloseHandle(snapshot);

            result.details =
                "Terminated " +
                std::to_string(result.terminatedTools) +
                " watched tool process(es)";

            return result;
        }
    };

} // namespace Mjolnir
