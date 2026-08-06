#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "alert.hpp"

#include <windows.h>

#include <string>

namespace Mjolnir {

    struct EnforcementResult {
        bool attempted = false;
        bool succeeded = false;
        std::string action;
        std::string details;
        DWORD errorCode = ERROR_SUCCESS;
    };

    class EnforcementOfficer {
    public:
        /*
         * Avslutar targetprocessen när observe-only är avstängt
         * och risknivån når tröskeln.
         */
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
                result.details = "No target process to enforce against";
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

            HANDLE process = OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                targetPid
            );

            if (process == nullptr) {
                result.errorCode = GetLastError();
                result.details =
                    "OpenProcess(PROCESS_TERMINATE) failed with error " +
                    std::to_string(result.errorCode);

                SecurityAlertSystem::DispatchAlert(
                    ThreatLevel::CRITICAL,
                    "ENFORCE",
                    result.details,
                    targetPid,
                    highestRisk
                );

                return result;
            }

            const BOOL terminated = TerminateProcess(process, 1);
            result.errorCode = terminated ? ERROR_SUCCESS : GetLastError();
            CloseHandle(process);

            if (terminated) {
                result.succeeded = true;
                result.details =
                    "Terminated target PID " +
                    std::to_string(targetPid) +
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
                result.details =
                    "TerminateProcess failed with error " +
                    std::to_string(result.errorCode);

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
    };

} // namespace Mjolnir
