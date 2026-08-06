#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <string>
#include <thread>

#include "alert.hpp"
#include "config.hpp"
#include "debugger.hpp"
#include "enforce.hpp"
#include "engine.hpp"
#include "integrity.hpp"
#include "ipc.hpp"
#include "memory.hpp"
#include "self_protect.hpp"

namespace {

    std::atomic<bool> g_running{true};

    void HandleSignal(int) {
        g_running = false;
    }

    std::wstring Utf8ToWide(const std::string& value) {
        if (value.empty()) {
            return {};
        }

        const int requiredSize = MultiByteToWideChar(
            CP_UTF8,
            0,
            value.c_str(),
            static_cast<int>(value.size()),
            nullptr,
            0
        );

        if (requiredSize <= 0) {
            return {};
        }

        std::wstring wide(
            static_cast<std::size_t>(requiredSize),
            L'\0'
        );

        MultiByteToWideChar(
            CP_UTF8,
            0,
            value.c_str(),
            static_cast<int>(value.size()),
            wide.data(),
            requiredSize
        );

        return wide;
    }

    void ApplyAlertSettingsFromConfig(
        Mjolnir::AlertSettings& alertSettings,
        const Mjolnir::ConfigManager& config
    ) {
        const auto settings = config.GetSettings();
        alertSettings.duplicateCooldownMs =
            settings.alertCooldownMs;
        Mjolnir::SecurityAlertSystem::Configure(alertSettings);
    }

} // namespace

int main() {
    std::signal(SIGINT, HandleSignal);
    std::signal(SIGTERM, HandleSignal);

    Mjolnir::ConfigManager config("whitelist.json");
    Mjolnir::IpcClient ipcClient;
    Mjolnir::SecurityEngine engine(config);

    Mjolnir::AlertSettings alertSettings{};
    alertSettings.logPath = "log/mjolnir.jsonl";
    alertSettings.consoleOutput = true;
    alertSettings.fileOutput = true;
    alertSettings.jsonLines = true;
    alertSettings.duplicateCooldownMs = 30000;
    Mjolnir::SecurityAlertSystem::Configure(alertSettings);

    Mjolnir::SecurityAlertSystem::SetExternalSink(
        [&ipcClient](const Mjolnir::SecurityAlert& alert) {
            ipcClient.SendJsonAlert(
                Mjolnir::SecurityAlertSystem::ThreatLevelToString(
                    alert.level
                ),
                alert.category,
                alert.details,
                alert.processId,
                alert.riskScore
            );
        }
    );

    Mjolnir::SecurityAlertSystem::DispatchAlert(
        Mjolnir::ThreatLevel::LOW,
        "DAEMON",
        "[Mjölnir v1.6.0] Security core armed. "
        "Vectors: modules, overlays, handles, debugger, "
        "integrity, memory-regions, threads, provenance, "
        "hooks, inline-hooks, manual-map, devices, image, "
        "artifacts, services, baseline, self-protect, timing, "
        "process-watch."
    );

    const auto loadResult =
        config.LoadConfigDetailed("whitelist.json");

    if (loadResult) {
        ApplyAlertSettingsFromConfig(alertSettings, config);

        Mjolnir::SecurityAlertSystem::DispatchAlert(
            Mjolnir::ThreatLevel::LOW,
            "CONFIG",
            "Loaded whitelist.json successfully."
        );
    } else {
        Mjolnir::SecurityAlertSystem::DispatchAlert(
            Mjolnir::ThreatLevel::MEDIUM,
            "CONFIG",
            "Failed to load whitelist.json: " +
                loadResult.errorMessage +
                ". Operating with restrictive defaults."
        );
    }

    if (config.GetSettings().enableSelfProtect) {
        const auto selfReport =
            Mjolnir::SelfProtect::Initialize();

        std::string reasons;
        for (
            std::size_t index = 0;
            index < selfReport.reasons.size();
            ++index
        ) {
            if (index > 0) {
                reasons += "; ";
            }
            reasons += selfReport.reasons[index];
        }

        Mjolnir::SecurityAlertSystem::DispatchAlert(
            selfReport.riskScore >= 40
                ? Mjolnir::ThreatLevel::HIGH
                : Mjolnir::ThreatLevel::LOW,
            "SELF",
            "Self-protect initialized. Mitigations=" +
                std::string(
                    selfReport.mitigationsApplied
                        ? "yes"
                        : "partial"
                ) +
                " Reasons=" +
                (reasons.empty() ? "none" : reasons),
            GetCurrentProcessId(),
            selfReport.riskScore
        );
    }

    const auto selfDebug =
        Mjolnir::DebuggerDetector::InspectCurrentProcess();

    if (selfDebug.attached) {
        Mjolnir::SecurityAlertSystem::DispatchAlert(
            Mjolnir::ThreatLevel::HIGH,
            "DEBUGGER",
            "Security core itself appears to be debugged.",
            GetCurrentProcessId(),
            selfDebug.riskScore
        );
    }

    DWORD targetPid = 0;
    std::uint64_t cycle = 0;

    while (g_running) {
        Mjolnir::SelfProtect::Pulse();

        if (config.ReloadIfChanged()) {
            ApplyAlertSettingsFromConfig(alertSettings, config);
            Mjolnir::IntegrityChecker::ClearCache();

            Mjolnir::SecurityAlertSystem::DispatchAlert(
                Mjolnir::ThreatLevel::LOW,
                "CONFIG",
                "Configuration reloaded from disk."
            );
        }

        const auto settings = config.GetSettings();
        const auto target = config.GetTarget();
        const std::wstring targetName =
            Utf8ToWide(target.processName);

        if (targetPid == 0) {
            targetPid =
                Mjolnir::MemoryManager::GetProcessIdByName(
                    targetName
                );

            if (
                targetPid == 0 &&
                !target.windowTitle.empty()
            ) {
                targetPid =
                    Mjolnir::MemoryManager::GetProcessIdByWindowTitle(
                        Utf8ToWide(target.windowTitle)
                    );
            }

            if (targetPid != 0) {
                Mjolnir::SecurityAlertSystem::DispatchAlert(
                    Mjolnir::ThreatLevel::LOW,
                    "MONITOR",
                    "Target acquired: " +
                        target.processName +
                        (
                            target.windowTitle.empty()
                                ? ""
                                : (" / '" + target.windowTitle + "'")
                        ) +
                        " (PID " +
                        std::to_string(targetPid) +
                        ")",
                    targetPid
                );
            }
        } else {
            HANDLE probe =
                Mjolnir::MemoryManager::OpenTargetProcess(
                    targetPid,
                    PROCESS_QUERY_LIMITED_INFORMATION
                );

            if (
                probe == nullptr ||
                !Mjolnir::MemoryManager::IsProcessAlive(probe)
            ) {
                Mjolnir::SecurityAlertSystem::DispatchAlert(
                    Mjolnir::ThreatLevel::MEDIUM,
                    "MONITOR",
                    "Lost target process. Waiting for relaunch.",
                    targetPid
                );

                targetPid = 0;
                engine.ResetSessionState();

                if (probe != nullptr) {
                    CloseHandle(probe);
                }
            } else {
                CloseHandle(probe);

                Mjolnir::SelfProtect::Pulse();

                const auto report =
                    engine.RunCycle(targetPid);

                if (!settings.observeOnly) {
                    const auto enforcement =
                        Mjolnir::EnforcementOfficer::MaybeTerminateTarget(
                            targetPid,
                            report.highestRisk,
                            settings.enforceRiskThreshold,
                            settings.observeOnly
                        );

                    if (
                        settings.enforceTerminateWatchedTools
                    ) {
                        Mjolnir::EnforcementOfficer::MaybeTerminateWatchedTools(
                            config.GetSnapshot()
                                .monitorOnlyProcesses,
                            settings.observeOnly
                        );
                    }

                    if (enforcement.succeeded) {
                        targetPid = 0;
                    }
                }

                ++cycle;

                if (cycle % 20 == 0) {
                    Mjolnir::SecurityAlertSystem::DispatchAlert(
                        Mjolnir::ThreatLevel::LOW,
                        "HEARTBEAT",
                        "Scan cycle " +
                            std::to_string(cycle) +
                            " complete. Findings=" +
                            std::to_string(report.findings) +
                            " Emitted=" +
                            std::to_string(
                                report.emittedAlerts
                            ) +
                            " HighestRisk=" +
                            std::to_string(
                                report.highestRisk
                            ) +
                            " ObserveOnly=" +
                            std::string(
                                settings.observeOnly
                                    ? "true"
                                    : "false"
                            ),
                        targetPid
                    );
                }

                if (
                    settings.enableSelfProtect &&
                    cycle % 15 == 0
                ) {
                    const auto selfReport =
                        Mjolnir::SelfProtect::Inspect(
                            config.GetSnapshot()
                                .whitelistedProcesses,
                            config.GetRiskWeights().selfProtect
                        );

                    if (selfReport.riskScore >= 40) {
                        std::string reasons;
                        for (
                            std::size_t index = 0;
                            index < selfReport.reasons.size();
                            ++index
                        ) {
                            if (index > 0) {
                                reasons += "; ";
                            }
                            reasons += selfReport.reasons[index];
                        }

                        Mjolnir::SecurityAlertSystem::DispatchAlert(
                            Mjolnir::ThreatLevel::HIGH,
                            "SELF",
                            "Self-protect alert: " + reasons,
                            GetCurrentProcessId(),
                            selfReport.riskScore
                        );
                    }
                }
            }
        }

        const auto interval = std::chrono::milliseconds(
            settings.scanIntervalMs == 0
                ? 3000
                : settings.scanIntervalMs
        );

        std::this_thread::sleep_for(interval);
    }

    Mjolnir::SecurityAlertSystem::DispatchAlert(
        Mjolnir::ThreatLevel::LOW,
        "DAEMON",
        "Security core shutting down cleanly."
    );

    Mjolnir::SelfProtect::StopWatchdog();
    Mjolnir::SecurityAlertSystem::ClearExternalSink();
    return 0;
}
