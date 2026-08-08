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
#include "evidence.hpp"
#include "integrity.hpp"
#include "ipc.hpp"
#include "memory.hpp"
#include "self_protect.hpp"
#include "twin_watchdog.hpp"

namespace {

    std::atomic<bool> g_running{true};
    Mjolnir::TwinWatchdogClient g_twin;

    std::string ResolveIpcHmacSecret(
        const Mjolnir::ConfigSettings& settings
    ) {
        char buffer[1024] = {};
        const DWORD length = GetEnvironmentVariableA(
            "MJOLNIR_IPC_SECRET",
            buffer,
            static_cast<DWORD>(sizeof(buffer))
        );

        if (length > 0 && length < sizeof(buffer)) {
            return std::string(buffer, length);
        }

        return settings.ipcHmacSecret;
    }

    void ApplyIpcSecret(
        Mjolnir::IpcClient& ipcClient,
        const Mjolnir::ConfigManager& config
    ) {
        ipcClient.SetHmacSecret(
            ResolveIpcHmacSecret(config.GetSettings())
        );
    }

    Mjolnir::EvidenceSettings MakeEvidenceSettings(
        const Mjolnir::ConfigSettings& settings
    ) {
        Mjolnir::EvidenceSettings evidence{};
        evidence.windowMs = settings.evidenceWindowMs;
        evidence.minSamples = settings.evidenceMinSamples;
        evidence.minAverageRisk = settings.evidenceMinAverageRisk;
        evidence.minPeakRisk = settings.evidenceMinPeakRisk;
        evidence.sustainedHighRisk =
            settings.evidenceSustainedHighRisk;
        evidence.minSustainedHighSamples =
            settings.evidenceMinSustainedHighSamples;
        evidence.settleCyclesAfterAttach =
            settings.evidenceSettleCycles;
        return evidence;
    }

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

    bool HasArg(int argc, char** argv, const char* needle) {
        for (int index = 1; index < argc; ++index) {
            if (std::string(argv[index]) == needle) {
                return true;
            }
        }

        return false;
    }

    void EnsureTwinWatchdog(bool enabled) {
        if (!enabled) {
            return;
        }

        if (!g_twin.OpenOrCreate(true)) {
            Mjolnir::SecurityAlertSystem::DispatchAlert(
                Mjolnir::ThreatLevel::MEDIUM,
                "WATCHDOG",
                "Failed to create twin heartbeat mapping."
            );
            return;
        }

        g_twin.PulseCore();

        const auto snapshot = g_twin.Snapshot();

        if (
            snapshot.watchdogPid != 0 &&
            Mjolnir::IsProcessAlive(snapshot.watchdogPid)
        ) {
            Mjolnir::SecurityAlertSystem::DispatchAlert(
                Mjolnir::ThreatLevel::LOW,
                "WATCHDOG",
                "Twin watchdog already running (PID " +
                    std::to_string(snapshot.watchdogPid) +
                    ")."
            );
            return;
        }

        const std::wstring watchdogPath =
            Mjolnir::GetSelfDirectory() + L"\\mjolnir_watchdog.exe";

        const std::wstring args =
            L"--parent=" +
            std::to_wstring(GetCurrentProcessId());

        if (
            Mjolnir::LaunchSiblingProcess(watchdogPath, args)
        ) {
            Mjolnir::SecurityAlertSystem::DispatchAlert(
                Mjolnir::ThreatLevel::LOW,
                "WATCHDOG",
                "Spawned twin watchdog process."
            );
        } else {
            Mjolnir::SecurityAlertSystem::DispatchAlert(
                Mjolnir::ThreatLevel::MEDIUM,
                "WATCHDOG",
                "Could not spawn mjolnir_watchdog.exe. "
                "Build/place it next to mjolnir_core.exe."
            );
        }
    }

} // namespace

int main(int argc, char** argv) {
    std::signal(SIGINT, HandleSignal);
    std::signal(SIGTERM, HandleSignal);

    Mjolnir::ConfigManager config("whitelist.json");
    Mjolnir::IpcClient ipcClient;
    Mjolnir::SecurityEngine engine(config);
    Mjolnir::EvidenceWindow evidenceWindow;

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
        "[Mjölnir v1.12.0] Security core armed. "
        "Vectors: modules, overlays, handles, debugger, "
        "integrity, memory-regions, threads, provenance, "
        "hooks, inline-hooks, eat-hooks, syscall-stubs, etw, "
        "manual-map, hollowing, writable-image, mitigations, stealth, "
        "devices, image, artifacts, services, baseline, lifetime, "
        "injection, privileges, pipes, persistence, ports, "
        "evidence-window, hmac-ipc, self-protect, twin-watchdog, "
        "timing, process-watch."
    );

    const auto loadResult =
        config.LoadConfigDetailed("whitelist.json");

    if (loadResult) {
        ApplyAlertSettingsFromConfig(alertSettings, config);
        ApplyIpcSecret(ipcClient, config);
        evidenceWindow.Configure(
            MakeEvidenceSettings(config.GetSettings())
        );

        Mjolnir::SecurityAlertSystem::DispatchAlert(
            Mjolnir::ThreatLevel::LOW,
            "CONFIG",
            "Loaded whitelist.json successfully. IPC HMAC=" +
                std::string(
                    ipcClient.HasHmacSecret() ? "on" : "off"
                )
        );
    } else {
        ApplyIpcSecret(ipcClient, config);

        Mjolnir::SecurityAlertSystem::DispatchAlert(
            Mjolnir::ThreatLevel::MEDIUM,
            "CONFIG",
            "Failed to load whitelist.json: " +
                loadResult.errorMessage +
                ". Operating with restrictive defaults."
        );
    }

    EnsureTwinWatchdog(config.GetSettings().enableTwinWatchdog);

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
    std::uint64_t lastWatchdogHeartbeat = 0;
    int watchdogStallCount = 0;

    while (g_running) {
        Mjolnir::SelfProtect::Pulse();
        g_twin.PulseCore();

        if (config.ReloadIfChanged()) {
            ApplyAlertSettingsFromConfig(alertSettings, config);
            ApplyIpcSecret(ipcClient, config);
            evidenceWindow.Configure(
                MakeEvidenceSettings(config.GetSettings())
            );
            Mjolnir::IntegrityChecker::ClearCache();

            Mjolnir::SecurityAlertSystem::DispatchAlert(
                Mjolnir::ThreatLevel::LOW,
                "CONFIG",
                "Configuration reloaded from disk. IPC HMAC=" +
                    std::string(
                        ipcClient.HasHmacSecret()
                            ? "on"
                            : "off"
                    )
            );
        }

        const auto settings = config.GetSettings();
        const auto target = config.GetTarget();
        const std::wstring targetName =
            Utf8ToWide(target.processName);

        if (settings.enableTwinWatchdog) {
            const auto twin = g_twin.Snapshot();

            if (
                twin.watchdogPid == 0 ||
                !Mjolnir::IsProcessAlive(twin.watchdogPid)
            ) {
                EnsureTwinWatchdog(true);
                watchdogStallCount = 0;
            } else if (
                twin.watchdogHeartbeat == lastWatchdogHeartbeat
            ) {
                ++watchdogStallCount;

                if (watchdogStallCount >= 8) {
                    Mjolnir::SecurityAlertSystem::DispatchAlert(
                        Mjolnir::ThreatLevel::HIGH,
                        "WATCHDOG",
                        "Twin watchdog heartbeat stalled; respawning.",
                        twin.watchdogPid
                    );
                    EnsureTwinWatchdog(true);
                    watchdogStallCount = 0;
                }
            } else {
                lastWatchdogHeartbeat = twin.watchdogHeartbeat;
                watchdogStallCount = 0;
            }
        }

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
                evidenceWindow.Reset();

                if (probe != nullptr) {
                    CloseHandle(probe);
                }
            } else {
                CloseHandle(probe);

                Mjolnir::SelfProtect::Pulse();

                const auto report =
                    engine.RunCycle(targetPid);

                evidenceWindow.Configure(
                    MakeEvidenceSettings(settings)
                );
                evidenceWindow.Push(
                    targetPid,
                    report.highestRisk,
                    report.findings,
                    report.emittedAlerts
                );

                const auto evidence =
                    evidenceWindow.Evaluate();

                if (!settings.observeOnly) {
                    Mjolnir::EnforcementResult enforcement{};

                    if (settings.enableEvidenceWindow) {
                        if (evidence.shouldEnforce) {
                            Mjolnir::SecurityAlertSystem::DispatchAlert(
                                Mjolnir::ThreatLevel::CRITICAL,
                                "EVIDENCE",
                                evidence.reason,
                                targetPid,
                                evidence.peakRisk
                            );

                            enforcement =
                                Mjolnir::EnforcementOfficer::MaybeTerminateTarget(
                                    targetPid,
                                    evidence.peakRisk,
                                    settings.enforceRiskThreshold,
                                    settings.observeOnly
                                );
                        }
                    } else {
                        enforcement =
                            Mjolnir::EnforcementOfficer::MaybeTerminateTarget(
                                targetPid,
                                report.highestRisk,
                                settings.enforceRiskThreshold,
                                settings.observeOnly
                            );
                    }

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
                        engine.ResetSessionState();
                        evidenceWindow.Reset();
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
                            " EvidencePeak=" +
                            std::to_string(evidence.peakRisk) +
                            " EvidenceAvg=" +
                            std::to_string(
                                evidence.averageRisk
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
    g_twin.Close();
    Mjolnir::SecurityAlertSystem::ClearExternalSink();

    (void)argc;
    (void)argv;
    (void)HasArg;
    return 0;
}
