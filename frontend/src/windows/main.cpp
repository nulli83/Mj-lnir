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
#include "engine.hpp"
#include "ipc.hpp"
#include "memory.hpp"

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
        "[Mjölnir v1.1.0] Security core armed. "
        "Vectors: modules, overlays, handles, debugger, "
        "integrity, memory-regions, process-watch."
    );

    const auto loadResult =
        config.LoadConfigDetailed("whitelist.json");

    if (loadResult) {
        Mjolnir::SecurityAlertSystem::DispatchAlert(
            Mjolnir::ThreatLevel::LOW,
            "CONFIG",
            "Loaded whitelist.json successfully."
        );

        const auto settings = config.GetSettings();
        alertSettings.duplicateCooldownMs =
            settings.alertCooldownMs;
        Mjolnir::SecurityAlertSystem::Configure(
            alertSettings
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
        if (config.ReloadIfChanged()) {
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

            if (targetPid != 0) {
                Mjolnir::SecurityAlertSystem::DispatchAlert(
                    Mjolnir::ThreatLevel::LOW,
                    "MONITOR",
                    "Target acquired: " +
                        target.processName +
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

                if (probe != nullptr) {
                    CloseHandle(probe);
                }
            } else {
                CloseHandle(probe);

                const auto report =
                    engine.RunCycle(targetPid);

                ++cycle;

                if (cycle % 20 == 0) {
                    Mjolnir::SecurityAlertSystem::DispatchAlert(
                        Mjolnir::ThreatLevel::LOW,
                        "HEARTBEAT",
                        "Scan cycle " +
                            std::to_string(cycle) +
                            " complete. Findings this cycle: " +
                            std::to_string(report.findings) +
                            ". Highest risk: " +
                            std::to_string(
                                report.highestRisk
                            ) +
                            ". Observe-only=" +
                            std::string(
                                settings.observeOnly
                                    ? "true"
                                    : "false"
                            ),
                        targetPid
                    );
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

    Mjolnir::SecurityAlertSystem::ClearExternalSink();
    return 0;
}
