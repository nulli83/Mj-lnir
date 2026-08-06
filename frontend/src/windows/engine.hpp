#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "alert.hpp"
#include "config.hpp"
#include "debugger.hpp"
#include "handles.hpp"
#include "integrity.hpp"
#include "memory.hpp"
#include "modules.hpp"
#include "overlay.hpp"
#include "regions.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Mjolnir {

    enum class FindingCategory {
        Module,
        Overlay,
        Handle,
        Debugger,
        ProcessWatch,
        Integrity,
        Memory
    };

    struct SecurityFinding {
        FindingCategory category = FindingCategory::Module;
        ThreatLevel level = ThreatLevel::LOW;

        std::string title;
        std::string details;

        DWORD processId = 0;
        int riskScore = 0;
    };

    struct ScanCycleReport {
        DWORD targetPid = 0;
        std::size_t findings = 0;
        int highestRisk = 0;
        std::vector<SecurityFinding> alerts;
    };

    class SecurityEngine {
    private:
        ConfigManager& config_;

        static std::string ToLower(std::string value) {
            std::transform(
                value.begin(),
                value.end(),
                value.begin(),
                [](unsigned char character) {
                    return static_cast<char>(
                        std::tolower(character)
                    );
                }
            );

            return value;
        }

        static std::string JoinReasons(
            const std::vector<std::string>& reasons
        ) {
            if (reasons.empty()) {
                return "No detailed reasons available";
            }

            std::ostringstream stream;

            for (std::size_t index = 0;
                 index < reasons.size();
                 ++index) {
                if (index > 0) {
                    stream << "; ";
                }

                stream << reasons[index];
            }

            return stream.str();
        }

        static ThreatLevel ScoreToThreatLevel(int riskScore) {
            if (riskScore >= 80) {
                return ThreatLevel::CRITICAL;
            }

            if (riskScore >= 50) {
                return ThreatLevel::HIGH;
            }

            if (riskScore >= 25) {
                return ThreatLevel::MEDIUM;
            }

            return ThreatLevel::LOW;
        }

        static std::string CategoryName(
            FindingCategory category
        ) {
            switch (category) {
                case FindingCategory::Module:
                    return "MODULE";
                case FindingCategory::Overlay:
                    return "OVERLAY";
                case FindingCategory::Handle:
                    return "HANDLE";
                case FindingCategory::Debugger:
                    return "DEBUGGER";
                case FindingCategory::ProcessWatch:
                    return "PROCESS";
                case FindingCategory::Integrity:
                    return "INTEGRITY";
                case FindingCategory::Memory:
                    return "MEMORY";
                default:
                    return "UNKNOWN";
            }
        }

        void EmitFinding(
            ScanCycleReport& report,
            SecurityFinding finding
        ) {
            finding.level =
                ScoreToThreatLevel(finding.riskScore);

            report.highestRisk = std::max(
                report.highestRisk,
                finding.riskScore
            );

            ++report.findings;

            SecurityAlertSystem::DispatchAlert(
                finding.level,
                CategoryName(finding.category),
                finding.title + " | " + finding.details,
                finding.processId,
                finding.riskScore
            );

            report.alerts.push_back(std::move(finding));
        }

        void ScanModules(
            DWORD targetPid,
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const ModuleScanResult scan =
                ModuleScanner::ScanModules(
                    targetPid,
                    snapshot.whitelistedModules
                );

            if (!scan.Success()) {
                SecurityAlertSystem::DispatchAlert(
                    ThreatLevel::MEDIUM,
                    "MODULE",
                    "Module enumeration failed with error " +
                        std::to_string(scan.errorCode),
                    targetPid
                );
                return;
            }

            const bool requireSignature =
                snapshot.settings.requireValidSignature;

            constexpr std::size_t maxIntegrityChecks = 12;
            std::size_t integrityChecks = 0;

            for (const ModuleInfo& module : scan.modules) {
                int score = module.riskScore;

                if (
                    !module.whitelisted &&
                    !module.systemModule
                ) {
                    score +=
                        snapshot.riskWeights.unknownModule;
                }

                if (module.suspiciousPath) {
                    score = std::max(
                        score,
                        snapshot.riskWeights
                            .moduleFromSuspiciousDirectory
                    );
                }

                FileIntegrityInfo integrity{};

                const bool shouldInspectIntegrity =
                    !module.path.empty() &&
                    (
                        requireSignature ||
                        module.suspiciousPath ||
                        (
                            !module.whitelisted &&
                            !module.systemModule
                        )
                    ) &&
                    integrityChecks < maxIntegrityChecks;

                if (shouldInspectIntegrity) {
                    integrity =
                        IntegrityChecker::InspectFile(
                            module.path
                        );

                    ++integrityChecks;

                    if (
                        !integrity.sha256.empty() &&
                        snapshot.trustedHashes.find(
                            integrity.sha256
                        ) != snapshot.trustedHashes.end()
                    ) {
                        score +=
                            snapshot.riskWeights.trustedHash;
                    }

                    if (
                        !integrity.sha256.empty() &&
                        snapshot.knownBadHashes.find(
                            integrity.sha256
                        ) != snapshot.knownBadHashes.end()
                    ) {
                        score +=
                            snapshot.riskWeights.knownBadHash;
                    }

                    if (
                        integrity.signatureValid &&
                        !integrity.publisher.empty() &&
                        snapshot.trustedPublishers.find(
                            ToLower(integrity.publisher)
                        ) !=
                            snapshot.trustedPublishers.end()
                    ) {
                        score +=
                            snapshot.riskWeights
                                .trustedPublisher;
                    }

                    if (
                        requireSignature &&
                        !integrity.signatureValid &&
                        !module.whitelisted
                    ) {
                        score +=
                            snapshot.riskWeights
                                .unsignedModule;
                    }

                    if (
                        snapshot.settings
                            .allowUnknownMicrosoftModules &&
                        integrity.microsoftPublisher &&
                        integrity.signatureValid
                    ) {
                        score = std::max(0, score - 20);
                    }
                }

                score = std::max(0, score);

                if (score < 20) {
                    continue;
                }

                std::ostringstream details;

                details
                    << "Module='" << module.name << "'"
                    << " Path='" << module.path << "'"
                    << " Base=0x" << std::hex
                    << module.baseAddress << std::dec
                    << " Size=" << module.imageSize
                    << " Reasons="
                    << JoinReasons(module.reasons);

                if (!integrity.sha256.empty()) {
                    details
                        << " SHA256="
                        << integrity.sha256;
                }

                if (!integrity.publisher.empty()) {
                    details
                        << " Publisher='"
                        << integrity.publisher
                        << "'";
                }

                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::Module,
                        ThreatLevel::LOW,
                        "Suspicious module loaded into target",
                        details.str(),
                        targetPid,
                        score
                    }
                );
            }
        }

        void ScanOverlays(
            DWORD targetPid,
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const auto overlays =
                OverlayDetector::DetectSuspiciousOverlays(
                    targetPid,
                    snapshot.allowedOverlayProcesses,
                    40
                );

            for (const WindowInfo& overlay : overlays) {
                int score = overlay.riskScore +
                    snapshot.riskWeights.unexpectedOverlay;

                std::ostringstream details;

                details
                    << "Title='" << overlay.title << "'"
                    << " Class='" << overlay.className << "'"
                    << " Process='" << overlay.processName
                    << "'"
                    << " Coverage="
                    << static_cast<int>(
                           overlay.targetCoverage * 100.0
                       )
                    << "%"
                    << " Reasons="
                    << JoinReasons(overlay.reasons);

                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::Overlay,
                        ThreatLevel::LOW,
                        "Suspicious overlay covering the target",
                        details.str(),
                        overlay.processId,
                        score
                    }
                );
            }
        }

        void ScanHandles(
            DWORD targetPid,
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const HandleScanResult scan =
                HandleScanner::ScanExternalHandles(
                    targetPid,
                    snapshot.whitelistedProcesses,
                    snapshot.riskWeights
                        .externalProcessHandle
                );

            if (!scan.Success()) {
                /*
                 * Handle-enumeration kan kräva admin.
                 * Logga mjukt så att övriga vektorer fortsätter.
                 */
                SecurityAlertSystem::DispatchAlert(
                    ThreatLevel::LOW,
                    "HANDLE",
                    "Handle scan unavailable (error " +
                        std::to_string(scan.errorCode) +
                        "). Continuing with other vectors.",
                    targetPid
                );
                return;
            }

            for (const ExternalHandleInfo& handle : scan.handles) {
                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::Handle,
                        ThreatLevel::LOW,
                        "External process holds a handle to the target",
                        "Owner='" + handle.ownerProcessName +
                            "' PID=" +
                            std::to_string(
                                handle.ownerProcessId
                            ) +
                            " Access=0x" +
                            [&]() {
                                std::ostringstream hex;
                                hex << std::hex
                                    << handle.grantedAccess;
                                return hex.str();
                            }() +
                            " Reasons=" +
                            JoinReasons(handle.reasons),
                        handle.ownerProcessId,
                        handle.riskScore
                    }
                );
            }
        }

        void ScanDebugger(
            HANDLE processHandle,
            DWORD targetPid,
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const DebuggerFinding finding =
                DebuggerDetector::InspectProcess(
                    processHandle,
                    snapshot.riskWeights.debuggerAttached
                );

            if (!finding.attached) {
                return;
            }

            EmitFinding(
                report,
                SecurityFinding{
                    FindingCategory::Debugger,
                    ThreatLevel::LOW,
                    "Debugger activity detected on target process",
                    JoinReasons(finding.reasons),
                    targetPid,
                    finding.riskScore
                }
            );
        }

        void ScanMemoryRegions(
            HANDLE processHandle,
            DWORD targetPid,
            ScanCycleReport& report
        ) {
            const MemoryRegionScanResult scan =
                MemoryRegionScanner::ScanSuspiciousRegions(
                    processHandle
                );

            if (!scan.Success()) {
                return;
            }

            constexpr std::size_t maxReports = 8;
            std::size_t reported = 0;

            for (
                const MemoryRegionInfo& region :
                scan.suspiciousRegions
            ) {
                if (reported >= maxReports) {
                    break;
                }

                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::Memory,
                        ThreatLevel::LOW,
                        "Suspicious executable memory region in target",
                        MemoryRegionScanner::FormatRegion(
                            region
                        ) +
                            " Reasons=" +
                            JoinReasons(region.reasons),
                        targetPid,
                        region.riskScore
                    }
                );

                ++reported;
            }
        }

        void ScanWatchedProcesses(
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            HANDLE snapshotHandle = CreateToolhelp32Snapshot(
                TH32CS_SNAPPROCESS,
                0
            );

            if (snapshotHandle == INVALID_HANDLE_VALUE) {
                return;
            }

            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);

            if (Process32FirstW(snapshotHandle, &entry)) {
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

                    const std::string processName =
                        ToLower(narrowName);

                    if (
                        snapshot.monitorOnlyProcesses.find(
                            processName
                        ) ==
                            snapshot.monitorOnlyProcesses
                                .end()
                    ) {
                        continue;
                    }

                    const int score =
                        snapshot.riskWeights.unknownProcess +
                        25;

                    EmitFinding(
                        report,
                        SecurityFinding{
                            FindingCategory::ProcessWatch,
                            ThreatLevel::LOW,
                            "Monitored high-risk tooling is running",
                            "Process='" + processName +
                                "' is listed as monitor-only "
                                "and often used for cheating/"
                                "reverse engineering",
                            entry.th32ProcessID,
                            score
                        }
                    );

                    entry.dwSize = sizeof(entry);

                } while (
                    Process32NextW(snapshotHandle, &entry)
                );
            }

            CloseHandle(snapshotHandle);
        }

    public:
        explicit SecurityEngine(ConfigManager& config)
            : config_(config) {}

        ScanCycleReport RunCycle(DWORD targetPid) {
            ScanCycleReport report{};
            report.targetPid = targetPid;

            if (targetPid == 0) {
                return report;
            }

            const ConfigSnapshot snapshot =
                config_.GetSnapshot();

            HANDLE processHandle =
                MemoryManager::OpenTargetProcess(
                    targetPid,
                    PROCESS_QUERY_INFORMATION |
                    PROCESS_VM_READ |
                    PROCESS_QUERY_LIMITED_INFORMATION
                );

            if (processHandle == nullptr) {
                SecurityAlertSystem::DispatchAlert(
                    ThreatLevel::MEDIUM,
                    "MONITOR",
                    "Unable to open target process for security scan",
                    targetPid
                );
                return report;
            }

            ScanModules(targetPid, snapshot, report);
            ScanOverlays(targetPid, snapshot, report);

            if (snapshot.settings.enableHandleScan) {
                ScanHandles(targetPid, snapshot, report);
            }

            ScanDebugger(
                processHandle,
                targetPid,
                snapshot,
                report
            );

            if (snapshot.settings.enableMemoryRegionScan) {
                ScanMemoryRegions(
                    processHandle,
                    targetPid,
                    report
                );
            }

            ScanWatchedProcesses(snapshot, report);

            CloseHandle(processHandle);
            return report;
        }
    };

} // namespace Mjolnir
