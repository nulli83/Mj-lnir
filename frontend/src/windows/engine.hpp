#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "alert.hpp"
#include "artifacts.hpp"
#include "baseline.hpp"
#include "config.hpp"
#include "debugger.hpp"
#include "devices.hpp"
#include "handles.hpp"
#include "hooks.hpp"
#include "image_integrity.hpp"
#include "inline_hooks.hpp"
#include "integrity.hpp"
#include "manual_map.hpp"
#include "memory.hpp"
#include "modules.hpp"
#include "overlay.hpp"
#include "process.hpp"
#include "regions.hpp"
#include "services.hpp"
#include "threads.hpp"
#include "timing.hpp"

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
        Memory,
        Thread,
        Process,
        Hook,
        Timing,
        InlineHook,
        ManualMap,
        Device,
        ImageIntegrity,
        Artifact,
        Service,
        Baseline,
        SelfProtect
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
        std::size_t emittedAlerts = 0;
        int highestRisk = 0;
        std::vector<SecurityFinding> alerts;
    };

    class SecurityEngine {
    private:
        ConfigManager& config_;
        std::uint64_t cycleCounter_ = 0;
        SessionBaseline baseline_{};
        DWORD baselinePid_ = 0;

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
                case FindingCategory::Thread:
                    return "THREAD";
                case FindingCategory::Process:
                    return "TARGET";
                case FindingCategory::Hook:
                    return "HOOK";
                case FindingCategory::Timing:
                    return "TIMING";
                case FindingCategory::InlineHook:
                    return "INLINE_HOOK";
                case FindingCategory::ManualMap:
                    return "MANUAL_MAP";
                case FindingCategory::Device:
                    return "DEVICE";
                case FindingCategory::ImageIntegrity:
                    return "IMAGE";
                case FindingCategory::Artifact:
                    return "ARTIFACT";
                case FindingCategory::Service:
                    return "SERVICE";
                case FindingCategory::Baseline:
                    return "BASELINE";
                case FindingCategory::SelfProtect:
                    return "SELF";
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

            const bool emitted =
                SecurityAlertSystem::DispatchAlert(
                    finding.level,
                    CategoryName(finding.category),
                    finding.title + " | " + finding.details,
                    finding.processId,
                    finding.riskScore
                );

            if (emitted) {
                ++report.emittedAlerts;
                report.alerts.push_back(std::move(finding));
            }
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

            constexpr std::size_t maxIntegrityChecks = 8;
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
                            module.path,
                            true
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

                if (integrity.fromCache) {
                    details << " Cache=hit";
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
                const int score = overlay.riskScore +
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
                std::ostringstream accessHex;
                accessHex << std::hex << handle.grantedAccess;

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
                            " Access=0x" + accessHex.str() +
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
            DebuggerFinding finding =
                DebuggerDetector::InspectProcess(
                    processHandle,
                    snapshot.riskWeights.debuggerAttached
                );

            if (!finding.attached) {
                return;
            }

            /*
             * Flera debugger-signaler ska inte stacka till
             * absurda riskvärden.
             */
            finding.riskScore = std::min(
                finding.riskScore,
                snapshot.riskWeights.debuggerAttached + 30
            );

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

        void ScanThreads(
            DWORD targetPid,
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const ThreadScanResult scan =
                ThreadScanner::ScanSuspiciousThreads(
                    targetPid,
                    30
                );

            if (!scan.Success()) {
                return;
            }

            constexpr std::size_t maxReports = 6;
            std::size_t reported = 0;

            for (
                const SuspiciousThreadInfo& thread :
                scan.threads
            ) {
                if (reported >= maxReports) {
                    break;
                }

                std::ostringstream details;
                details
                    << "TID=" << thread.threadId
                    << " Start=0x" << std::hex
                    << thread.startAddress << std::dec
                    << " Reasons="
                    << JoinReasons(thread.reasons);

                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::Thread,
                        ThreatLevel::LOW,
                        "Thread starts outside loaded modules",
                        details.str(),
                        targetPid,
                        thread.riskScore +
                            snapshot.riskWeights.unknownModule
                    }
                );

                ++reported;
            }
        }

        void ScanTargetProcess(
            HANDLE processHandle,
            DWORD targetPid,
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const ParentProcessInfo info =
                ProcessInspector::InspectTarget(
                    processHandle,
                    targetPid,
                    snapshot.target.expectedInstallRoots,
                    snapshot.whitelistedProcesses,
                    snapshot.riskWeights.unknownProcess
                );

            if (info.riskScore < 15) {
                return;
            }

            std::ostringstream details;
            details
                << "Image='" << info.imagePath << "'"
                << " Parent='" << info.parentProcessName
                << "' (PID " << info.parentProcessId << ")"
                << " ExpectedRoot="
                << (info.insideExpectedRoot ? "yes" : "no")
                << " Reasons="
                << JoinReasons(info.reasons);

            EmitFinding(
                report,
                SecurityFinding{
                    FindingCategory::Process,
                    ThreatLevel::LOW,
                    "Target process provenance looks suspicious",
                    details.str(),
                    targetPid,
                    info.riskScore
                }
            );
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

            std::unordered_set<std::string> alreadyReported;

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

                    if (
                        !alreadyReported.insert(processName)
                             .second
                    ) {
                        continue;
                    }

                    int score =
                        snapshot.riskWeights.unknownProcess +
                        25;

                    /*
                     * Kända cheat/debug-verktyg får högre vikt.
                     */
                    static const std::unordered_set<std::string>
                        elevatedTools = {
                            "cheatengine.exe",
                            "cheatengine-x86_64.exe",
                            "x64dbg.exe",
                            "x32dbg.exe",
                            "x96dbg.exe",
                            "ida.exe",
                            "ida64.exe",
                            "ollydbg.exe",
                            "processhacker.exe",
                            "systeminformer.exe",
                            "reclass.net.exe",
                            "reclass.exe"
                        };

                    if (
                        elevatedTools.find(processName) !=
                        elevatedTools.end()
                    ) {
                        score += 25;
                    }

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

        void ScanHooks(
            HANDLE processHandle,
            DWORD targetPid,
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const ModuleScanResult modules =
                ModuleScanner::ScanModules(
                    targetPid,
                    snapshot.whitelistedModules
                );

            if (!modules.Success() || modules.modules.empty()) {
                return;
            }

            std::uintptr_t mainBase = 0;
            const std::string targetName =
                ToLower(snapshot.target.processName);

            for (const ModuleInfo& module : modules.modules) {
                if (ToLower(module.name) == targetName) {
                    mainBase = module.baseAddress;
                    break;
                }
            }

            if (mainBase == 0) {
                mainBase = modules.modules.front().baseAddress;
            }

            const HookScanResult scan =
                HookDetector::ScanCriticalImports(
                    processHandle,
                    targetPid,
                    mainBase,
                    snapshot.riskWeights.apiHook
                );

            if (!scan.Success()) {
                return;
            }

            for (const HookFinding& hook : scan.hooks) {
                std::ostringstream details;
                details
                    << "Import=" << hook.importedFrom
                    << "!" << hook.functionName
                    << " IAT=0x" << std::hex
                    << hook.iatAddress
                    << " Resolved=0x"
                    << hook.resolvedAddress
                    << std::dec
                    << " Reasons="
                    << JoinReasons(hook.reasons);

                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::Hook,
                        ThreatLevel::LOW,
                        "Critical API import appears hooked",
                        details.str(),
                        targetPid,
                        hook.riskScore
                    }
                );
            }
        }

        void ScanTiming(
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const TimingFinding finding =
                TimingDetector::InspectLocalProcess(
                    snapshot.riskWeights.timingAnomaly
                );

            if (!finding.anomalyDetected) {
                return;
            }

            std::ostringstream details;
            details
                << "QpcMicros=" << finding.qpcMicros
                << " TickMicros=" << finding.tickMicros
                << " Ratio=" << finding.ratio
                << " Reasons="
                << JoinReasons(finding.reasons);

            EmitFinding(
                report,
                SecurityFinding{
                    FindingCategory::Timing,
                    ThreatLevel::LOW,
                    "Timing anomaly suggests instrumentation or single-stepping",
                    details.str(),
                    GetCurrentProcessId(),
                    finding.riskScore
                }
            );
        }

        void ScanInlineHooks(
            HANDLE processHandle,
            DWORD targetPid,
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const InlineHookScanResult scan =
                InlineHookDetector::ScanCriticalPrologues(
                    processHandle,
                    targetPid,
                    snapshot.riskWeights.inlineHook
                );

            if (!scan.Success()) {
                return;
            }

            for (const InlineHookFinding& hook : scan.hooks) {
                std::ostringstream details;
                details
                    << "Function=" << hook.moduleName
                    << "!" << hook.functionName
                    << " Addr=0x" << std::hex
                    << hook.remoteAddress << std::dec
                    << " Prologue=" << hook.prologueHex
                    << " Reasons="
                    << JoinReasons(hook.reasons);

                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::InlineHook,
                        ThreatLevel::LOW,
                        "Critical API prologue looks inline-hooked",
                        details.str(),
                        targetPid,
                        hook.riskScore
                    }
                );
            }
        }

        void ScanManualMaps(
            HANDLE processHandle,
            DWORD targetPid,
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const ManualMapScanResult scan =
                ManualMapDetector::ScanPrivateImages(
                    processHandle,
                    snapshot.riskWeights.manualMap
                );

            if (!scan.Success()) {
                return;
            }

            constexpr std::size_t maxReports = 6;
            std::size_t reported = 0;

            for (const ManualMapFinding& finding : scan.findings) {
                if (reported >= maxReports) {
                    break;
                }

                std::ostringstream details;
                details
                    << "Base=0x" << std::hex
                    << finding.baseAddress << std::dec
                    << " Size=" << finding.regionSize
                    << " Machine=0x" << std::hex
                    << finding.machine << std::dec
                    << " Reasons="
                    << JoinReasons(finding.reasons);

                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::ManualMap,
                        ThreatLevel::LOW,
                        "Private PE image looks manually mapped",
                        details.str(),
                        targetPid,
                        finding.riskScore
                    }
                );

                ++reported;
            }
        }

        void ScanDevices(
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const DeviceScanResult scan =
                DeviceScanner::ScanKnownThreats(
                    snapshot.riskWeights.riskyDevice,
                    snapshot.riskWeights.riskyDevice
                );

            if (!scan.Success()) {
                return;
            }

            for (const DeviceFinding& device : scan.devices) {
                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::Device,
                        ThreatLevel::LOW,
                        "Risky kernel device interface detected",
                        "Device='" + device.devicePath +
                            "' Label='" + device.label +
                            "' Reasons=" +
                            JoinReasons(device.reasons),
                        0,
                        device.riskScore
                    }
                );
            }

            for (const DriverFinding& driver : scan.drivers) {
                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::Device,
                        ThreatLevel::LOW,
                        "Risky kernel driver image is loaded",
                        "Driver='" + driver.baseName +
                            "' Path='" + driver.imagePath +
                            "' Reasons=" +
                            JoinReasons(driver.reasons),
                        0,
                        driver.riskScore
                    }
                );
            }
        }

        void ScanImageIntegrity(
            HANDLE processHandle,
            DWORD targetPid,
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const ModuleScanResult modules =
                ModuleScanner::ScanModules(
                    targetPid,
                    snapshot.whitelistedModules
                );

            if (!modules.Success() || modules.modules.empty()) {
                return;
            }

            const std::string targetName =
                ToLower(snapshot.target.processName);

            const ModuleInfo* mainModule = nullptr;

            for (const ModuleInfo& module : modules.modules) {
                if (ToLower(module.name) == targetName) {
                    mainModule = &module;
                    break;
                }
            }

            if (mainModule == nullptr) {
                mainModule = &modules.modules.front();
            }

            if (
                mainModule->path.empty() ||
                mainModule->baseAddress == 0
            ) {
                return;
            }

            const ImageIntegrityScanResult scan =
                ImageIntegrityScanner::ScanModule(
                    processHandle,
                    mainModule->baseAddress,
                    mainModule->path,
                    snapshot.riskWeights.imageIntegrity
                );

            if (!scan.Success()) {
                return;
            }

            for (
                const ImageIntegrityFinding& finding :
                scan.findings
            ) {
                std::ostringstream details;
                details
                    << "Module='" << finding.modulePath << "'"
                    << " Base=0x" << std::hex
                    << finding.moduleBase << std::dec
                    << " Compared=" << finding.bytesCompared
                    << " HookSites=" << finding.hookLikePatches
                    << " Reasons="
                    << JoinReasons(finding.reasons);

                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::ImageIntegrity,
                        ThreatLevel::LOW,
                        "Main module image integrity mismatch",
                        details.str(),
                        targetPid,
                        finding.riskScore
                    }
                );
            }
        }

        void ScanArtifacts(
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const ArtifactScanResult scan =
                ArtifactScanner::ScanKnownArtifacts(
                    snapshot.riskWeights.knownArtifact
                );

            if (!scan.Success()) {
                return;
            }

            for (const ArtifactFinding& artifact : scan.artifacts) {
                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::Artifact,
                        ThreatLevel::LOW,
                        "Known cheat/debugger artifact detected",
                        "Kind=" + artifact.kind +
                            " Name='" + artifact.name +
                            "' Reasons=" +
                            JoinReasons(artifact.reasons),
                        0,
                        artifact.riskScore
                    }
                );
            }
        }

        void ScanServices(
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            const ServiceScanResult scan =
                ServiceScanner::ScanSuspiciousServices(
                    snapshot.riskWeights.suspiciousService
                );

            if (!scan.Success()) {
                return;
            }

            for (const ServiceFinding& service : scan.services) {
                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::Service,
                        ThreatLevel::LOW,
                        "Suspicious Windows service detected",
                        "Service='" + service.serviceName +
                            "' Display='" + service.displayName +
                            "' State=" +
                            std::to_string(service.state) +
                            " Reasons=" +
                            JoinReasons(service.reasons),
                        0,
                        service.riskScore
                    }
                );
            }
        }

        void TrackBaseline(
            HANDLE processHandle,
            DWORD targetPid,
            const ConfigSnapshot& snapshot,
            ScanCycleReport& report
        ) {
            if (!snapshot.settings.enableBaselineTracking) {
                return;
            }

            if (baselinePid_ != targetPid) {
                baseline_.Reset();
                baselinePid_ = targetPid;
            }

            const ModuleScanResult modules =
                ModuleScanner::ScanModules(
                    targetPid,
                    snapshot.whitelistedModules
                );

            if (!modules.Success() || modules.modules.empty()) {
                return;
            }

            std::vector<std::pair<std::string, std::uintptr_t>>
                modulePairs;

            modulePairs.reserve(modules.modules.size());

            const std::string targetName =
                ToLower(snapshot.target.processName);

            std::string mainPath;
            std::uintptr_t mainBase = 0;

            for (const ModuleInfo& module : modules.modules) {
                modulePairs.emplace_back(
                    module.name,
                    module.baseAddress
                );

                if (
                    mainBase == 0 &&
                    ToLower(module.name) == targetName
                ) {
                    mainPath = module.path;
                    mainBase = module.baseAddress;
                }
            }

            if (mainBase == 0) {
                mainPath = modules.modules.front().path;
                mainBase = modules.modules.front().baseAddress;
            }

            if (!baseline_.Established()) {
                baseline_.Establish(
                    targetPid,
                    processHandle,
                    modulePairs,
                    mainPath,
                    mainBase
                );

                SecurityAlertSystem::DispatchAlert(
                    ThreatLevel::LOW,
                    "BASELINE",
                    "Session baseline established with " +
                        std::to_string(modulePairs.size()) +
                        " modules",
                    targetPid
                );
                return;
            }

            const BaselineDiffResult diff = baseline_.Diff(
                processHandle,
                modulePairs,
                snapshot.whitelistedModules,
                snapshot.riskWeights.moduleBirth,
                snapshot.riskWeights.codeMutation
            );

            for (const BaselineFinding& finding : diff.findings) {
                EmitFinding(
                    report,
                    SecurityFinding{
                        FindingCategory::Baseline,
                        ThreatLevel::LOW,
                        finding.kind == "module_birth"
                            ? "New module appeared after baseline"
                            : "Module code mutated after baseline",
                        "Module='" + finding.details +
                            "' Reasons=" +
                            JoinReasons(finding.reasons),
                        targetPid,
                        finding.riskScore
                    }
                );
            }
        }

    public:
        explicit SecurityEngine(ConfigManager& config)
            : config_(config) {}

        void ResetSessionState() {
            baseline_.Reset();
            baselinePid_ = 0;
        }

        ScanCycleReport RunCycle(DWORD targetPid) {
            ScanCycleReport report{};
            report.targetPid = targetPid;

            if (targetPid == 0) {
                return report;
            }

            ++cycleCounter_;

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

            ScanTargetProcess(
                processHandle,
                targetPid,
                snapshot,
                report
            );

            TrackBaseline(
                processHandle,
                targetPid,
                snapshot,
                report
            );

            ScanModules(targetPid, snapshot, report);
            ScanOverlays(targetPid, snapshot, report);
            ScanDebugger(
                processHandle,
                targetPid,
                snapshot,
                report
            );
            ScanThreads(targetPid, snapshot, report);

            if (
                snapshot.settings.enableHookScan &&
                (cycleCounter_ % 3 == 2)
            ) {
                ScanHooks(
                    processHandle,
                    targetPid,
                    snapshot,
                    report
                );
            }

            if (
                snapshot.settings.enableInlineHookScan &&
                (cycleCounter_ % 4 == 1)
            ) {
                ScanInlineHooks(
                    processHandle,
                    targetPid,
                    snapshot,
                    report
                );
            }

            if (
                snapshot.settings.enableManualMapScan &&
                (cycleCounter_ % 4 == 2)
            ) {
                ScanManualMaps(
                    processHandle,
                    targetPid,
                    snapshot,
                    report
                );
            }

            /*
             * Dyra skanningar körs mer sällan.
             */
            if (
                snapshot.settings.enableHandleScan &&
                (cycleCounter_ % 3 == 1)
            ) {
                ScanHandles(targetPid, snapshot, report);
            }

            if (
                snapshot.settings.enableMemoryRegionScan &&
                (cycleCounter_ % 2 == 0)
            ) {
                ScanMemoryRegions(
                    processHandle,
                    targetPid,
                    report
                );
            }

            if (cycleCounter_ % 2 == 1) {
                ScanWatchedProcesses(snapshot, report);
            }

            if (
                snapshot.settings.enableDeviceScan &&
                (cycleCounter_ % 10 == 3)
            ) {
                ScanDevices(snapshot, report);
            }

            if (
                snapshot.settings.enableImageIntegrityScan &&
                (cycleCounter_ % 4 == 3)
            ) {
                ScanImageIntegrity(
                    processHandle,
                    targetPid,
                    snapshot,
                    report
                );
            }

            if (
                snapshot.settings.enableArtifactScan &&
                (cycleCounter_ % 3 == 0)
            ) {
                ScanArtifacts(snapshot, report);
            }

            if (
                snapshot.settings.enableServiceScan &&
                (cycleCounter_ % 12 == 5)
            ) {
                ScanServices(snapshot, report);
            }

            if (
                snapshot.settings.enableTimingScan &&
                (cycleCounter_ % 5 == 0)
            ) {
                ScanTiming(snapshot, report);
            }

            CloseHandle(processHandle);
            return report;
        }
    };

} // namespace Mjolnir
