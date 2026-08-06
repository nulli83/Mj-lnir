#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "alert.hpp"
#include "handles.hpp"
#include "integrity.hpp"

#include <windows.h>
#include <winternl.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "ntdll.lib")

namespace Mjolnir {

    struct SelfProtectReport {
        bool mitigationsApplied = false;
        bool selfIntegrityOk = true;
        bool debuggerDetected = false;
        std::size_t externalHandlesToSelf = 0;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    class SelfProtect {
    private:
        inline static std::atomic<std::uint64_t> heartbeat_{0};
        inline static std::atomic<bool> watchdogRunning_{false};
        inline static std::thread watchdogThread_;
        inline static std::string expectedSelfHash_;

        using NtSetInformationProcessFn =
            NTSTATUS(NTAPI*)(
                HANDLE ProcessHandle,
                ULONG ProcessInformationClass,
                PVOID ProcessInformation,
                ULONG ProcessInformationLength
            );

        static std::wstring GetSelfPathWide() {
            std::wstring path(32768, L'\0');
            DWORD length = static_cast<DWORD>(path.size());

            if (
                !QueryFullProcessImageNameW(
                    GetCurrentProcess(),
                    0,
                    path.data(),
                    &length
                )
            ) {
                return {};
            }

            path.resize(length);
            return path;
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

        static bool ApplyMitigationPolicies(
            std::vector<std::string>& reasons
        ) {
            bool any = false;

            /*
             * Stäng av legacy extension points (AppInit DLL etc).
             */
            PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY
                extensionPolicy{};
            extensionPolicy.DisableExtensionPoints = 1;

            if (
                SetProcessMitigationPolicy(
                    ProcessExtensionPointDisablePolicy,
                    &extensionPolicy,
                    sizeof(extensionPolicy)
                )
            ) {
                any = true;
                reasons.push_back(
                    "Extension point disable policy enabled"
                );
            }

            PROCESS_MITIGATION_ASLR_POLICY aslrPolicy{};
            aslrPolicy.EnableBottomUpRandomization = 1;
            aslrPolicy.EnableForceRelocateImages = 1;
            aslrPolicy.EnableHighEntropy = 1;
            aslrPolicy.DisallowStrippedImages = 1;

            if (
                SetProcessMitigationPolicy(
                    ProcessASLRPolicy,
                    &aslrPolicy,
                    sizeof(aslrPolicy)
                )
            ) {
                any = true;
                reasons.push_back("Hardened ASLR policy enabled");
            }

            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicPolicy{};
            dynamicPolicy.ProhibitDynamicCode = 1;

            if (
                SetProcessMitigationPolicy(
                    ProcessDynamicCodePolicy,
                    &dynamicPolicy,
                    sizeof(dynamicPolicy)
                )
            ) {
                any = true;
                reasons.push_back(
                    "Dynamic code generation prohibited"
                );
            }

            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
                signaturePolicy{};
            signaturePolicy.MicrosoftSignedOnly = 0;
            signaturePolicy.StoreSignedOnly = 0;
            signaturePolicy.MitigationOptIn = 1;

            if (
                SetProcessMitigationPolicy(
                    ProcessSignaturePolicy,
                    &signaturePolicy,
                    sizeof(signaturePolicy)
                )
            ) {
                any = true;
                reasons.push_back(
                    "Signature mitigation opt-in enabled"
                );
            }

            PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicy{};
            imageLoadPolicy.NoRemoteImages = 1;
            imageLoadPolicy.NoLowMandatoryLabelImages = 1;

            if (
                SetProcessMitigationPolicy(
                    ProcessImageLoadPolicy,
                    &imageLoadPolicy,
                    sizeof(imageLoadPolicy)
                )
            ) {
                any = true;
                reasons.push_back(
                    "Remote/low-label image loads blocked"
                );
            }

            return any;
        }

        static bool BlockRemoteDebuggerAttach(
            std::vector<std::string>& reasons
        ) {
            auto* ntSet =
                reinterpret_cast<NtSetInformationProcessFn>(
                    GetProcAddress(
                        GetModuleHandleW(L"ntdll.dll"),
                        "NtSetInformationProcess"
                    )
                );

            if (ntSet == nullptr) {
                return false;
            }

            /*
             * ProcessBreakOnTermination = 29 är för aggressivt.
             * ProcessDebugFlags = 31 med NoDebugInherit=1 hjälper.
             */
            ULONG noDebugInherit = 1;
            constexpr ULONG ProcessDebugFlags = 31;

            const NTSTATUS status = ntSet(
                GetCurrentProcess(),
                ProcessDebugFlags,
                &noDebugInherit,
                sizeof(noDebugInherit)
            );

            if (NT_SUCCESS(status)) {
                reasons.push_back(
                    "ProcessDebugFlags set to discourage attach"
                );
                return true;
            }

            return false;
        }

    public:
        static void Pulse() {
            heartbeat_.fetch_add(1, std::memory_order_relaxed);
        }

        static void StartWatchdog(
            std::chrono::milliseconds timeout =
                std::chrono::seconds(20)
        ) {
            if (watchdogRunning_.exchange(true)) {
                return;
            }

            watchdogThread_ = std::thread([timeout]() {
                std::uint64_t lastSeen =
                    heartbeat_.load(std::memory_order_relaxed);

                while (watchdogRunning_.load()) {
                    std::this_thread::sleep_for(
                        std::chrono::seconds(5)
                    );

                    const std::uint64_t current =
                        heartbeat_.load(std::memory_order_relaxed);

                    if (current == lastSeen) {
                        SecurityAlertSystem::DispatchAlert(
                            ThreatLevel::CRITICAL,
                            "SELF",
                            "Watchdog detected stalled security core heartbeat"
                        );
                    }

                    lastSeen = current;
                }
            });
        }

        static void StopWatchdog() {
            if (!watchdogRunning_.exchange(false)) {
                return;
            }

            if (watchdogThread_.joinable()) {
                watchdogThread_.join();
            }
        }

        static SelfProtectReport Initialize() {
            SelfProtectReport report{};

            report.mitigationsApplied =
                ApplyMitigationPolicies(report.reasons);

            BlockRemoteDebuggerAttach(report.reasons);

            const std::string selfPath =
                WideToUtf8(GetSelfPathWide());

            if (!selfPath.empty()) {
                const FileIntegrityInfo integrity =
                    IntegrityChecker::InspectFile(selfPath, false);

                expectedSelfHash_ = integrity.sha256;

                if (expectedSelfHash_.empty()) {
                    report.selfIntegrityOk = false;
                    report.riskScore += 20;
                    report.reasons.push_back(
                        "Could not hash security core image"
                    );
                } else {
                    report.reasons.push_back(
                        "Self image hash captured for integrity monitoring"
                    );
                }
            }

            if (IsDebuggerPresent()) {
                report.debuggerDetected = true;
                report.riskScore += 50;
                report.reasons.push_back(
                    "Debugger present on security core at startup"
                );
            }

            StartWatchdog();
            Pulse();

            return report;
        }

        static SelfProtectReport Inspect(
            const std::unordered_set<std::string>&
                trustedProcesses = {},
            int handleRiskWeight = 45
        ) {
            SelfProtectReport report{};
            Pulse();

            if (IsDebuggerPresent()) {
                report.debuggerDetected = true;
                report.riskScore += 50;
                report.reasons.push_back(
                    "Debugger attached to security core"
                );
            }

            const std::string selfPath =
                WideToUtf8(GetSelfPathWide());

            if (
                !selfPath.empty() &&
                !expectedSelfHash_.empty()
            ) {
                const FileIntegrityInfo integrity =
                    IntegrityChecker::InspectFile(selfPath, true);

                if (
                    integrity.sha256.empty() ||
                    integrity.sha256 != expectedSelfHash_
                ) {
                    report.selfIntegrityOk = false;
                    report.riskScore += 80;
                    report.reasons.push_back(
                        "Security core image hash changed on disk"
                    );
                }
            }

            const HandleScanResult handles =
                HandleScanner::ScanExternalHandles(
                    GetCurrentProcessId(),
                    trustedProcesses,
                    handleRiskWeight
                );

            if (handles.Success()) {
                report.externalHandlesToSelf =
                    handles.handles.size();

                for (const ExternalHandleInfo& handle :
                     handles.handles) {
                    if (!handle.dangerousAccess) {
                        continue;
                    }

                    report.riskScore += handle.riskScore;

                    std::ostringstream accessHex;
                    accessHex << std::hex << handle.grantedAccess;

                    report.reasons.push_back(
                        "External handle to security core from " +
                        handle.ownerProcessName +
                        " access=0x" + accessHex.str()
                    );
                }
            }

            return report;
        }
    };

} // namespace Mjolnir
