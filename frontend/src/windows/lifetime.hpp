#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "handles.hpp"
#include "regions.hpp"

#include <windows.h>

#include <cstdint>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Mjolnir {

    struct LifetimeFinding {
        std::string kind;
        std::string details;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct LifetimeScanResult {
        std::vector<LifetimeFinding> findings;
    };

    class LifetimeTracker {
    private:
        struct RegionState {
            std::uintptr_t base = 0;
            std::size_t size = 0;
            DWORD protect = 0;
            bool executable = false;
            bool writable = false;
            bool privateMemory = false;
            std::uint64_t firstSeenCycle = 0;
            std::uint64_t lastSeenCycle = 0;
            bool seenWritable = false;
            bool becameExecutableAfterWrite = false;
        };

        struct HandleState {
            DWORD ownerPid = 0;
            ACCESS_MASK access = 0;
            std::string ownerName;
            bool dangerous = false;
            std::uint64_t firstSeenCycle = 0;
            std::uint64_t lastSeenCycle = 0;
        };

        std::unordered_map<std::uintptr_t, RegionState> regions_;
        std::unordered_map<std::uint64_t, HandleState> handles_;
        DWORD trackedPid_ = 0;

        static std::uint64_t MakeHandleKey(
            DWORD ownerPid,
            ACCESS_MASK access
        ) {
            return (static_cast<std::uint64_t>(ownerPid) << 32) |
                   static_cast<std::uint64_t>(access);
        }

    public:
        void Reset() {
            regions_.clear();
            handles_.clear();
            trackedPid_ = 0;
        }

        void BindProcess(DWORD pid) {
            if (trackedPid_ != pid) {
                Reset();
                trackedPid_ = pid;
            }
        }

        LifetimeScanResult ObserveRegions(
            HANDLE processHandle,
            std::uint64_t cycle,
            int birthWeight = 45,
            int escalateWeight = 55
        ) {
            LifetimeScanResult result{};

            if (
                processHandle == nullptr ||
                processHandle == INVALID_HANDLE_VALUE
            ) {
                return result;
            }

            const MemoryRegionScanResult scan =
                MemoryRegionScanner::ScanSuspiciousRegions(
                    processHandle,
                    4096
                );

            if (!scan.Success()) {
                return result;
            }

            std::unordered_map<std::uintptr_t, RegionState> current;

            for (const MemoryRegionInfo& region : scan.suspiciousRegions) {
                RegionState state{};
                state.base = region.baseAddress;
                state.size = region.regionSize;
                state.protect = region.protect;
                state.executable = region.executable;
                state.writable = region.writable;
                state.privateMemory = region.privateMemory;
                state.firstSeenCycle = cycle;
                state.lastSeenCycle = cycle;
                state.seenWritable = region.writable;

                const auto previous = regions_.find(region.baseAddress);

                if (previous == regions_.end()) {
                    LifetimeFinding finding{};
                    finding.kind = "region_birth";
                    finding.riskScore = birthWeight;

                    std::ostringstream details;
                    details
                        << "Base=0x" << std::hex << region.baseAddress
                        << std::dec
                        << " Size=" << region.regionSize
                        << " Protect=0x" << std::hex << region.protect
                        << std::dec;

                    finding.details = details.str();
                    finding.reasons.push_back(
                        "Suspicious private executable region appeared mid-session"
                    );

                    if (region.writable && region.executable) {
                        finding.riskScore += 15;
                        finding.reasons.push_back("Region is RWX at birth");
                    }

                    result.findings.push_back(std::move(finding));
                } else {
                    state.firstSeenCycle = previous->second.firstSeenCycle;
                    state.seenWritable =
                        previous->second.seenWritable || region.writable;

                    if (
                        previous->second.seenWritable &&
                        region.executable &&
                        !previous->second.executable
                    ) {
                        state.becameExecutableAfterWrite = true;

                        LifetimeFinding finding{};
                        finding.kind = "region_escalate";
                        finding.riskScore = escalateWeight;

                        std::ostringstream details;
                        details
                            << "Base=0x" << std::hex
                            << region.baseAddress << std::dec
                            << " Size=" << region.regionSize;

                        finding.details = details.str();
                        finding.reasons.push_back(
                            "Region became executable after being writable (W->X pattern)"
                        );
                        result.findings.push_back(std::move(finding));
                    } else {
                        state.becameExecutableAfterWrite =
                            previous->second.becameExecutableAfterWrite;
                    }
                }

                current.emplace(region.baseAddress, state);
            }

            regions_ = std::move(current);
            return result;
        }

        LifetimeScanResult ObserveHandles(
            DWORD targetPid,
            const std::unordered_set<std::string>& trustedProcesses,
            std::uint64_t cycle,
            int birthWeight = 40,
            int dangerousWeight = 55
        ) {
            LifetimeScanResult result{};

            const HandleScanResult scan =
                HandleScanner::ScanExternalHandles(
                    targetPid,
                    trustedProcesses,
                    dangerousWeight
                );

            if (!scan.Success()) {
                return result;
            }

            std::unordered_map<std::uint64_t, HandleState> current;

            for (const ExternalHandleInfo& handle : scan.handles) {
                const std::uint64_t key = MakeHandleKey(
                    handle.ownerProcessId,
                    handle.grantedAccess
                );

                HandleState state{};
                state.ownerPid = handle.ownerProcessId;
                state.access = handle.grantedAccess;
                state.ownerName = handle.ownerProcessName;
                state.dangerous = handle.dangerousAccess;
                state.firstSeenCycle = cycle;
                state.lastSeenCycle = cycle;

                const auto previous = handles_.find(key);

                if (previous == handles_.end()) {
                    LifetimeFinding finding{};
                    finding.kind = "handle_birth";
                    finding.riskScore =
                        handle.dangerousAccess
                            ? dangerousWeight
                            : birthWeight;

                    std::ostringstream details;
                    details
                        << "Owner='" << handle.ownerProcessName
                        << "' PID=" << handle.ownerProcessId
                        << " Access=0x" << std::hex
                        << handle.grantedAccess << std::dec;

                    finding.details = details.str();
                    finding.reasons.push_back(
                        "New external handle to target appeared mid-session"
                    );

                    if (handle.dangerousAccess) {
                        finding.reasons.push_back(
                            "Handle grants dangerous process access"
                        );
                    }

                    result.findings.push_back(std::move(finding));
                } else {
                    state.firstSeenCycle = previous->second.firstSeenCycle;
                }

                current.emplace(key, state);
            }

            handles_ = std::move(current);
            return result;
        }
    };

} // namespace Mjolnir
