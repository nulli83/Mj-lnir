#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace Mjolnir {

    struct MemoryRegionInfo {
        std::uintptr_t baseAddress = 0;
        std::size_t regionSize = 0;

        DWORD state = 0;
        DWORD protect = 0;
        DWORD type = 0;

        bool executable = false;
        bool writable = false;
        bool privateMemory = false;

        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct MemoryRegionScanResult {
        std::vector<MemoryRegionInfo> suspiciousRegions;
        std::size_t regionsScanned = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class MemoryRegionScanner {
    private:
        static bool IsExecutable(DWORD protect) {
            const DWORD base = protect & 0xFF;

            return
                base == PAGE_EXECUTE ||
                base == PAGE_EXECUTE_READ ||
                base == PAGE_EXECUTE_READWRITE ||
                base == PAGE_EXECUTE_WRITECOPY;
        }

        static bool IsWritable(DWORD protect) {
            const DWORD base = protect & 0xFF;

            return
                base == PAGE_READWRITE ||
                base == PAGE_WRITECOPY ||
                base == PAGE_EXECUTE_READWRITE ||
                base == PAGE_EXECUTE_WRITECOPY;
        }

        static std::string ProtectToString(DWORD protect) {
            const DWORD base = protect & 0xFF;

            switch (base) {
                case PAGE_NOACCESS:
                    return "NOACCESS";
                case PAGE_READONLY:
                    return "READONLY";
                case PAGE_READWRITE:
                    return "READWRITE";
                case PAGE_WRITECOPY:
                    return "WRITECOPY";
                case PAGE_EXECUTE:
                    return "EXECUTE";
                case PAGE_EXECUTE_READ:
                    return "EXECUTE_READ";
                case PAGE_EXECUTE_READWRITE:
                    return "EXECUTE_READWRITE";
                case PAGE_EXECUTE_WRITECOPY:
                    return "EXECUTE_WRITECOPY";
                default:
                    return "UNKNOWN";
            }
        }

    public:
        /*
         * Letar efter privata RWX/W+X-regioner som ofta
         * används för manuell mapping och shellcode.
         */
        static MemoryRegionScanResult ScanSuspiciousRegions(
            HANDLE processHandle,
            std::size_t minimumRegionSize = 4096
        ) {
            MemoryRegionScanResult result{};

            if (
                processHandle == nullptr ||
                processHandle == INVALID_HANDLE_VALUE
            ) {
                result.errorCode = ERROR_INVALID_PARAMETER;
                return result;
            }

            SYSTEM_INFO systemInfo{};
            GetSystemInfo(&systemInfo);

            std::uintptr_t address =
                reinterpret_cast<std::uintptr_t>(
                    systemInfo.lpMinimumApplicationAddress
                );

            const std::uintptr_t maximum =
                reinterpret_cast<std::uintptr_t>(
                    systemInfo.lpMaximumApplicationAddress
                );

            while (address < maximum) {
                MEMORY_BASIC_INFORMATION information{};

                const SIZE_T queried = VirtualQueryEx(
                    processHandle,
                    reinterpret_cast<LPCVOID>(address),
                    &information,
                    sizeof(information)
                );

                if (queried == 0) {
                    break;
                }

                ++result.regionsScanned;

                if (
                    information.State == MEM_COMMIT &&
                    information.RegionSize >= minimumRegionSize
                ) {
                    MemoryRegionInfo region{};
                    region.baseAddress =
                        reinterpret_cast<std::uintptr_t>(
                            information.BaseAddress
                        );
                    region.regionSize =
                        static_cast<std::size_t>(
                            information.RegionSize
                        );
                    region.state = information.State;
                    region.protect = information.Protect;
                    region.type = information.Type;
                    region.executable =
                        IsExecutable(information.Protect);
                    region.writable =
                        IsWritable(information.Protect);
                    region.privateMemory =
                        information.Type == MEM_PRIVATE;

                    if (
                        region.executable &&
                        region.writable
                    ) {
                        region.riskScore += 45;
                        region.reasons.push_back(
                            "Region is both writable and executable (" +
                            ProtectToString(
                                information.Protect
                            ) +
                            ")"
                        );
                    }

                    if (
                        region.executable &&
                        region.privateMemory &&
                        region.writable
                    ) {
                        region.riskScore += 20;
                        region.reasons.push_back(
                            "Private RWX memory is a common manual-map / shellcode pattern"
                        );
                    }

                    if (
                        region.executable &&
                        region.privateMemory &&
                        region.regionSize >=
                            1024 * 1024
                    ) {
                        region.riskScore += 10;
                        region.reasons.push_back(
                            "Large private executable region"
                        );
                    }

                    if (region.riskScore >= 40) {
                        result.suspiciousRegions.push_back(
                            std::move(region)
                        );
                    }
                }

                const std::uintptr_t next =
                    reinterpret_cast<std::uintptr_t>(
                        information.BaseAddress
                    ) +
                    static_cast<std::uintptr_t>(
                        information.RegionSize
                    );

                if (next <= address) {
                    break;
                }

                address = next;
            }

            return result;
        }

        static std::string FormatRegion(
            const MemoryRegionInfo& region
        ) {
            std::ostringstream stream;

            stream
                << "Base=0x" << std::hex
                << region.baseAddress << std::dec
                << " Size=" << region.regionSize
                << " Protect="
                << ProtectToString(region.protect)
                << " Private="
                << (region.privateMemory ? "yes" : "no");

            return stream.str();
        }
    };

} // namespace Mjolnir
