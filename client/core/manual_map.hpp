#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace Mjolnir {

    struct ManualMapFinding {
        std::uintptr_t baseAddress = 0;
        std::size_t regionSize = 0;
        std::uint16_t machine = 0;
        bool hasPeHeader = false;
        bool executable = false;
        bool privateMemory = true;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct ManualMapScanResult {
        std::vector<ManualMapFinding> findings;
        std::size_t regionsScanned = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class ManualMapDetector {
    private:
        static bool IsExecutable(DWORD protect) {
            const DWORD base = protect & 0xFF;

            return
                base == PAGE_EXECUTE ||
                base == PAGE_EXECUTE_READ ||
                base == PAGE_EXECUTE_READWRITE ||
                base == PAGE_EXECUTE_WRITECOPY;
        }

    public:
        /*
         * Letar efter MZ/PE-headers i privata executable
         * regioner — typiskt tecken på manuell mapping.
         */
        static ManualMapScanResult ScanPrivateImages(
            HANDLE processHandle,
            int baseRiskWeight = 55
        ) {
            ManualMapScanResult result{};

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

                const bool candidate =
                    information.State == MEM_COMMIT &&
                    information.Type == MEM_PRIVATE &&
                    information.RegionSize >= 0x1000 &&
                    IsExecutable(information.Protect);

                if (candidate) {
                    IMAGE_DOS_HEADER dosHeader{};
                    SIZE_T bytesRead = 0;

                    if (
                        ReadProcessMemory(
                            processHandle,
                            information.BaseAddress,
                            &dosHeader,
                            sizeof(dosHeader),
                            &bytesRead
                        ) &&
                        bytesRead == sizeof(dosHeader) &&
                        dosHeader.e_magic == IMAGE_DOS_SIGNATURE &&
                        dosHeader.e_lfanew > 0 &&
                        dosHeader.e_lfanew < 0x1000
                    ) {
                        IMAGE_NT_HEADERS64 ntHeaders{};
                        const std::uintptr_t ntAddress =
                            reinterpret_cast<std::uintptr_t>(
                                information.BaseAddress
                            ) +
                            static_cast<std::uintptr_t>(
                                dosHeader.e_lfanew
                            );

                        if (
                            ReadProcessMemory(
                                processHandle,
                                reinterpret_cast<LPCVOID>(
                                    ntAddress
                                ),
                                &ntHeaders,
                                sizeof(ntHeaders),
                                &bytesRead
                            ) &&
                            bytesRead >= sizeof(DWORD) +
                                sizeof(IMAGE_FILE_HEADER) &&
                            ntHeaders.Signature ==
                                IMAGE_NT_SIGNATURE
                        ) {
                            ManualMapFinding finding{};
                            finding.baseAddress =
                                reinterpret_cast<std::uintptr_t>(
                                    information.BaseAddress
                                );
                            finding.regionSize =
                                static_cast<std::size_t>(
                                    information.RegionSize
                                );
                            finding.machine =
                                ntHeaders.FileHeader.Machine;
                            finding.hasPeHeader = true;
                            finding.executable = true;
                            finding.riskScore = baseRiskWeight;
                            finding.reasons.push_back(
                                "Private executable region contains a PE image"
                            );

                            if (
                                (information.Protect & 0xFF) ==
                                PAGE_EXECUTE_READWRITE
                            ) {
                                finding.riskScore += 15;
                                finding.reasons.push_back(
                                    "Mapped image is RWX"
                                );
                            }

                            result.findings.push_back(
                                std::move(finding)
                            );
                        }
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

            result.errorCode = ERROR_SUCCESS;
            return result;
        }
    };

} // namespace Mjolnir
