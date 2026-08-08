#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace Mjolnir {

    struct PortFinding {
        std::uint16_t port = 0;
        DWORD owningPid = 0;
        std::string protocol;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct PortScanResult {
        std::vector<PortFinding> findings;
        std::size_t entriesInspected = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    /*
     * Letar efter lyssnande TCP-portar som ofta används av
     * cheat engines / remote tools.
     */
    class PortScanner {
    private:
        static bool IsSuspiciousPort(std::uint16_t port) {
            static const std::unordered_set<std::uint16_t> ports = {
                1234,
                1337,
                2020,
                31337,
                4444,
                5555,
                6666,
                7777,
                8888,
                9999,
                16000,
                17000,
                18000,
                19000,
                32100,
                54321,
            };
            return ports.find(port) != ports.end();
        }

    public:
        static PortScanResult ScanListeningPorts(int baseWeight = 35) {
            PortScanResult result{};

            ULONG size = 0;
            DWORD status = GetExtendedTcpTable(
                nullptr,
                &size,
                FALSE,
                AF_INET,
                TCP_TABLE_OWNER_PID_LISTENER,
                0
            );

            if (status != ERROR_INSUFFICIENT_BUFFER || size == 0) {
                result.errorCode = status == 0 ? ERROR_INVALID_DATA : status;
                if (result.errorCode == ERROR_INSUFFICIENT_BUFFER) {
                    result.errorCode = ERROR_SUCCESS;
                }
                return result;
            }

            std::vector<std::uint8_t> buffer(size);
            status = GetExtendedTcpTable(
                buffer.data(),
                &size,
                FALSE,
                AF_INET,
                TCP_TABLE_OWNER_PID_LISTENER,
                0
            );

            if (status != NO_ERROR) {
                result.errorCode = status;
                return result;
            }

            const auto* table =
                reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());

            for (DWORD index = 0; index < table->dwNumEntries; ++index) {
                ++result.entriesInspected;
                const auto& row = table->table[index];
                const auto port = static_cast<std::uint16_t>(
                    ntohs(static_cast<u_short>(row.dwLocalPort))
                );

                if (!IsSuspiciousPort(port)) {
                    continue;
                }

                if (
                    row.dwOwningPid == 0 ||
                    row.dwOwningPid == GetCurrentProcessId()
                ) {
                    continue;
                }

                PortFinding finding{};
                finding.port = port;
                finding.owningPid = row.dwOwningPid;
                finding.protocol = "tcp";
                finding.riskScore = baseWeight;
                finding.reasons.push_back(
                    "Listening TCP port matches common cheat/remote-tool range"
                );
                result.findings.push_back(std::move(finding));
            }

            return result;
        }
    };

} // namespace Mjolnir
