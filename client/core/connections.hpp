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

    struct ConnectionFinding {
        std::uint16_t remotePort = 0;
        std::uint16_t localPort = 0;
        DWORD owningPid = 0;
        std::string remoteAddress;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct ConnectionScanResult {
        std::vector<ConnectionFinding> findings;
        std::size_t entriesInspected = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    /*
     * Letar efter ESTABLISHED TCP-anslutningar till portar som
     * ofta används av cheat loaders / remote debug / C2.
     */
    class ConnectionScanner {
    private:
        static bool IsSuspiciousRemotePort(std::uint16_t port) {
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
                27015,
                32100,
                54321,
            };
            return ports.find(port) != ports.end();
        }

        static std::string FormatIpv4(DWORD addrNetworkOrder) {
            const std::uint8_t* bytes =
                reinterpret_cast<const std::uint8_t*>(&addrNetworkOrder);
            return std::to_string(bytes[0]) + "." +
                   std::to_string(bytes[1]) + "." +
                   std::to_string(bytes[2]) + "." +
                   std::to_string(bytes[3]);
        }

    public:
        static ConnectionScanResult ScanEstablished(
            DWORD focusPid = 0,
            int baseWeight = 40
        ) {
            ConnectionScanResult result{};

            ULONG size = 0;
            DWORD status = GetExtendedTcpTable(
                nullptr,
                &size,
                FALSE,
                AF_INET,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0
            );

            if (status != ERROR_INSUFFICIENT_BUFFER || size == 0) {
                result.errorCode =
                    status == 0 ? ERROR_INVALID_DATA : status;
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
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0
            );

            if (status != NO_ERROR) {
                result.errorCode = status;
                return result;
            }

            auto* table =
                reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());

            for (DWORD index = 0; index < table->dwNumEntries; ++index) {
                const auto& row = table->table[index];
                ++result.entriesInspected;

                if (row.dwState != MIB_TCP_STATE_ESTAB) {
                    continue;
                }

                if (focusPid != 0 && row.dwOwningPid != focusPid) {
                    continue;
                }

                const auto remotePort =
                    static_cast<std::uint16_t>(ntohs(
                        static_cast<u_short>(row.dwRemotePort)
                    ));
                const auto localPort =
                    static_cast<std::uint16_t>(ntohs(
                        static_cast<u_short>(row.dwLocalPort)
                    ));

                if (!IsSuspiciousRemotePort(remotePort)) {
                    continue;
                }

                /*
                 * Skip obvious localhost steam/local services noise when
                 * remote is loopback unless port is highly suspicious.
                 */
                const bool loopback =
                    (row.dwRemoteAddr & 0xFF) == 127;

                ConnectionFinding finding{};
                finding.remotePort = remotePort;
                finding.localPort = localPort;
                finding.owningPid = row.dwOwningPid;
                finding.remoteAddress = FormatIpv4(row.dwRemoteAddr);
                finding.riskScore = baseWeight;
                if (!loopback) {
                    finding.riskScore = baseWeight + 10;
                }
                finding.reasons.push_back(
                    "Established TCP to suspicious remote port " +
                    std::to_string(remotePort)
                );
                result.findings.push_back(std::move(finding));
            }

            return result;
        }
    };

} // namespace Mjolnir
