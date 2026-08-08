#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cctype>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace Mjolnir {

    struct HostsFinding {
        std::string line;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct HostsScanResult {
        std::vector<HostsFinding> findings;
        std::size_t linesInspected = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    /*
     * Skannar hosts-filen efter omdirigeringar som ofta används
     * för att blockera anti-cheat/telemetri eller spoofa game CDN.
     */
    class HostsScanner {
    private:
        static std::string ToLower(std::string value) {
            for (char& character : value) {
                character = static_cast<char>(
                    std::tolower(static_cast<unsigned char>(character))
                );
            }
            return value;
        }

        static bool IsInterestingHost(const std::string& host) {
            static const char* needles[] = {
                "easyanticheat",
                "easyanti",
                "battleye",
                "vac.",
                "steamcommunity",
                "steampowered",
                "riotgames",
                "valorant",
                "epicgames",
                "xboxlive",
                "microsoft.com",
                "windowsupdate",
                "anticheat",
                "mjolnir",
                "faceit",
                "esea",
                "vanguard",
                "nprotect",
                "xigncode",
                "gameguard",
            };

            for (const char* needle : needles) {
                if (host.find(needle) != std::string::npos) {
                    return true;
                }
            }

            return false;
        }

        static bool IsLoopbackOrPrivate(const std::string& ip) {
            return ip == "0.0.0.0" ||
                   ip == "127.0.0.1" ||
                   ip.rfind("127.", 0) == 0 ||
                   ip.rfind("10.", 0) == 0 ||
                   ip.rfind("192.168.", 0) == 0 ||
                   ip.rfind("172.16.", 0) == 0 ||
                   ip.rfind("172.17.", 0) == 0 ||
                   ip.rfind("172.18.", 0) == 0 ||
                   ip.rfind("172.19.", 0) == 0 ||
                   ip.rfind("172.2", 0) == 0 ||
                   ip.rfind("172.3", 0) == 0;
        }

    public:
        static HostsScanResult Scan(int baseWeight = 45) {
            HostsScanResult result{};

            wchar_t windowsDir[MAX_PATH] = {};
            if (GetWindowsDirectoryW(windowsDir, MAX_PATH) == 0) {
                result.errorCode = GetLastError();
                return result;
            }

            std::wstring path = windowsDir;
            path += L"\\System32\\drivers\\etc\\hosts";

            std::ifstream stream(path);
            if (!stream) {
                result.errorCode = ERROR_FILE_NOT_FOUND;
                return result;
            }

            std::string line;
            while (std::getline(stream, line)) {
                ++result.linesInspected;

                std::string trimmed;
                trimmed.reserve(line.size());
                for (char character : line) {
                    if (character == '#') {
                        break;
                    }
                    trimmed.push_back(character);
                }

                while (
                    !trimmed.empty() &&
                    std::isspace(
                        static_cast<unsigned char>(trimmed.front())
                    )
                ) {
                    trimmed.erase(trimmed.begin());
                }

                if (trimmed.empty()) {
                    continue;
                }

                std::istringstream parser(trimmed);
                std::string ip;
                std::string host;
                if (!(parser >> ip >> host)) {
                    continue;
                }

                const std::string lowerHost = ToLower(host);
                if (!IsInterestingHost(lowerHost)) {
                    continue;
                }

                HostsFinding finding{};
                finding.line = ip + " " + host;
                finding.riskScore = baseWeight;
                if (IsLoopbackOrPrivate(ip)) {
                    finding.riskScore = baseWeight + 15;
                    finding.reasons.push_back(
                        "Interesting host redirected to loopback/private IP"
                    );
                } else {
                    finding.reasons.push_back(
                        "Interesting game/AC host overridden in hosts file"
                    );
                }
                result.findings.push_back(std::move(finding));
            }

            return result;
        }
    };

} // namespace Mjolnir
