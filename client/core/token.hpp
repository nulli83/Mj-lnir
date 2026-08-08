#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace Mjolnir {

    struct TokenFinding {
        int riskScore = 0;
        std::vector<std::string> reasons;
        std::string integrityLevel;
        bool elevated = false;
        bool impersonation = false;
    };

    struct TokenScanResult {
        std::vector<TokenFinding> findings;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    /*
     * Inspekterar målprocessens token för oväntad elevation,
     * låg/high integrity-avvikelser och impersonation.
     */
    class TokenScanner {
    private:
        static std::string IntegrityName(DWORD rid) {
            switch (rid) {
                case SECURITY_MANDATORY_UNTRUSTED_RID:
                    return "Untrusted";
                case SECURITY_MANDATORY_LOW_RID:
                    return "Low";
                case SECURITY_MANDATORY_MEDIUM_RID:
                    return "Medium";
                case SECURITY_MANDATORY_MEDIUM_PLUS_RID:
                    return "MediumPlus";
                case SECURITY_MANDATORY_HIGH_RID:
                    return "High";
                case SECURITY_MANDATORY_SYSTEM_RID:
                    return "System";
                default:
                    return "Unknown";
            }
        }

    public:
        static TokenScanResult Scan(
            HANDLE process,
            int baseWeight = 40
        ) {
            TokenScanResult result{};

            if (process == nullptr) {
                result.errorCode = ERROR_INVALID_HANDLE;
                return result;
            }

            HANDLE token = nullptr;
            if (
                !OpenProcessToken(
                    process,
                    TOKEN_QUERY,
                    &token
                )
            ) {
                result.errorCode = GetLastError();
                return result;
            }

            TokenFinding finding{};

            TOKEN_ELEVATION elevation{};
            DWORD returned = 0;
            if (
                GetTokenInformation(
                    token,
                    TokenElevation,
                    &elevation,
                    sizeof(elevation),
                    &returned
                )
            ) {
                finding.elevated = elevation.TokenIsElevated != 0;
                if (finding.elevated) {
                    finding.riskScore += baseWeight;
                    finding.reasons.push_back(
                        "Target process token is elevated (admin)"
                    );
                }
            }

            DWORD integrityBuffer[16] = {};
            if (
                GetTokenInformation(
                    token,
                    TokenIntegrityLevel,
                    integrityBuffer,
                    sizeof(integrityBuffer),
                    &returned
                )
            ) {
                auto* til =
                    reinterpret_cast<TOKEN_MANDATORY_LABEL*>(
                        integrityBuffer
                    );
                DWORD rid = *GetSidSubAuthority(
                    til->Label.Sid,
                    static_cast<DWORD>(
                        *GetSidSubAuthorityCount(til->Label.Sid) - 1
                    )
                );
                finding.integrityLevel = IntegrityName(rid);

                if (rid == SECURITY_MANDATORY_SYSTEM_RID) {
                    finding.riskScore += baseWeight + 15;
                    finding.reasons.push_back(
                        "Target runs at System integrity"
                    );
                } else if (rid == SECURITY_MANDATORY_HIGH_RID) {
                    finding.riskScore += baseWeight;
                    finding.reasons.push_back(
                        "Target runs at High integrity"
                    );
                } else if (rid <= SECURITY_MANDATORY_LOW_RID) {
                    finding.riskScore += baseWeight / 2;
                    finding.reasons.push_back(
                        "Target runs at unusually low integrity"
                    );
                }
            }

            TOKEN_STATISTICS stats{};
            if (
                GetTokenInformation(
                    token,
                    TokenStatistics,
                    &stats,
                    sizeof(stats),
                    &returned
                )
            ) {
                if (stats.TokenType == TokenImpersonation) {
                    finding.impersonation = true;
                    finding.riskScore += baseWeight + 10;
                    finding.reasons.push_back(
                        "Process primary token type is Impersonation"
                    );
                }
            }

            CloseHandle(token);

            if (!finding.reasons.empty()) {
                if (finding.riskScore < baseWeight / 2) {
                    finding.riskScore = baseWeight / 2;
                }
                result.findings.push_back(std::move(finding));
            }

            return result;
        }
    };

} // namespace Mjolnir
