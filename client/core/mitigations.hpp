#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <string>
#include <vector>

namespace Mjolnir {

    struct MitigationFinding {
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct MitigationScanResult {
        std::vector<MitigationFinding> findings;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    /*
     * Kontrollerar om moderna process-mitigations är avstängda
     * på ett sätt som ofta följer med injectors/cheat loaders.
     */
    class MitigationScanner {
    public:
        static MitigationScanResult Scan(
            HANDLE process,
            int baseWeight = 40
        ) {
            MitigationScanResult result{};

            if (process == nullptr) {
                result.errorCode = ERROR_INVALID_HANDLE;
                return result;
            }

            MitigationFinding finding{};

            PROCESS_MITIGATION_DEP_POLICY dep{};
            if (
                GetProcessMitigationPolicy(
                    process,
                    ProcessDEPPolicy,
                    &dep,
                    sizeof(dep)
                )
            ) {
                if (dep.Enable == 0) {
                    finding.riskScore += baseWeight;
                    finding.reasons.push_back("DEP is disabled for the target process");
                }
                if (dep.Permanent == 0 && dep.Enable != 0) {
                    finding.riskScore += 10;
                    finding.reasons.push_back("DEP is enabled but not permanent");
                }
            }

            PROCESS_MITIGATION_ASLR_POLICY aslr{};
            if (
                GetProcessMitigationPolicy(
                    process,
                    ProcessASLRPolicy,
                    &aslr,
                    sizeof(aslr)
                )
            ) {
                if (
                    aslr.EnableBottomUpRandomization == 0 &&
                    aslr.EnableForceRelocateImages == 0
                ) {
                    finding.riskScore += baseWeight / 2;
                    finding.reasons.push_back("ASLR mitigations appear disabled");
                }
            }

            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
            if (
                GetProcessMitigationPolicy(
                    process,
                    ProcessControlFlowGuardPolicy,
                    &cfg,
                    sizeof(cfg)
                )
            ) {
                if (cfg.EnableControlFlowGuard == 0) {
                    finding.riskScore += baseWeight / 2;
                    finding.reasons.push_back("Control Flow Guard is disabled");
                }
            }

            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dyn{};
            if (
                GetProcessMitigationPolicy(
                    process,
                    ProcessDynamicCodePolicy,
                    &dyn,
                    sizeof(dyn)
                )
            ) {
                /*
                 * Inte alltid på i spel — reporta endast om policy säger
                 * ProhibitDynamicCode=0 OCH AllowRemoteDowngrade=1.
                 */
                if (dyn.AllowRemoteDowngrade != 0) {
                    finding.riskScore += baseWeight;
                    finding.reasons.push_back(
                        "Dynamic code policy allows remote downgrade"
                    );
                }
            }

            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig{};
            if (
                GetProcessMitigationPolicy(
                    process,
                    ProcessSignaturePolicy,
                    &sig,
                    sizeof(sig)
                )
            ) {
                if (sig.MicrosoftSignedOnly == 0 && sig.StoreSignedOnly == 0) {
                    /*
                     * Normal for most games — low weight informational only
                     * when combined with other signals.
                     */
                }
            }

            if (!finding.reasons.empty()) {
                result.findings.push_back(std::move(finding));
            }

            return result;
        }
    };

} // namespace Mjolnir
