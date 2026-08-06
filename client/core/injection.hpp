#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "threads.hpp"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Mjolnir {

    struct InjectionFinding {
        std::string moduleName;
        std::string modulePath;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct InjectionScanResult {
        std::vector<InjectionFinding> findings;
    };

    class InjectionAnalyzer {
    private:
        static std::string ToLower(std::string value) {
            for (char& character : value) {
                character = static_cast<char>(
                    std::tolower(
                        static_cast<unsigned char>(character)
                    )
                );
            }

            return value;
        }

        static bool Contains(
            const std::string& value,
            const char* needle
        ) {
            return value.find(needle) != std::string::npos;
        }

        static bool IsSuspiciousPath(const std::string& path) {
            const std::string lowered = ToLower(path);

            return
                Contains(lowered, "\\appdata\\local\\temp\\") ||
                Contains(lowered, "\\windows\\temp\\") ||
                Contains(lowered, "\\downloads\\") ||
                Contains(lowered, "\\public\\downloads\\") ||
                Contains(lowered, "\\recycle.bin\\");
        }

        static bool LooksLikeRandomName(const std::string& name) {
            const std::string lowered = ToLower(name);

            if (lowered.size() < 8) {
                return false;
            }

            /*
             * Enkla heuristik: massa hex-tecken / få vokaler.
             */
            std::size_t hexChars = 0;
            std::size_t letters = 0;

            for (char character : lowered) {
                if (
                    (character >= '0' && character <= '9') ||
                    (character >= 'a' && character <= 'f')
                ) {
                    ++hexChars;
                }

                if (character >= 'a' && character <= 'z') {
                    ++letters;
                }
            }

            if (letters == 0) {
                return false;
            }

            return (
                       hexChars * 100 / lowered.size() >= 70
                   ) ||
                   (
                       lowered.find(".dll") != std::string::npos &&
                       lowered.size() >= 16 &&
                       hexChars >= 10
                   );
        }

    public:
        static InjectionScanResult AnalyzeNewModules(
            DWORD targetPid,
            const std::vector<std::pair<std::string, std::string>>&
                newModules,
            const std::unordered_set<std::string>&
                whitelistedModules,
            int baseWeight = 50
        ) {
            InjectionScanResult result{};

            if (newModules.empty() || targetPid == 0) {
                return result;
            }

            const ThreadScanResult threads =
                ThreadScanner::ScanSuspiciousThreads(
                    targetPid,
                    30
                );

            const bool hasOutOfModuleThread =
                threads.Success() && !threads.threads.empty();

            for (const auto& module : newModules) {
                const std::string name = ToLower(module.first);
                const std::string path = module.second;

                if (
                    whitelistedModules.find(name) !=
                    whitelistedModules.end()
                ) {
                    continue;
                }

                InjectionFinding finding{};
                finding.moduleName = name;
                finding.modulePath = path;
                finding.riskScore = baseWeight;
                finding.reasons.push_back(
                    "Module appeared after baseline and is not whitelisted"
                );

                if (IsSuspiciousPath(path)) {
                    finding.riskScore += 25;
                    finding.reasons.push_back(
                        "Module loaded from a suspicious directory"
                    );
                }

                if (LooksLikeRandomName(name)) {
                    finding.riskScore += 15;
                    finding.reasons.push_back(
                        "Module name looks randomly generated"
                    );
                }

                if (path.empty()) {
                    finding.riskScore += 20;
                    finding.reasons.push_back(
                        "Module path could not be resolved"
                    );
                }

                /*
                 * Thread correlation only when the module itself already
                 * looks suspicious — avoids boosting every birth on one
                 * unrelated out-of-module thread.
                 */
                const bool moduleLooksSuspicious =
                    IsSuspiciousPath(path) ||
                    path.empty() ||
                    LooksLikeRandomName(name);

                if (hasOutOfModuleThread && moduleLooksSuspicious) {
                    finding.riskScore += 20;
                    finding.reasons.push_back(
                        "Suspicious module birth correlated with out-of-module threads"
                    );

                    if (IsSuspiciousPath(path)) {
                        finding.riskScore += 15;
                        finding.reasons.push_back(
                            "Temp-path module + out-of-module thread correlation"
                        );
                    }
                }

                result.findings.push_back(std::move(finding));
            }

            return result;
        }
    };

} // namespace Mjolnir
