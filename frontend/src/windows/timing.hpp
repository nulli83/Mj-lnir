#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace Mjolnir {

    struct TimingFinding {
        bool anomalyDetected = false;
        double ratio = 1.0;
        std::int64_t qpcMicros = 0;
        std::int64_t tickMicros = 0;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    class TimingDetector {
    public:
        /*
         * Jämför QueryPerformanceCounter mot GetTickCount64
         * under en kort busy-wait. Stora avvikelser kan tyda
         * på single-stepping / instrumentation.
         */
        static TimingFinding InspectLocalProcess(
            int baseRiskWeight = 35
        ) {
            TimingFinding finding{};

            LARGE_INTEGER frequency{};
            LARGE_INTEGER startCounter{};
            LARGE_INTEGER endCounter{};

            if (
                !QueryPerformanceFrequency(&frequency) ||
                frequency.QuadPart <= 0 ||
                !QueryPerformanceCounter(&startCounter)
            ) {
                return finding;
            }

            const ULONGLONG startTick = GetTickCount64();

            /*
             * Kort CPU-bunden loop — undvik Sleep eftersom
             * schemaläggning annars dominerar mätningen.
             */
            volatile std::uint64_t sink = 0;

            for (int index = 0; index < 2500000; ++index) {
                sink += static_cast<std::uint64_t>(index);
            }

            if (!QueryPerformanceCounter(&endCounter)) {
                return finding;
            }

            const ULONGLONG endTick = GetTickCount64();

            const double qpcSeconds =
                static_cast<double>(
                    endCounter.QuadPart - startCounter.QuadPart
                ) /
                static_cast<double>(frequency.QuadPart);

            finding.qpcMicros = static_cast<std::int64_t>(
                qpcSeconds * 1000000.0
            );

            finding.tickMicros = static_cast<std::int64_t>(
                (endTick - startTick) * 1000ULL
            );

            if (finding.qpcMicros <= 0) {
                return finding;
            }

            /*
             * Om tick-klockan knappt rör sig medan QPC visar
             * lång tid, eller tvärtom, är något fiskigt.
             */
            if (finding.tickMicros > 0) {
                finding.ratio =
                    static_cast<double>(finding.qpcMicros) /
                    static_cast<double>(finding.tickMicros);
            } else if (finding.qpcMicros > 15000) {
                finding.anomalyDetected = true;
                finding.riskScore = baseRiskWeight;
                finding.reasons.push_back(
                    "GetTickCount64 stalled while QPC advanced"
                );
                return finding;
            }

            if (finding.ratio > 8.0 || finding.ratio < 0.125) {
                finding.anomalyDetected = true;
                finding.riskScore = baseRiskWeight;
                finding.reasons.push_back(
                    "Large divergence between QPC and tick count"
                );
            }

            /*
             * Extremt lång QPC-tid för en liten loop tyder på
             * att processen single-steppats.
             */
            if (finding.qpcMicros > 250000) {
                finding.anomalyDetected = true;
                finding.riskScore += baseRiskWeight / 2;
                finding.reasons.push_back(
                    "Busy-loop took abnormally long according to QPC"
                );
            }

            (void)sink;
            return finding;
        }
    };

} // namespace Mjolnir
