#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
#include <string>
#include <utility>
#include <vector>

namespace Mjolnir {

    struct EvidenceSample {
        std::chrono::steady_clock::time_point at{};
        int highestRisk = 0;
        std::size_t findings = 0;
        std::size_t emittedAlerts = 0;
    };

    struct EvidenceDecision {
        bool shouldEnforce = false;
        int peakRisk = 0;
        int averageRisk = 0;
        std::size_t samples = 0;
        std::size_t sustainedHighSamples = 0;
        std::string reason;
    };

    struct EvidenceSettings {
        std::uint32_t windowMs = 45000;
        std::uint32_t minSamples = 3;
        int minAverageRisk = 55;
        int minPeakRisk = 80;
        int sustainedHighRisk = 50;
        std::uint32_t minSustainedHighSamples = 3;
        std::uint32_t settleCyclesAfterAttach = 5;
    };

    class EvidenceWindow {
    private:
        std::deque<EvidenceSample> samples_;
        DWORD boundPid_ = 0;
        std::uint64_t cyclesOnTarget_ = 0;
        EvidenceSettings settings_{};

        void Prune(std::chrono::steady_clock::time_point now) {
            const auto window = std::chrono::milliseconds(
                settings_.windowMs
            );

            while (
                !samples_.empty() &&
                now - samples_.front().at > window
            ) {
                samples_.pop_front();
            }
        }

    public:
        void Configure(EvidenceSettings settings) {
            settings_ = std::move(settings);
        }

        const EvidenceSettings& Settings() const {
            return settings_;
        }

        void Reset() {
            samples_.clear();
            boundPid_ = 0;
            cyclesOnTarget_ = 0;
        }

        void BindTarget(DWORD pid) {
            if (boundPid_ != pid) {
                Reset();
                boundPid_ = pid;
            }
        }

        void Push(
            DWORD pid,
            int highestRisk,
            std::size_t findings,
            std::size_t emittedAlerts
        ) {
            BindTarget(pid);

            ++cyclesOnTarget_;

            EvidenceSample sample{};
            sample.at = std::chrono::steady_clock::now();
            sample.highestRisk = std::max(0, highestRisk);
            sample.findings = findings;
            sample.emittedAlerts = emittedAlerts;

            samples_.push_back(sample);
            Prune(sample.at);
        }

        EvidenceDecision Evaluate() {
            EvidenceDecision decision{};
            const auto now = std::chrono::steady_clock::now();
            Prune(now);

            decision.samples = samples_.size();

            if (samples_.empty()) {
                decision.reason = "No evidence samples yet";
                return decision;
            }

            if (
                cyclesOnTarget_ <
                settings_.settleCyclesAfterAttach
            ) {
                decision.reason =
                    "Still in post-attach settle window";
                return decision;
            }

            std::int64_t riskSum = 0;
            std::size_t sustained = 0;

            for (const EvidenceSample& sample : samples_) {
                riskSum += sample.highestRisk;
                decision.peakRisk = std::max(
                    decision.peakRisk,
                    sample.highestRisk
                );

                if (
                    sample.highestRisk >=
                    settings_.sustainedHighRisk
                ) {
                    ++sustained;
                }
            }

            decision.averageRisk = static_cast<int>(
                riskSum / static_cast<std::int64_t>(samples_.size())
            );
            decision.sustainedHighSamples = sustained;

            const bool enoughSamples =
                samples_.size() >= settings_.minSamples;

            const bool peakHit =
                decision.peakRisk >= settings_.minPeakRisk;

            const bool averageHit =
                decision.averageRisk >= settings_.minAverageRisk;

            const bool sustainedHit =
                sustained >= settings_.minSustainedHighSamples;

            /*
             * Enforce kräver:
             * - settle klar
             * - tillräckligt många samples i fönstret
             * - peak över tröskel
             * - antingen hög snitt-risk ELLER ihållande high samples
             */
            decision.shouldEnforce =
                enoughSamples &&
                peakHit &&
                (averageHit || sustainedHit);

            if (decision.shouldEnforce) {
                decision.reason =
                    "Sustained evidence: peak=" +
                    std::to_string(decision.peakRisk) +
                    " avg=" +
                    std::to_string(decision.averageRisk) +
                    " sustainedHigh=" +
                    std::to_string(sustained) +
                    "/" +
                    std::to_string(samples_.size());
            } else {
                decision.reason =
                    "Evidence insufficient: peak=" +
                    std::to_string(decision.peakRisk) +
                    " avg=" +
                    std::to_string(decision.averageRisk) +
                    " samples=" +
                    std::to_string(samples_.size());
            }

            return decision;
        }
    };

} // namespace Mjolnir
