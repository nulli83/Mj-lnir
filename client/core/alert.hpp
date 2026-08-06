#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

namespace Mjolnir {

    enum class ThreatLevel : std::uint8_t {
        LOW = 0,
        MEDIUM = 1,
        HIGH = 2,
        CRITICAL = 3
    };

    struct SecurityAlert {
        ThreatLevel level = ThreatLevel::LOW;

        std::string category;
        std::string details;
        std::string timestampUtc;

        DWORD processId = 0;
        int riskScore = 0;

        std::uint64_t sequence = 0;
    };

    struct AlertSettings {
        std::filesystem::path logPath =
            "log/mjolnir.jsonl";

        bool consoleOutput = true;
        bool fileOutput = true;

        /*
         * true:
         * Varje loggrad skrivs som ett JSON-objekt.
         *
         * false:
         * Vanlig läsbar text används.
         */
        bool jsonLines = true;

        /*
         * Minsta alertnivå som ska loggas.
         */
        ThreatLevel minimumLevel =
            ThreatLevel::LOW;

        /*
         * Identiska alerts under denna period ignoreras.
         * Sätt till 0 för att stänga av cooldown.
         */
        std::uint32_t duplicateCooldownMs =
            30000;

        /*
         * Loggfilen roteras när denna storlek uppnås.
         * 0 stänger av storleksbaserad rotation.
         */
        std::uintmax_t maxLogSizeBytes =
            5ULL * 1024ULL * 1024ULL;

        /*
         * Antal äldre loggfiler att behålla:
         *
         * mjolnir.jsonl
         * mjolnir.jsonl.1
         * mjolnir.jsonl.2
         * mjolnir.jsonl.3
         */
        std::size_t retainedLogFiles = 3;
    };

    class SecurityAlertSystem {
    public:
        using AlertSink =
            std::function<void(const SecurityAlert&)>;

        static void Configure(
            AlertSettings settings
        ) {
            std::lock_guard<std::mutex> lock(
                mutex_
            );

            settings_ = std::move(settings);
        }

        /*
         * Använd denna för att koppla alerts till IPC-klienten.
         *
         * Callbacken körs efter att alerten har loggats och
         * utan att alert-systemets mutex hålls.
         */
        static void SetExternalSink(
            AlertSink sink
        ) {
            std::lock_guard<std::mutex> lock(
                mutex_
            );

            externalSink_ = std::move(sink);
        }

        static void ClearExternalSink() {
            std::lock_guard<std::mutex> lock(
                mutex_
            );

            externalSink_ = nullptr;
        }

        static const char* ThreatLevelToString(
            ThreatLevel level
        ) {
            switch (level) {
                case ThreatLevel::LOW:
                    return "INFO";

                case ThreatLevel::MEDIUM:
                    return "WARNING";

                case ThreatLevel::HIGH:
                    return "HIGH";

                case ThreatLevel::CRITICAL:
                    return "CRITICAL";

                default:
                    return "UNKNOWN";
            }
        }

        /*
         * Returnerar true om alerten skickades.
         *
         * Returnerar false om den filtrerades på grund av
         * minimumLevel eller duplicateCooldownMs.
         */
        static bool DispatchAlert(
            ThreatLevel level,
            const std::string& category,
            const std::string& details,
            DWORD processId = 0,
            int riskScore = 0
        ) {
            const auto now =
                std::chrono::steady_clock::now();

            SecurityAlert alert{};
            AlertSink sinkCopy;

            {
                std::lock_guard<std::mutex> lock(
                    mutex_
                );

                if (
                    static_cast<int>(level) <
                    static_cast<int>(
                        settings_.minimumLevel
                    )
                ) {
                    return false;
                }

                const std::string deduplicationKey =
                    BuildDeduplicationKey(
                        level,
                        category,
                        details,
                        processId
                    );

                if (
                    settings_.duplicateCooldownMs > 0 &&
                    WasRecentlyDispatched(
                        deduplicationKey,
                        now
                    )
                ) {
                    return false;
                }

                recentAlerts_[deduplicationKey] = now;

                PruneRecentAlerts(now);

                alert.level = level;
                alert.category = category;
                alert.details = details;
                alert.processId = processId;
                alert.riskScore = riskScore;
                alert.sequence = ++sequence_;
                alert.timestampUtc =
                    CreateUtcTimestamp();

                const std::string textLine =
                    BuildTextLine(alert);

                if (settings_.consoleOutput) {
                    WriteConsole(
                        alert.level,
                        textLine
                    );
                }

                if (settings_.fileOutput) {
                    const std::string fileLine =
                        settings_.jsonLines
                            ? BuildJsonLine(alert)
                            : textLine;

                    WriteFile(fileLine);
                }

                sinkCopy = externalSink_;
            }

            /*
             * IPC eller annan extern kod körs utanför låset.
             * Det förhindrar deadlocks om callbacken själv
             * behöver logga något.
             */
            if (sinkCopy) {
                try {
                    sinkCopy(alert);
                } catch (const std::exception& error) {
                    std::cerr
                        << "[Mjolnir AlertSink Error] "
                        << error.what()
                        << '\n';
                } catch (...) {
                    std::cerr
                        << "[Mjolnir AlertSink Error] "
                        << "Unknown callback exception."
                        << '\n';
                }
            }

            return true;
        }

    private:
        static std::string BuildDeduplicationKey(
            ThreatLevel level,
            const std::string& category,
            const std::string& details,
            DWORD processId
        ) {
            std::ostringstream key;

            key
                << static_cast<int>(level)
                << '|'
                << processId
                << '|'
                << category
                << '|'
                << details;

            return key.str();
        }

        static bool WasRecentlyDispatched(
            const std::string& key,
            std::chrono::steady_clock::time_point now
        ) {
            const auto iterator =
                recentAlerts_.find(key);

            if (iterator == recentAlerts_.end()) {
                return false;
            }

            const auto elapsed =
                std::chrono::duration_cast<
                    std::chrono::milliseconds
                >(
                    now - iterator->second
                );

            return elapsed.count() <
                   settings_.duplicateCooldownMs;
        }

        static void PruneRecentAlerts(
            std::chrono::steady_clock::time_point now
        ) {
            /*
             * Städning behöver inte göras för varje alert.
             */
            constexpr auto cleanupInterval =
                std::chrono::seconds(60);

            if (
                lastCleanup_.time_since_epoch().count() != 0 &&
                now - lastCleanup_ < cleanupInterval
            ) {
                return;
            }

            lastCleanup_ = now;

            if (settings_.duplicateCooldownMs == 0) {
                recentAlerts_.clear();
                return;
            }

            const auto retentionTime =
                std::chrono::milliseconds(
                    static_cast<std::uint64_t>(
                        settings_.duplicateCooldownMs
                    ) * 4ULL
                );

            for (
                auto iterator = recentAlerts_.begin();
                iterator != recentAlerts_.end();
            ) {
                if (
                    now - iterator->second >
                    retentionTime
                ) {
                    iterator =
                        recentAlerts_.erase(iterator);
                } else {
                    ++iterator;
                }
            }
        }

        static std::string CreateUtcTimestamp() {
            const auto now =
                std::chrono::system_clock::now();

            const std::time_t time =
                std::chrono::system_clock::to_time_t(
                    now
                );

            std::tm utcTime{};

            /*
             * Windows-versionen av gmtime_s.
             */
            if (gmtime_s(&utcTime, &time) != 0) {
                return "1970-01-01T00:00:00.000Z";
            }

            const auto milliseconds =
                std::chrono::duration_cast<
                    std::chrono::milliseconds
                >(
                    now.time_since_epoch()
                ) % 1000;

            std::ostringstream timestamp;

            timestamp
                << std::put_time(
                    &utcTime,
                    "%Y-%m-%dT%H:%M:%S"
                )
                << '.'
                << std::setw(3)
                << std::setfill('0')
                << milliseconds.count()
                << 'Z';

            return timestamp.str();
        }

        static std::string EscapeJson(
            const std::string& value
        ) {
            std::ostringstream escaped;

            for (unsigned char character : value) {
                switch (character) {
                    case '"':
                        escaped << "\\\"";
                        break;

                    case '\\':
                        escaped << "\\\\";
                        break;

                    case '\b':
                        escaped << "\\b";
                        break;

                    case '\f':
                        escaped << "\\f";
                        break;

                    case '\n':
                        escaped << "\\n";
                        break;

                    case '\r':
                        escaped << "\\r";
                        break;

                    case '\t':
                        escaped << "\\t";
                        break;

                    default:
                        if (character < 0x20) {
                            escaped
                                << "\\u00"
                                << std::hex
                                << std::setw(2)
                                << std::setfill('0')
                                << static_cast<int>(
                                    character
                                )
                                << std::dec;
                        } else {
                            escaped <<
                                static_cast<char>(
                                    character
                                );
                        }

                        break;
                }
            }

            return escaped.str();
        }

        static std::string BuildJsonLine(
            const SecurityAlert& alert
        ) {
            std::ostringstream json;

            json
                << '{'
                << "\"timestamp\":\""
                << EscapeJson(alert.timestampUtc)
                << "\","
                << "\"sequence\":"
                << alert.sequence
                << ','
                << "\"level\":\""
                << ThreatLevelToString(alert.level)
                << "\","
                << "\"category\":\""
                << EscapeJson(alert.category)
                << "\","
                << "\"details\":\""
                << EscapeJson(alert.details)
                << "\","
                << "\"pid\":"
                << alert.processId
                << ','
                << "\"risk_score\":"
                << alert.riskScore
                << '}';

            return json.str();
        }

        static std::string BuildTextLine(
            const SecurityAlert& alert
        ) {
            std::ostringstream line;

            line
                << '['
                << alert.timestampUtc
                << "] ["
                << ThreatLevelToString(alert.level)
                << "] ["
                << alert.category
                << ']';

            if (alert.processId != 0) {
                line
                    << " [PID "
                    << alert.processId
                    << ']';
            }

            if (alert.riskScore != 0) {
                line
                    << " [Risk "
                    << alert.riskScore
                    << ']';
            }

            line
                << ' '
                << alert.details;

            return line.str();
        }

        static void WriteConsole(
            ThreatLevel level,
            const std::string& line
        ) {
            if (
                level == ThreatLevel::HIGH ||
                level == ThreatLevel::CRITICAL
            ) {
                std::cerr << line << '\n';
                return;
            }

            std::cout << line << '\n';
        }

        static void EnsureLogDirectory() {
            const std::filesystem::path parent =
                settings_.logPath.parent_path();

            if (parent.empty()) {
                return;
            }

            std::error_code error;

            std::filesystem::create_directories(
                parent,
                error
            );

            if (error) {
                std::cerr
                    << "[Mjolnir Logging Error] "
                    << "Could not create log directory: "
                    << error.message()
                    << '\n';
            }
        }

        static void RotateLogsIfNeeded() {
            if (settings_.maxLogSizeBytes == 0) {
                return;
            }

            std::error_code error;

            if (
                !std::filesystem::exists(
                    settings_.logPath,
                    error
                ) ||
                error
            ) {
                return;
            }

            const std::uintmax_t currentSize =
                std::filesystem::file_size(
                    settings_.logPath,
                    error
                );

            if (
                error ||
                currentSize <
                    settings_.maxLogSizeBytes
            ) {
                return;
            }

            if (settings_.retainedLogFiles == 0) {
                std::filesystem::remove(
                    settings_.logPath,
                    error
                );

                return;
            }

            for (
                std::size_t index =
                    settings_.retainedLogFiles;
                index > 0;
                --index
            ) {
                const std::filesystem::path source =
                    index == 1
                        ? settings_.logPath
                        : std::filesystem::path(
                            settings_.logPath.string() +
                            "." +
                            std::to_string(index - 1)
                        );

                const std::filesystem::path destination =
                    std::filesystem::path(
                        settings_.logPath.string() +
                        "." +
                        std::to_string(index)
                    );

                error.clear();

                if (
                    !std::filesystem::exists(
                        source,
                        error
                    ) ||
                    error
                ) {
                    continue;
                }

                error.clear();

                if (
                    std::filesystem::exists(
                        destination,
                        error
                    ) &&
                    !error
                ) {
                    std::filesystem::remove(
                        destination,
                        error
                    );
                }

                error.clear();

                std::filesystem::rename(
                    source,
                    destination,
                    error
                );

                if (error) {
                    std::cerr
                        << "[Mjolnir Logging Error] "
                        << "Could not rotate log file: "
                        << error.message()
                        << '\n';

                    return;
                }
            }
        }

        static void WriteFile(
            const std::string& line
        ) {
            EnsureLogDirectory();
            RotateLogsIfNeeded();

            std::ofstream logFile(
                settings_.logPath,
                std::ios::binary |
                std::ios::app
            );

            if (!logFile.is_open()) {
                std::cerr
                    << "[Mjolnir Logging Error] "
                    << "Could not open log file: "
                    << settings_.logPath.string()
                    << '\n';

                return;
            }

            logFile << line << '\n';

            if (!logFile.good()) {
                std::cerr
                    << "[Mjolnir Logging Error] "
                    << "Failed to write alert."
                    << '\n';
            }
        }

        inline static std::mutex mutex_;

        inline static AlertSettings settings_{};

        inline static AlertSink externalSink_{};

        inline static std::unordered_map<
            std::string,
            std::chrono::steady_clock::time_point
        > recentAlerts_;

        inline static std::chrono::steady_clock::time_point
            lastCleanup_{};

        inline static std::uint64_t sequence_ = 0;
    };

} // namespace Mjolnir
