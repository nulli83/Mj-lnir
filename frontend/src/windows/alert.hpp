#pragma once

#include <string>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace Mjolnir {

    enum class ThreatLevel {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    };

    class SecurityAlertSystem {
    public:
        static void DispatchAlert(ThreatLevel level, const std::string& category, const std::string& details) {
            std::string levelStr;
            switch (level) {
                case ThreatLevel::LOW:      levelStr = "INFO"; break;
                case ThreatLevel::MEDIUM:   levelStr = "WARN"; break;
                case ThreatLevel::HIGH:     levelStr = "ALERT"; break;
                case ThreatLevel::CRITICAL: levelStr = "CRITICAL"; break;
            }

            auto now = std::chrono::system_clock::now();
            auto in_time_t = std::chrono::system_clock::to_time_t(now);

            std::stringstream ss;
            ss << "[" << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S") << "] "
               << "[" << levelStr << "] "
               << "[" << category << "] " << details;

            // Output to console
            std::cout << ss.str() << "\n";

            // Persist to audit log file
            std::ofstream logFile("log/sample.log", std::ios::app);
            if (logFile.is_open()) {
                logFile << ss.str() << "\n";
            }
        }
    };

} // namespace Mjolnir
