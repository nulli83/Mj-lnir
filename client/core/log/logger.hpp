#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace Mjolnir {

    class Logger {
    public:
        static void Write(const std::string& level, const std::string& message) {
            auto now = std::chrono::system_clock::now();
            auto in_time_t = std::chrono::system_clock::to_time_t(now);

            std::stringstream ss;
            ss << "[" << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S") << "] "
               << "[" << level << "] " << message;

            // Console output
            std::cout << ss.str() << "\n";

            // File output
            std::ofstream logFile("log/sample.log", std::ios::app);
            if (logFile.is_open()) {
                logFile << ss.str() << "\n";
            }
        }
    };

} // namespace Mjolnir
