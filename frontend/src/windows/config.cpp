#include "config.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace Mjolnir {

    // Helper to strip quotes, commas, and whitespace for clean lookups
    static std::string TrimAndClean(const std::string& str) {
        std::string result = str;
        result.erase(std::remove(result.begin(), result.end(), '"'), result.end());
        result.erase(std::remove(result.begin(), result.end(), ','), result.end());
        result.erase(std::remove(result.begin(), result.end(), ' '), result.end());
        result.erase(std::remove(result.begin(), result.end(), '\t'), result.end());
        result.erase(std::remove(result.begin(), result.end(), '\r'), result.end());
        result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());
        
        // Convert to lowercase for case-insensitive process matching
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }

    bool ConfigManager::LoadConfig(const std::string& configPath) {
        std::ifstream file(configPath);
        if (!file.is_open()) {
            return false;
        }

        std::string line;
        bool inProcessArray = false;

        while (std::getline(file, line)) {
            // Track when we enter the whitelisted_processes array block
            if (line.find("whitelisted_processes") != std::string::npos) {
                inProcessArray = true;
                continue;
            }

            if (inProcessArray) {
                // Exit array block when closing bracket is reached
                if (line.find(']') != std::string::npos) {
                    inProcessArray = false;
                    continue;
                }

                std::string cleaned = TrimAndClean(line);
                if (!cleaned.empty()) {
                    whitelistedProcesses.insert(cleaned);
                }
            }

            // Parse basic settings inline
            if (line.find("strict_mode") != std::string::npos) {
                settings.strict_mode = (line.find("true") != std::string::npos);
            }
        }

        return true;
    }

    bool ConfigManager::IsWhitelisted(const std::string& processName) const {
        std::string lowerName = processName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        lowerName.erase(std::remove(lowerName.begin(), lowerName.end(), '"'), lowerName.end());
        
        return whitelistedProcesses.find(lowerName) != whitelistedProcesses.end();
    }

    const ConfigSettings& ConfigManager::GetSettings() const {
        return settings;
    }

} // namespace Mjolnir
