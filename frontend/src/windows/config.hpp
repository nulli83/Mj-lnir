#pragma once

#include <string>
#include <vector>
#include <unordered_set>

namespace Mjolnir {

    struct ConfigSettings {
        bool strict_mode = false;
        std::string log_level = "info";
    };

    class ConfigManager {
    private:
        ConfigSettings settings;
        std::unordered_set<std::string> whitelistedProcesses;

    public:
        bool LoadConfig(const std::string& configPath = "whitelist.json");
        bool IsWhitelisted(const std::string& processName) const;
        const ConfigSettings& GetSettings() const;
    };

} // namespace Mjolnir
