#include "config.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <limits>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace Mjolnir {

    namespace {

        using Json = nlohmann::json;

        std::string Trim(std::string_view value) {
            std::size_t first = 0;

            while (
                first < value.size() &&
                std::isspace(
                    static_cast<unsigned char>(value[first])
                )
            ) {
                ++first;
            }

            std::size_t last = value.size();

            while (
                last > first &&
                std::isspace(
                    static_cast<unsigned char>(value[last - 1])
                )
            ) {
                --last;
            }

            return std::string(
                value.substr(first, last - first)
            );
        }

        std::string ToLowerAscii(std::string value) {
            std::transform(
                value.begin(),
                value.end(),
                value.begin(),
                [](unsigned char character) {
                    return static_cast<char>(
                        std::tolower(character)
                    );
                }
            );

            return value;
        }

        bool ReadBoolean(
            const Json& object,
            const char* key,
            bool fallback
        ) {
            const auto iterator = object.find(key);

            if (iterator == object.end()) {
                return fallback;
            }

            if (!iterator->is_boolean()) {
                throw std::runtime_error(
                    std::string("Expected boolean field: ") + key
                );
            }

            return iterator->get<bool>();
        }

        std::string ReadString(
            const Json& object,
            const char* key,
            const std::string& fallback
        ) {
            const auto iterator = object.find(key);

            if (iterator == object.end()) {
                return fallback;
            }

            if (!iterator->is_string()) {
                throw std::runtime_error(
                    std::string("Expected string field: ") + key
                );
            }

            return iterator->get<std::string>();
        }

        std::uint32_t ReadUnsigned32(
            const Json& object,
            const char* key,
            std::uint32_t fallback
        ) {
            const auto iterator = object.find(key);

            if (iterator == object.end()) {
                return fallback;
            }

            if (!iterator->is_number_integer()) {
                throw std::runtime_error(
                    std::string("Expected integer field: ") + key
                );
            }

            std::uint64_t value = 0;

            if (iterator->is_number_unsigned()) {
                value = iterator->get<std::uint64_t>();
            } else {
                const std::int64_t signedValue =
                    iterator->get<std::int64_t>();

                if (signedValue < 0) {
                    throw std::runtime_error(
                        std::string(
                            "Field cannot be negative: "
                        ) + key
                    );
                }

                value = static_cast<std::uint64_t>(
                    signedValue
                );
            }

            if (
                value >
                std::numeric_limits<std::uint32_t>::max()
            ) {
                throw std::runtime_error(
                    std::string(
                        "Integer field is too large: "
                    ) + key
                );
            }

            return static_cast<std::uint32_t>(value);
        }

        int ReadInteger(
            const Json& object,
            const char* key,
            int fallback
        ) {
            const auto iterator = object.find(key);

            if (iterator == object.end()) {
                return fallback;
            }

            if (!iterator->is_number_integer()) {
                throw std::runtime_error(
                    std::string("Expected integer field: ") + key
                );
            }

            const std::int64_t value =
                iterator->get<std::int64_t>();

            if (
                value < std::numeric_limits<int>::min() ||
                value > std::numeric_limits<int>::max()
            ) {
                throw std::runtime_error(
                    std::string(
                        "Integer field is outside int range: "
                    ) + key
                );
            }

            return static_cast<int>(value);
        }

        std::pair<std::size_t, std::size_t>
        CalculateLineAndColumn(
            const std::string& content,
            std::size_t parserByte
        ) {
            /*
             * nlohmann::json använder en 1-baserad byteposition.
             */
            const std::size_t targetIndex =
                parserByte > 0
                    ? std::min(
                        parserByte - 1,
                        content.size()
                    )
                    : 0;

            std::size_t line = 1;
            std::size_t column = 1;

            for (
                std::size_t index = 0;
                index < targetIndex;
                ++index
            ) {
                if (content[index] == '\n') {
                    ++line;
                    column = 1;
                } else {
                    ++column;
                }
            }

            return {line, column};
        }

        bool IsHexadecimalString(
            const std::string& value
        ) {
            return std::all_of(
                value.begin(),
                value.end(),
                [](unsigned char character) {
                    return std::isxdigit(character) != 0;
                }
            );
        }

        bool IsPathInsideDirectory(
            const std::string& path,
            const std::string& directory
        ) {
            if (path.empty() || directory.empty()) {
                return false;
            }

            if (path == directory) {
                return true;
            }

            if (path.size() <= directory.size()) {
                return false;
            }

            if (
                path.compare(
                    0,
                    directory.size(),
                    directory
                ) != 0
            ) {
                return false;
            }

            if (directory.back() == '\\') {
                return true;
            }

            return path[directory.size()] == '\\';
        }

    } // namespace

    ConfigManager::ConfigManager(
        std::filesystem::path configPath
    ) {
        LoadConfigDetailed(configPath);
    }

    ConfigLoadResult ConfigManager::LoadConfigDetailed(
        const std::filesystem::path& configPath
    ) {
        ConfigLoadResult result{};

        try {
            std::ifstream file(
                configPath,
                std::ios::binary
            );

            if (!file.is_open()) {
                result.errorMessage =
                    "Could not open configuration file: " +
                    configPath.string();

                std::unique_lock<std::shared_mutex> lock(
                    mutex_
                );

                lastError_ = result.errorMessage;
                return result;
            }

            std::ostringstream stream;
            stream << file.rdbuf();

            if (file.bad()) {
                result.errorMessage =
                    "Failed while reading configuration file: " +
                    configPath.string();

                std::unique_lock<std::shared_mutex> lock(
                    mutex_
                );

                lastError_ = result.errorMessage;
                return result;
            }

            const std::string content = stream.str();

            if (content.empty()) {
                result.errorMessage =
                    "Configuration file is empty.";

                std::unique_lock<std::shared_mutex> lock(
                    mutex_
                );

                lastError_ = result.errorMessage;
                return result;
            }

            const Json root = Json::parse(content);

            if (!root.is_object()) {
                throw std::runtime_error(
                    "Configuration root must be a JSON object."
                );
            }

            ConfigSnapshot candidate{};

            candidate.schemaVersion = ReadUnsigned32(
                root,
                "schema_version",
                candidate.schemaVersion
            );

            /*
             * Settings
             */
            if (const auto settingsIterator =
                    root.find("settings");
                settingsIterator != root.end()) {

                if (!settingsIterator->is_object()) {
                    throw std::runtime_error(
                        "Field 'settings' must be an object."
                    );
                }

                const Json& settingsObject =
                    *settingsIterator;

                candidate.settings.strictMode =
                    ReadBoolean(
                        settingsObject,
                        "strict_mode",
                        candidate.settings.strictMode
                    );

                candidate.settings.logLevel =
                    ParseLogLevel(
                        ReadString(
                            settingsObject,
                            "log_level",
                            "info"
                        )
                    );

                candidate.settings.scanIntervalMs =
                    ReadUnsigned32(
                        settingsObject,
                        "scan_interval_ms",
                        candidate.settings.scanIntervalMs
                    );

                candidate.settings.alertCooldownMs =
                    ReadUnsigned32(
                        settingsObject,
                        "alert_cooldown_ms",
                        candidate.settings.alertCooldownMs
                    );

                candidate.settings.maxAlertsPerMinute =
                    ReadUnsigned32(
                        settingsObject,
                        "max_alerts_per_minute",
                        candidate.settings.maxAlertsPerMinute
                    );

                candidate.settings.requireValidSignature =
                    ReadBoolean(
                        settingsObject,
                        "require_valid_signature",
                        candidate.settings
                            .requireValidSignature
                    );

                candidate.settings
                    .allowUnknownMicrosoftModules =
                    ReadBoolean(
                        settingsObject,
                        "allow_unknown_microsoft_modules",
                        candidate.settings
                            .allowUnknownMicrosoftModules
                    );

                candidate.settings.observeOnly =
                    ReadBoolean(
                        settingsObject,
                        "observe_only",
                        candidate.settings.observeOnly
                    );

                candidate.settings.enableHandleScan =
                    ReadBoolean(
                        settingsObject,
                        "enable_handle_scan",
                        candidate.settings.enableHandleScan
                    );

                candidate.settings.enableMemoryRegionScan =
                    ReadBoolean(
                        settingsObject,
                        "enable_memory_region_scan",
                        candidate.settings
                            .enableMemoryRegionScan
                    );

                candidate.settings.enableHookScan =
                    ReadBoolean(
                        settingsObject,
                        "enable_hook_scan",
                        candidate.settings.enableHookScan
                    );

                candidate.settings.enableTimingScan =
                    ReadBoolean(
                        settingsObject,
                        "enable_timing_scan",
                        candidate.settings.enableTimingScan
                    );

                candidate.settings.enableInlineHookScan =
                    ReadBoolean(
                        settingsObject,
                        "enable_inline_hook_scan",
                        candidate.settings
                            .enableInlineHookScan
                    );

                candidate.settings.enableManualMapScan =
                    ReadBoolean(
                        settingsObject,
                        "enable_manual_map_scan",
                        candidate.settings
                            .enableManualMapScan
                    );

                candidate.settings.enableDeviceScan =
                    ReadBoolean(
                        settingsObject,
                        "enable_device_scan",
                        candidate.settings.enableDeviceScan
                    );

                candidate.settings.enableImageIntegrityScan =
                    ReadBoolean(
                        settingsObject,
                        "enable_image_integrity_scan",
                        candidate.settings
                            .enableImageIntegrityScan
                    );

                candidate.settings.enableArtifactScan =
                    ReadBoolean(
                        settingsObject,
                        "enable_artifact_scan",
                        candidate.settings.enableArtifactScan
                    );

                candidate.settings.enableServiceScan =
                    ReadBoolean(
                        settingsObject,
                        "enable_service_scan",
                        candidate.settings.enableServiceScan
                    );

                candidate.settings.enableBaselineTracking =
                    ReadBoolean(
                        settingsObject,
                        "enable_baseline_tracking",
                        candidate.settings
                            .enableBaselineTracking
                    );

                candidate.settings.enableSelfProtect =
                    ReadBoolean(
                        settingsObject,
                        "enable_self_protect",
                        candidate.settings.enableSelfProtect
                    );

                candidate.settings
                    .enforceTerminateWatchedTools =
                    ReadBoolean(
                        settingsObject,
                        "enforce_terminate_watched_tools",
                        candidate.settings
                            .enforceTerminateWatchedTools
                    );

                candidate.settings.enforceRiskThreshold =
                    ReadInteger(
                        settingsObject,
                        "enforce_risk_threshold",
                        candidate.settings
                            .enforceRiskThreshold
                    );
            }

            /*
             * Target
             */
            if (const auto targetIterator =
                    root.find("target");
                targetIterator != root.end()) {

                if (!targetIterator->is_object()) {
                    throw std::runtime_error(
                        "Field 'target' must be an object."
                    );
                }

                const Json& targetObject = *targetIterator;

                candidate.target.processName =
                    NormalizeName(
                        ReadString(
                            targetObject,
                            "process_name",
                            candidate.target.processName
                        )
                    );

                candidate.target.windowTitle =
                    Trim(
                        ReadString(
                            targetObject,
                            "window_title",
                            candidate.target.windowTitle
                        )
                    );

                const auto rootsIterator =
                    targetObject.find(
                        "expected_install_roots"
                    );

                if (rootsIterator != targetObject.end()) {
                    if (!rootsIterator->is_array()) {
                        throw std::runtime_error(
                            "'expected_install_roots' "
                            "must be an array."
                        );
                    }

                    for (const Json& item : *rootsIterator) {
                        if (!item.is_string()) {
                            throw std::runtime_error(
                                "Each expected install root "
                                "must be a string."
                            );
                        }

                        std::string path = NormalizePath(
                            ExpandEnvironmentVariables(
                                item.get<std::string>()
                            )
                        );

                        if (!path.empty()) {
                            candidate.target
                                .expectedInstallRoots
                                .push_back(
                                    std::move(path)
                                );
                        }
                    }
                }
            }

            /*
             * Risk weights
             */
            if (const auto riskIterator =
                    root.find("risk_weights");
                riskIterator != root.end()) {

                if (!riskIterator->is_object()) {
                    throw std::runtime_error(
                        "Field 'risk_weights' must be an object."
                    );
                }

                const Json& riskObject = *riskIterator;

                candidate.riskWeights.unknownProcess =
                    ReadInteger(
                        riskObject,
                        "unknown_process",
                        candidate.riskWeights
                            .unknownProcess
                    );

                candidate.riskWeights.unknownModule =
                    ReadInteger(
                        riskObject,
                        "unknown_module",
                        candidate.riskWeights
                            .unknownModule
                    );

                candidate.riskWeights.unsignedModule =
                    ReadInteger(
                        riskObject,
                        "unsigned_module",
                        candidate.riskWeights
                            .unsignedModule
                    );

                candidate.riskWeights
                    .moduleFromSuspiciousDirectory =
                    ReadInteger(
                        riskObject,
                        "module_from_suspicious_directory",
                        candidate.riskWeights
                            .moduleFromSuspiciousDirectory
                    );

                candidate.riskWeights.unexpectedOverlay =
                    ReadInteger(
                        riskObject,
                        "unexpected_overlay",
                        candidate.riskWeights
                            .unexpectedOverlay
                    );

                candidate.riskWeights
                    .externalProcessHandle =
                    ReadInteger(
                        riskObject,
                        "external_process_handle",
                        candidate.riskWeights
                            .externalProcessHandle
                    );

                candidate.riskWeights.debuggerAttached =
                    ReadInteger(
                        riskObject,
                        "debugger_attached",
                        candidate.riskWeights
                            .debuggerAttached
                    );

                candidate.riskWeights.knownBadHash =
                    ReadInteger(
                        riskObject,
                        "known_bad_hash",
                        candidate.riskWeights
                            .knownBadHash
                    );

                candidate.riskWeights.trustedPublisher =
                    ReadInteger(
                        riskObject,
                        "trusted_publisher",
                        candidate.riskWeights
                            .trustedPublisher
                    );

                candidate.riskWeights.trustedHash =
                    ReadInteger(
                        riskObject,
                        "trusted_hash",
                        candidate.riskWeights
                            .trustedHash
                    );

                candidate.riskWeights.apiHook =
                    ReadInteger(
                        riskObject,
                        "api_hook",
                        candidate.riskWeights.apiHook
                    );

                candidate.riskWeights.timingAnomaly =
                    ReadInteger(
                        riskObject,
                        "timing_anomaly",
                        candidate.riskWeights
                            .timingAnomaly
                    );

                candidate.riskWeights.inlineHook =
                    ReadInteger(
                        riskObject,
                        "inline_hook",
                        candidate.riskWeights.inlineHook
                    );

                candidate.riskWeights.manualMap =
                    ReadInteger(
                        riskObject,
                        "manual_map",
                        candidate.riskWeights.manualMap
                    );

                candidate.riskWeights.riskyDevice =
                    ReadInteger(
                        riskObject,
                        "risky_device",
                        candidate.riskWeights.riskyDevice
                    );

                candidate.riskWeights.imageIntegrity =
                    ReadInteger(
                        riskObject,
                        "image_integrity",
                        candidate.riskWeights.imageIntegrity
                    );

                candidate.riskWeights.knownArtifact =
                    ReadInteger(
                        riskObject,
                        "known_artifact",
                        candidate.riskWeights.knownArtifact
                    );

                candidate.riskWeights.suspiciousService =
                    ReadInteger(
                        riskObject,
                        "suspicious_service",
                        candidate.riskWeights
                            .suspiciousService
                    );

                candidate.riskWeights.moduleBirth =
                    ReadInteger(
                        riskObject,
                        "module_birth",
                        candidate.riskWeights.moduleBirth
                    );

                candidate.riskWeights.codeMutation =
                    ReadInteger(
                        riskObject,
                        "code_mutation",
                        candidate.riskWeights.codeMutation
                    );

                candidate.riskWeights.selfProtect =
                    ReadInteger(
                        riskObject,
                        "self_protect",
                        candidate.riskWeights.selfProtect
                    );
            }

            /*
             * Läser en array av namn till unordered_set.
             */
            const auto readNameSet =
                [&root](
                    const char* key,
                    std::unordered_set<std::string>& destination
                ) {
                    const auto iterator = root.find(key);

                    if (iterator == root.end()) {
                        return;
                    }

                    if (!iterator->is_array()) {
                        throw std::runtime_error(
                            std::string("'") + key +
                            "' must be an array."
                        );
                    }

                    for (const Json& item : *iterator) {
                        if (!item.is_string()) {
                            throw std::runtime_error(
                                std::string(
                                    "Every item in '"
                                ) + key +
                                "' must be a string."
                            );
                        }

                        std::string value =
                            ConfigManager::NormalizeName(
                                item.get<std::string>()
                            );

                        if (!value.empty()) {
                            destination.insert(
                                std::move(value)
                            );
                        }
                    }
                };

            readNameSet(
                "whitelisted_processes",
                candidate.whitelistedProcesses
            );

            readNameSet(
                "whitelisted_modules",
                candidate.whitelistedModules
            );

            readNameSet(
                "allowed_overlay_processes",
                candidate.allowedOverlayProcesses
            );

            readNameSet(
                "trusted_publishers",
                candidate.trustedPublishers
            );

            readNameSet(
                "whitelisted_signatures",
                candidate.whitelistedSignatures
            );

            readNameSet(
                "monitor_only_processes",
                candidate.monitorOnlyProcesses
            );

            /*
             * SHA-256-listor
             */
            const auto readHashSet =
                [](
                    const Json& rootObject,
                    const char* key,
                    std::unordered_set<std::string>& destination
                ) {
                    const auto iterator = rootObject.find(key);

                    if (iterator == rootObject.end()) {
                        return;
                    }

                    if (!iterator->is_array()) {
                        throw std::runtime_error(
                            std::string("'") + key +
                            "' must be an array."
                        );
                    }

                    for (const Json& item : *iterator) {
                        if (!item.is_string()) {
                            throw std::runtime_error(
                                std::string(
                                    "Every item in '"
                                ) + key +
                                "' must be a string."
                            );
                        }

                        std::string hash = NormalizeHash(
                            item.get<std::string>()
                        );

                        if (!hash.empty()) {
                            destination.insert(
                                std::move(hash)
                            );
                        }
                    }
                };

            readHashSet(
                root,
                "trusted_hashes",
                candidate.trustedHashes
            );

            readHashSet(
                root,
                "known_bad_hashes",
                candidate.knownBadHashes
            );

            /*
             * Misstänkta modulkataloger
             */
            if (const auto directoriesIterator =
                    root.find(
                        "suspicious_module_directories"
                    );
                directoriesIterator != root.end()) {

                if (!directoriesIterator->is_array()) {
                    throw std::runtime_error(
                        "'suspicious_module_directories' "
                        "must be an array."
                    );
                }

                for (
                    const Json& item :
                    *directoriesIterator
                ) {
                    if (!item.is_string()) {
                        throw std::runtime_error(
                            "Every suspicious directory "
                            "must be a string."
                        );
                    }

                    std::string path = NormalizePath(
                        ExpandEnvironmentVariables(
                            item.get<std::string>()
                        )
                    );

                    if (!path.empty()) {
                        candidate
                            .suspiciousModuleDirectories
                            .push_back(
                                std::move(path)
                            );
                    }
                }
            }

            std::string validationError;

            if (!ValidateSnapshot(
                    candidate,
                    validationError
                )) {
                throw std::runtime_error(
                    "Configuration validation failed: " +
                    validationError
                );
            }

            std::error_code filesystemError;

            std::filesystem::path resolvedPath =
                std::filesystem::absolute(
                    configPath,
                    filesystemError
                );

            if (filesystemError) {
                resolvedPath = configPath;
                filesystemError.clear();
            }

            resolvedPath =
                resolvedPath.lexically_normal();

            const auto writeTime =
                std::filesystem::last_write_time(
                    resolvedPath,
                    filesystemError
                );

            /*
             * Konfigurationen ersätts först här, efter att
             * hela filen har lästs och validerats.
             */
            {
                std::unique_lock<std::shared_mutex> lock(
                    mutex_
                );

                snapshot_ = std::move(candidate);
                configPath_ = std::move(resolvedPath);

                if (!filesystemError) {
                    lastWriteTime_ = writeTime;
                } else {
                    lastWriteTime_ = {};
                }

                lastError_.clear();
                loaded_ = true;
            }

            result.success = true;
            return result;

        } catch (
            const nlohmann::json::parse_error& error
        ) {
            result.errorMessage =
                std::string("JSON parse error: ") +
                error.what();

            const auto [line, column] =
                CalculateLineAndColumn(
                    [&]() -> std::string {
                        std::ifstream retryFile(
                            configPath,
                            std::ios::binary
                        );

                        std::ostringstream retryStream;
                        retryStream << retryFile.rdbuf();
                        return retryStream.str();
                    }(),
                    error.byte
                );

            result.errorLine = line;
            result.errorColumn = column;

        } catch (
            const nlohmann::json::exception& error
        ) {
            result.errorMessage =
                std::string("JSON field error: ") +
                error.what();

        } catch (const std::exception& error) {
            result.errorMessage = error.what();
        }

        {
            std::unique_lock<std::shared_mutex> lock(
                mutex_
            );

            lastError_ = result.errorMessage;
        }

        return result;
    }

    bool ConfigManager::LoadConfig(
        const std::string& configPath
    ) {
        return LoadConfigDetailed(configPath).success;
    }

    ConfigLoadResult ConfigManager::Reload() {
        std::filesystem::path path;

        {
            std::shared_lock<std::shared_mutex> lock(
                mutex_
            );

            path = configPath_;
        }

        if (path.empty()) {
            path = "whitelist.json";
        }

        return LoadConfigDetailed(path);
    }

    bool ConfigManager::ReloadIfChanged() {
        std::filesystem::path path;
        std::filesystem::file_time_type previousTime{};
        bool wasLoaded = false;

        {
            std::shared_lock<std::shared_mutex> lock(
                mutex_
            );

            path = configPath_;
            previousTime = lastWriteTime_;
            wasLoaded = loaded_;
        }

        if (path.empty()) {
            path = "whitelist.json";
        }

        std::error_code error;

        const auto currentTime =
            std::filesystem::last_write_time(
                path,
                error
            );

        if (error) {
            std::unique_lock<std::shared_mutex> lock(
                mutex_
            );

            lastError_ =
                "Could not check configuration timestamp: " +
                error.message();

            return false;
        }

        if (
            wasLoaded &&
            currentTime == previousTime
        ) {
            return false;
        }

        return LoadConfigDetailed(path).success;
    }

    ConfigSnapshot ConfigManager::GetSnapshot() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_;
    }

    ConfigSettings ConfigManager::GetSettings() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_.settings;
    }

    TargetConfig ConfigManager::GetTarget() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_.target;
    }

    RiskWeights ConfigManager::GetRiskWeights() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_.riskWeights;
    }

    std::string ConfigManager::GetTargetProcessName() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_.target.processName;
    }

    bool ConfigManager::IsProcessWhitelisted(
        std::string_view processName
    ) const {
        const std::string normalized =
            NormalizeName(processName);

        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_
                   .whitelistedProcesses
                   .find(normalized) !=
               snapshot_
                   .whitelistedProcesses
                   .end();
    }

    bool ConfigManager::IsModuleWhitelisted(
        std::string_view moduleName
    ) const {
        const std::string normalized =
            NormalizeName(moduleName);

        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_
                   .whitelistedModules
                   .find(normalized) !=
               snapshot_
                   .whitelistedModules
                   .end();
    }

    bool ConfigManager::IsOverlayAllowed(
        std::string_view processName
    ) const {
        const std::string normalized =
            NormalizeName(processName);

        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_
                   .allowedOverlayProcesses
                   .find(normalized) !=
               snapshot_
                   .allowedOverlayProcesses
                   .end();
    }

    bool ConfigManager::IsPublisherTrusted(
        std::string_view publisher
    ) const {
        const std::string normalized =
            NormalizeName(publisher);

        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_
                   .trustedPublishers
                   .find(normalized) !=
               snapshot_
                   .trustedPublishers
                   .end();
    }

    bool ConfigManager::IsSignatureWhitelisted(
        std::string_view signature
    ) const {
        const std::string normalized =
            NormalizeName(signature);

        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_
                   .whitelistedSignatures
                   .find(normalized) !=
               snapshot_
                   .whitelistedSignatures
                   .end();
    }

    bool ConfigManager::IsHashTrusted(
        std::string_view sha256
    ) const {
        const std::string normalized =
            NormalizeHash(sha256);

        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_
                   .trustedHashes
                   .find(normalized) !=
               snapshot_
                   .trustedHashes
                   .end();
    }

    bool ConfigManager::IsHashKnownBad(
        std::string_view sha256
    ) const {
        const std::string normalized =
            NormalizeHash(sha256);

        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_
                   .knownBadHashes
                   .find(normalized) !=
               snapshot_
                   .knownBadHashes
                   .end();
    }

    bool ConfigManager::IsMonitorOnlyProcess(
        std::string_view processName
    ) const {
        const std::string normalized =
            NormalizeName(processName);

        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_
                   .monitorOnlyProcesses
                   .find(normalized) !=
               snapshot_
                   .monitorOnlyProcesses
                   .end();
    }

    bool ConfigManager::IsSuspiciousModulePath(
        std::string_view modulePath
    ) const {
        const std::string normalized =
            NormalizePath(modulePath);

        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        for (
            const std::string& directory :
            snapshot_.suspiciousModuleDirectories
        ) {
            if (
                IsPathInsideDirectory(
                    normalized,
                    directory
                )
            ) {
                return true;
            }
        }

        return false;
    }

    std::unordered_set<std::string>
    ConfigManager::GetWhitelistedProcesses() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_.whitelistedProcesses;
    }

    std::unordered_set<std::string>
    ConfigManager::GetWhitelistedModules() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_.whitelistedModules;
    }

    std::unordered_set<std::string>
    ConfigManager::GetAllowedOverlayProcesses() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_.allowedOverlayProcesses;
    }

    std::unordered_set<std::string>
    ConfigManager::GetTrustedPublishers() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_.trustedPublishers;
    }

    std::unordered_set<std::string>
    ConfigManager::GetTrustedHashes() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_.trustedHashes;
    }

    std::vector<std::string>
    ConfigManager::GetSuspiciousModuleDirectories() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return snapshot_.suspiciousModuleDirectories;
    }

    std::filesystem::path
    ConfigManager::GetConfigPath() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return configPath_;
    }

    std::string ConfigManager::GetLastError() const {
        std::shared_lock<std::shared_mutex> lock(
            mutex_
        );

        return lastError_;
    }

    std::string ConfigManager::NormalizeName(
        std::string_view value
    ) {
        std::string normalized = Trim(value);

        if (
            normalized.size() >= 2 &&
            (
                (
                    normalized.front() == '"' &&
                    normalized.back() == '"'
                ) ||
                (
                    normalized.front() == '\'' &&
                    normalized.back() == '\''
                )
            )
        ) {
            normalized = normalized.substr(
                1,
                normalized.size() - 2
            );
        }

        std::replace(
            normalized.begin(),
            normalized.end(),
            '/',
            '\\'
        );

        const std::size_t separator =
            normalized.find_last_of('\\');

        if (separator != std::string::npos) {
            normalized =
                normalized.substr(separator + 1);
        }

        return ToLowerAscii(
            Trim(normalized)
        );
    }

    std::string ConfigManager::NormalizeHash(
        std::string_view value
    ) {
        std::string normalized =
            ToLowerAscii(Trim(value));

        if (normalized.rfind("sha256:", 0) == 0) {
            normalized.erase(0, 7);
        }

        normalized.erase(
            std::remove_if(
                normalized.begin(),
                normalized.end(),
                [](unsigned char character) {
                    return
                        std::isspace(character) != 0 ||
                        character == ':' ||
                        character == '-';
                }
            ),
            normalized.end()
        );

        return normalized;
    }

    std::string ConfigManager::NormalizePath(
        std::string_view value
    ) {
        std::string normalized = Trim(value);

        if (
            normalized.size() >= 2 &&
            normalized.front() == '"' &&
            normalized.back() == '"'
        ) {
            normalized = normalized.substr(
                1,
                normalized.size() - 2
            );
        }

        std::replace(
            normalized.begin(),
            normalized.end(),
            '/',
            '\\'
        );

        normalized = ToLowerAscii(
            std::move(normalized)
        );

        /*
         * Behåll exempelvis C:\, men ta bort onödiga
         * avslutande backslashes från andra sökvägar.
         */
        while (
            normalized.size() > 3 &&
            normalized.back() == '\\'
        ) {
            normalized.pop_back();
        }

        return normalized;
    }

    std::string
    ConfigManager::ExpandEnvironmentVariables(
        std::string_view value
    ) {
        const std::string input(value);

        if (input.empty()) {
            return {};
        }

        const DWORD requiredSize =
            ExpandEnvironmentStringsA(
                input.c_str(),
                nullptr,
                0
            );

        if (requiredSize == 0) {
            return input;
        }

        std::string output(
            static_cast<std::size_t>(requiredSize),
            '\0'
        );

        const DWORD written =
            ExpandEnvironmentStringsA(
                input.c_str(),
                output.data(),
                requiredSize
            );

        if (
            written == 0 ||
            written > requiredSize
        ) {
            return input;
        }

        /*
         * ExpandEnvironmentStrings inkluderar nullbyte
         * i det returnerade antalet tecken.
         */
        if (written > 0) {
            output.resize(
                static_cast<std::size_t>(written - 1)
            );
        }

        return output;
    }

    LogLevel ConfigManager::ParseLogLevel(
        std::string_view value
    ) {
        const std::string normalized =
            ToLowerAscii(Trim(value));

        if (normalized == "trace") {
            return LogLevel::Trace;
        }

        if (normalized == "debug") {
            return LogLevel::Debug;
        }

        if (normalized == "info") {
            return LogLevel::Info;
        }

        if (
            normalized == "warn" ||
            normalized == "warning"
        ) {
            return LogLevel::Warning;
        }

        if (normalized == "error") {
            return LogLevel::Error;
        }

        if (
            normalized == "critical" ||
            normalized == "fatal"
        ) {
            return LogLevel::Critical;
        }

        if (
            normalized == "off" ||
            normalized == "none"
        ) {
            return LogLevel::Off;
        }

        throw std::runtime_error(
            "Unknown log level: " +
            std::string(value)
        );
    }

    bool ConfigManager::ValidateSnapshot(
        const ConfigSnapshot& snapshot,
        std::string& errorMessage
    ) {
        if (snapshot.schemaVersion != 1) {
            errorMessage =
                "Unsupported schema_version. Expected 1.";

            return false;
        }

        if (snapshot.target.processName.empty()) {
            errorMessage =
                "target.process_name cannot be empty.";

            return false;
        }

        if (
            snapshot.settings.scanIntervalMs < 100 ||
            snapshot.settings.scanIntervalMs > 600000
        ) {
            errorMessage =
                "scan_interval_ms must be between "
                "100 and 600000.";

            return false;
        }

        if (
            snapshot.settings.alertCooldownMs >
            24U * 60U * 60U * 1000U
        ) {
            errorMessage =
                "alert_cooldown_ms cannot exceed "
                "24 hours.";

            return false;
        }

        if (
            snapshot.settings.maxAlertsPerMinute == 0 ||
            snapshot.settings.maxAlertsPerMinute > 100000
        ) {
            errorMessage =
                "max_alerts_per_minute must be "
                "between 1 and 100000.";

            return false;
        }

        const auto validRiskWeight =
            [](int value) {
                return value >= -1000 &&
                       value <= 1000;
            };

        const RiskWeights& weights =
            snapshot.riskWeights;

        if (
            !validRiskWeight(weights.unknownProcess) ||
            !validRiskWeight(weights.unknownModule) ||
            !validRiskWeight(weights.unsignedModule) ||
            !validRiskWeight(
                weights.moduleFromSuspiciousDirectory
            ) ||
            !validRiskWeight(
                weights.unexpectedOverlay
            ) ||
            !validRiskWeight(
                weights.externalProcessHandle
            ) ||
            !validRiskWeight(
                weights.debuggerAttached
            ) ||
            !validRiskWeight(weights.knownBadHash) ||
            !validRiskWeight(
                weights.trustedPublisher
            ) ||
            !validRiskWeight(weights.trustedHash) ||
            !validRiskWeight(weights.apiHook) ||
            !validRiskWeight(weights.timingAnomaly) ||
            !validRiskWeight(weights.inlineHook) ||
            !validRiskWeight(weights.manualMap) ||
            !validRiskWeight(weights.riskyDevice) ||
            !validRiskWeight(weights.imageIntegrity) ||
            !validRiskWeight(weights.knownArtifact) ||
            !validRiskWeight(weights.suspiciousService) ||
            !validRiskWeight(weights.moduleBirth) ||
            !validRiskWeight(weights.codeMutation) ||
            !validRiskWeight(weights.selfProtect)
        ) {
            errorMessage =
                "Every risk weight must be between "
                "-1000 and 1000.";

            return false;
        }

        if (
            snapshot.settings.enforceRiskThreshold < 1 ||
            snapshot.settings.enforceRiskThreshold > 1000
        ) {
            errorMessage =
                "enforce_risk_threshold must be between "
                "1 and 1000.";

            return false;
        }

        for (
            const std::string& hash :
            snapshot.trustedHashes
        ) {
            if (
                hash.size() != 64 ||
                !IsHexadecimalString(hash)
            ) {
                errorMessage =
                    "Trusted SHA-256 hash must contain "
                    "exactly 64 hexadecimal characters: " +
                    hash;

                return false;
            }
        }

        return true;
    }

} // namespace Mjolnir
