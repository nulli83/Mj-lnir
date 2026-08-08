#pragma once

#include <cstdint>
#include <filesystem>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace Mjolnir {

    enum class LogLevel {
        Trace,
        Debug,
        Info,
        Warning,
        Error,
        Critical,
        Off
    };

    struct ConfigSettings {
        bool strictMode = false;
        LogLevel logLevel = LogLevel::Info;

        std::uint32_t scanIntervalMs = 3000;
        std::uint32_t alertCooldownMs = 30000;
        std::uint32_t maxAlertsPerMinute = 60;

        bool requireValidSignature = false;
        bool allowUnknownMicrosoftModules = true;

        /*
         * När observeOnly är true ska antifusket bara logga.
         * Inga processer avslutas och inga automatiska bans utförs.
         */
        bool observeOnly = true;

        /*
         * När true körs den tyngre handle-enumerationen.
         * Kräver ofta administratörsrättigheter.
         */
        bool enableHandleScan = true;

        /*
         * När true skannas privata RWX-minnesregioner.
         */
        bool enableMemoryRegionScan = true;

        /*
         * När true kontrolleras IAT för kritiska API-hooks.
         */
        bool enableHookScan = true;

        /*
         * När true körs lokal timing-anomali-detektion.
         */
        bool enableTimingScan = true;

        /*
         * När true kontrolleras funktionsprologues för inline hooks.
         */
        bool enableInlineHookScan = true;

        /*
         * När true letas PE-headers i privat executable minne.
         */
        bool enableManualMapScan = true;

        /*
         * När true skannas kända sårbara/cheat-relaterade devices.
         */
        bool enableDeviceScan = true;

        /*
         * När true jämförs .text / PE-header mot disk.
         */
        bool enableImageIntegrityScan = true;

        /*
         * När true letas kända cheat-mutexer/fönster.
         */
        bool enableArtifactScan = true;

        /*
         * När true skannas Windows-tjänster efter kända hot.
         */
        bool enableServiceScan = true;

        /*
         * När true etableras session-baseline och difftar module birth / code mutation.
         */
        bool enableBaselineTracking = true;

        /*
         * När true sparas/läses baselines från disk per game-hash.
         */
        bool persistBaselines = true;

        /*
         * Katalog för persistenta baselines.
         */
        std::string baselineDirectory = "baselines";

        /*
         * När true spåras region/handle lifetime över cykler.
         */
        bool enableLifetimeTracking = true;

        /*
         * När true startas twin watchdog-processen.
         */
        bool enableTwinWatchdog = true;

        /*
         * När true skyddas och övervakas själva security core.
         */
        bool enableSelfProtect = true;

        /*
         * När true körs inject-heuristik på module birth.
         */
        bool enableInjectionHeuristics = true;

        /*
         * När true skannas processer efter farliga privileges (SeDebug m.fl.).
         */
        bool enablePrivilegeScan = true;

        /*
         * När true jämförs kritiska EAT-exporters i målprocessen.
         */
        bool enableEatHookScan = true;

        /*
         * När true skannas named pipes efter kända cheat/debug-mönster.
         */
        bool enablePipeScan = true;

        /*
         * När true jämförs ntdll syscall-stub prologues remote vs local.
         */
        bool enableSyscallStubScan = true;

        /*
         * När true körs process-hollowing / section-remap heuristik.
         */
        bool enableHollowingScan = true;

        /*
         * När true kontrolleras process mitigation policies.
         */
        bool enableMitigationScan = true;

        /*
         * När true letas instrumentation callbacks / ThreadHideFromDebugger.
         */
        bool enableStealthScan = true;

        /*
         * När true letas writable+executable MEM_IMAGE-regioner (code caves).
         */
        bool enableWritableImageScan = true;

        /*
         * När true skannas Run/RunOnce efter kända cheat-strängar.
         */
        bool enablePersistenceScan = true;

        /*
         * När true skannas lyssnande TCP-portar.
         */
        bool enablePortScan = true;

        /*
         * När true kontrolleras ETW/trace-exports för patchar.
         */
        bool enableEtwScan = true;

        /*
         * När true jämförs exception/VEH/APC-dispatcher prologues.
         */
        bool enableExceptionDispatchScan = true;

        /*
         * När true skannas hosts-filen efter AC/game-omdirigeringar.
         */
        bool enableHostsScan = true;

        /*
         * När true inspekteras målprocessens access token.
         */
        bool enableTokenScan = true;

        /*
         * När true skannas ESTABLISHED TCP till misstänkta portar.
         */
        bool enableConnectionScan = true;

        /*
         * När true kräver enforce ett glidande evidence-fönster
         * (inte bara en enskild cykel-peak).
         */
        bool enableEvidenceWindow = true;

        std::uint32_t evidenceWindowMs = 45000;
        std::uint32_t evidenceMinSamples = 3;
        int evidenceMinAverageRisk = 55;
        int evidenceMinPeakRisk = 80;
        int evidenceSustainedHighRisk = 50;
        std::uint32_t evidenceMinSustainedHighSamples = 3;
        std::uint32_t evidenceSettleCycles = 5;

        /*
         * Valfri HMAC-hemlighet för IPC-frames.
         * MJOLNIR_IPC_SECRET i miljön har företräde.
         */
        std::string ipcHmacSecret;

        /*
         * När enforce är aktivt, terminera även kända cheat-verktyg.
         */
        bool enforceTerminateWatchedTools = true;

        /*
         * Risktröskel för enforce när observeOnly=false.
         */
        int enforceRiskThreshold = 80;
    };

    struct TargetConfig {
        std::string processName = "game.exe";
        std::string windowTitle;

        std::vector<std::string> expectedInstallRoots;
    };

    struct RiskWeights {
        int unknownProcess = 10;
        int unknownModule = 15;
        int unsignedModule = 25;
        int moduleFromSuspiciousDirectory = 30;
        int unexpectedOverlay = 20;
        int externalProcessHandle = 35;
        int debuggerAttached = 40;
        int knownBadHash = 100;
        int trustedPublisher = -25;
        int trustedHash = -50;
        int apiHook = 45;
        int timingAnomaly = 35;
        int inlineHook = 50;
        int manualMap = 55;
        int riskyDevice = 70;
        int imageIntegrity = 60;
        int knownArtifact = 55;
        int suspiciousService = 60;
        int moduleBirth = 40;
        int codeMutation = 65;
        int selfProtect = 50;
        int regionBirth = 45;
        int regionEscalate = 55;
        int handleBirth = 40;
        int injection = 50;
        int dangerousPrivilege = 45;
        int eatHook = 55;
        int suspiciousPipe = 50;
        int syscallStub = 60;
        int hollowing = 70;
        int mitigation = 40;
        int stealth = 65;
        int writableImage = 55;
        int persistence = 50;
        int suspiciousPort = 35;
        int etwPatch = 70;
        int exceptionDispatch = 65;
        int hostsTamper = 45;
        int suspiciousToken = 40;
        int suspiciousConnection = 40;
    };

    struct ConfigSnapshot {
        std::uint32_t schemaVersion = 1;

        ConfigSettings settings;
        TargetConfig target;
        RiskWeights riskWeights;

        std::unordered_set<std::string> whitelistedProcesses;
        std::unordered_set<std::string> whitelistedModules;
        std::unordered_set<std::string> allowedOverlayProcesses;

        std::unordered_set<std::string> trustedPublishers;
        std::unordered_set<std::string> whitelistedSignatures;
        std::unordered_set<std::string> trustedHashes;
        std::unordered_set<std::string> knownBadHashes;

        std::unordered_set<std::string> monitorOnlyProcesses;

        std::vector<std::string> suspiciousModuleDirectories;
    };

    struct ConfigLoadResult {
        bool success = false;

        std::string errorMessage;

        std::size_t errorLine = 0;
        std::size_t errorColumn = 0;

        explicit operator bool() const {
            return success;
        }
    };

    class ConfigManager {
    public:
        ConfigManager() = default;

        explicit ConfigManager(
            std::filesystem::path configPath
        );

        /*
         * Läser och validerar konfigurationen.
         *
         * Den befintliga konfigurationen byts endast ut om hela
         * den nya filen kan läsas och valideras.
         */
        ConfigLoadResult LoadConfigDetailed(
            const std::filesystem::path& configPath =
                "whitelist.json"
        );

        /*
         * Kompatibilitetsfunktion för äldre main.cpp.
         */
        bool LoadConfig(
            const std::string& configPath =
                "whitelist.json"
        );

        /*
         * Laddar om den senast använda konfigurationsfilen.
         */
        ConfigLoadResult Reload();

        /*
         * Laddar endast om filens ändringstid har förändrats.
         *
         * Returnerar true när en ny konfiguration laddades.
         */
        bool ReloadIfChanged();

        ConfigSnapshot GetSnapshot() const;

        ConfigSettings GetSettings() const;
        TargetConfig GetTarget() const;
        RiskWeights GetRiskWeights() const;

        std::string GetTargetProcessName() const;

        bool IsProcessWhitelisted(
            std::string_view processName
        ) const;

        bool IsModuleWhitelisted(
            std::string_view moduleName
        ) const;

        bool IsOverlayAllowed(
            std::string_view processName
        ) const;

        bool IsPublisherTrusted(
            std::string_view publisher
        ) const;

        bool IsSignatureWhitelisted(
            std::string_view signature
        ) const;

        bool IsHashTrusted(
            std::string_view sha256
        ) const;

        bool IsHashKnownBad(
            std::string_view sha256
        ) const;

        bool IsMonitorOnlyProcess(
            std::string_view processName
        ) const;

        bool IsSuspiciousModulePath(
            std::string_view modulePath
        ) const;

        /*
         * Behålls tillfälligt för gammal kod.
         *
         * Ny kod bör använda IsProcessWhitelisted(),
         * IsModuleWhitelisted() eller IsOverlayAllowed().
         */
        bool IsWhitelisted(
            const std::string& processName
        ) const {
            return IsProcessWhitelisted(processName);
        }

        std::unordered_set<std::string>
        GetWhitelistedProcesses() const;

        std::unordered_set<std::string>
        GetWhitelistedModules() const;

        std::unordered_set<std::string>
        GetAllowedOverlayProcesses() const;

        std::unordered_set<std::string>
        GetTrustedPublishers() const;

        std::unordered_set<std::string>
        GetTrustedHashes() const;

        std::vector<std::string>
        GetSuspiciousModuleDirectories() const;

        std::filesystem::path GetConfigPath() const;

        std::string GetLastError() const;

    private:
        static std::string NormalizeName(
            std::string_view value
        );

        static std::string NormalizeHash(
            std::string_view value
        );

        static std::string NormalizePath(
            std::string_view value
        );

        static std::string ExpandEnvironmentVariables(
            std::string_view value
        );

        static LogLevel ParseLogLevel(
            std::string_view value
        );

        static bool ValidateSnapshot(
            const ConfigSnapshot& snapshot,
            std::string& errorMessage
        );

        mutable std::shared_mutex mutex_;

        ConfigSnapshot snapshot_;

        std::filesystem::path configPath_;
        std::filesystem::file_time_type lastWriteTime_{};

        std::string lastError_;
        bool loaded_ = false;
    };

} // namespace Mjolnir
