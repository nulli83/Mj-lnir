#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Mjolnir {

    struct ModuleInfo {
        DWORD processId = 0;

        std::string name;
        std::string path;

        std::uintptr_t baseAddress = 0;
        DWORD imageSize = 0;

        bool whitelisted = false;
        bool systemModule = false;
        bool suspiciousPath = false;

        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct ModuleScanResult {
        std::vector<ModuleInfo> modules;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class ModuleScanner {
    private:
        class ScopedHandle {
        public:
            explicit ScopedHandle(HANDLE handle = INVALID_HANDLE_VALUE)
                : handle_(handle) {}

            ~ScopedHandle() {
                Reset();
            }

            ScopedHandle(const ScopedHandle&) = delete;
            ScopedHandle& operator=(const ScopedHandle&) = delete;

            ScopedHandle(ScopedHandle&& other) noexcept
                : handle_(other.handle_) {
                other.handle_ = INVALID_HANDLE_VALUE;
            }

            ScopedHandle& operator=(ScopedHandle&& other) noexcept {
                if (this != &other) {
                    Reset();

                    handle_ = other.handle_;
                    other.handle_ = INVALID_HANDLE_VALUE;
                }

                return *this;
            }

            HANDLE Get() const {
                return handle_;
            }

            bool IsValid() const {
                return handle_ != nullptr &&
                       handle_ != INVALID_HANDLE_VALUE;
            }

            void Reset(HANDLE newHandle = INVALID_HANDLE_VALUE) {
                if (IsValid()) {
                    CloseHandle(handle_);
                }

                handle_ = newHandle;
            }

        private:
            HANDLE handle_;
        };

        static std::string ToLower(std::string value) {
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

        static std::string WideToUtf8(const std::wstring& value) {
            if (value.empty()) {
                return {};
            }

            const int requiredSize = WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                nullptr,
                0,
                nullptr,
                nullptr
            );

            if (requiredSize <= 0) {
                return {};
            }

            std::string result(
                static_cast<std::size_t>(requiredSize),
                '\0'
            );

            const int convertedSize = WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                result.data(),
                requiredSize,
                nullptr,
                nullptr
            );

            if (convertedSize <= 0) {
                return {};
            }

            return result;
        }

        static bool StartsWith(
            const std::string& value,
            const std::string& prefix
        ) {
            return value.size() >= prefix.size() &&
                   value.compare(0, prefix.size(), prefix) == 0;
        }

        static bool EndsWith(
            const std::string& value,
            const std::string& suffix
        ) {
            return value.size() >= suffix.size() &&
                   value.compare(
                       value.size() - suffix.size(),
                       suffix.size(),
                       suffix
                   ) == 0;
        }

        static bool IsSystemPath(const std::string& rawPath) {
            const std::string path = ToLower(rawPath);

            static const std::vector<std::string> trustedRoots = {
                "c:\\windows\\system32\\",
                "c:\\windows\\syswow64\\",
                "c:\\windows\\winsxs\\",
                "c:\\program files\\",
                "c:\\program files (x86)\\"
            };

            for (const std::string& root : trustedRoots) {
                if (StartsWith(path, root)) {
                    return true;
                }
            }

            return false;
        }

        static bool IsSuspiciousPath(const std::string& rawPath) {
            const std::string path = ToLower(rawPath);

            static const std::vector<std::string> suspiciousSegments = {
                "\\appdata\\local\\temp\\",
                "\\windows\\temp\\",
                "\\downloads\\",
                "\\public\\downloads\\",
                "\\recycle.bin\\"
            };

            for (const std::string& segment : suspiciousSegments) {
                if (path.find(segment) != std::string::npos) {
                    return true;
                }
            }

            return false;
        }

        static void AddRisk(
            ModuleInfo& module,
            int amount,
            const std::string& reason
        ) {
            module.riskScore += amount;
            module.reasons.push_back(reason);
        }

        static void CalculateRisk(ModuleInfo& module) {
            if (module.path.empty()) {
                AddRisk(
                    module,
                    25,
                    "Module path could not be resolved"
                );
            }

            if (module.suspiciousPath) {
                AddRisk(
                    module,
                    40,
                    "Module was loaded from a suspicious directory"
                );
            }

            if (!module.systemModule && !module.whitelisted) {
                AddRisk(
                    module,
                    15,
                    "Module is neither system-located nor whitelisted"
                );
            }

            const std::string normalizedName =
                ToLower(module.name);

            if (
                !EndsWith(normalizedName, ".dll") &&
                !EndsWith(normalizedName, ".exe")
            ) {
                AddRisk(
                    module,
                    10,
                    "Module has an unexpected extension"
                );
            }

            if (module.imageSize == 0) {
                AddRisk(
                    module,
                    15,
                    "Module reports an invalid image size"
                );
            }

            if (module.whitelisted) {
                module.riskScore = std::max(
                    0,
                    module.riskScore - 30
                );

                module.reasons.push_back(
                    "Risk reduced because module is whitelisted"
                );
            }

            /*
             * Viktigt:
             * En modul från System32 eller Program Files är inte
             * automatiskt säker. Sökvägen är bara en signal.
             *
             * Digital signatur och filhash bör kontrolleras separat.
             */
        }

        static ScopedHandle CreateModuleSnapshot(DWORD pid) {
            constexpr int maxAttempts = 5;

            for (int attempt = 0; attempt < maxAttempts; ++attempt) {
                HANDLE snapshot = CreateToolhelp32Snapshot(
                    TH32CS_SNAPMODULE |
                    TH32CS_SNAPMODULE32,
                    pid
                );

                if (snapshot != INVALID_HANDLE_VALUE) {
                    return ScopedHandle(snapshot);
                }

                const DWORD error = GetLastError();

                /*
                 * Windows kan returnera ERROR_BAD_LENGTH när
                 * modullistan förändras medan snapshoten skapas.
                 */
                if (error != ERROR_BAD_LENGTH) {
                    break;
                }

                Sleep(10);
            }

            return ScopedHandle();
        }

    public:
        static ModuleScanResult ScanModules(
            DWORD pid,
            const std::unordered_set<std::string>& allowedModules = {}
        ) {
            ModuleScanResult result{};

            if (pid == 0) {
                result.errorCode = ERROR_INVALID_PARAMETER;
                return result;
            }

            std::unordered_set<std::string> normalizedAllowedModules;

            for (const std::string& module : allowedModules) {
                normalizedAllowedModules.insert(
                    ToLower(module)
                );
            }

            ScopedHandle snapshot = CreateModuleSnapshot(pid);

            if (!snapshot.IsValid()) {
                result.errorCode = GetLastError();
                return result;
            }

            MODULEENTRY32W entry{};
            entry.dwSize = sizeof(entry);

            if (!Module32FirstW(snapshot.Get(), &entry)) {
                result.errorCode = GetLastError();
                return result;
            }

            do {
                ModuleInfo module{};

                module.processId = entry.th32ProcessID;

                module.name = WideToUtf8(
                    std::wstring(entry.szModule)
                );

                module.path = WideToUtf8(
                    std::wstring(entry.szExePath)
                );

                module.baseAddress =
                    reinterpret_cast<std::uintptr_t>(
                        entry.modBaseAddr
                    );

                module.imageSize = entry.modBaseSize;

                const std::string normalizedName =
                    ToLower(module.name);

                module.whitelisted =
                    normalizedAllowedModules.find(normalizedName) !=
                    normalizedAllowedModules.end();

                module.systemModule =
                    IsSystemPath(module.path);

                module.suspiciousPath =
                    IsSuspiciousPath(module.path);

                CalculateRisk(module);

                result.modules.push_back(std::move(module));

                entry.dwSize = sizeof(entry);

            } while (Module32NextW(snapshot.Get(), &entry));

            const DWORD finalError = GetLastError();

            /*
             * ERROR_NO_MORE_FILES är det normala resultatet när
             * alla moduler har räknats upp.
             */
            if (finalError != ERROR_NO_MORE_FILES) {
                result.errorCode = finalError;
                return result;
            }

            std::sort(
                result.modules.begin(),
                result.modules.end(),
                [](const ModuleInfo& first, const ModuleInfo& second) {
                    return first.riskScore > second.riskScore;
                }
            );

            result.errorCode = ERROR_SUCCESS;
            return result;
        }

        static std::vector<ModuleInfo> GetSuspiciousModules(
            DWORD pid,
            const std::unordered_set<std::string>& allowedModules,
            int minimumRiskScore = 20
        ) {
            ModuleScanResult scan = ScanModules(
                pid,
                allowedModules
            );

            if (!scan.Success()) {
                return {};
            }

            std::vector<ModuleInfo> suspiciousModules;

            for (ModuleInfo& module : scan.modules) {
                if (module.riskScore >= minimumRiskScore) {
                    suspiciousModules.push_back(
                        std::move(module)
                    );
                }
            }

            return suspiciousModules;
        }
    };

} // namespace Mjolnir
