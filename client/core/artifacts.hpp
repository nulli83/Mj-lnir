#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace Mjolnir {

    struct ArtifactFinding {
        std::string kind;
        std::string name;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct ArtifactScanResult {
        std::vector<ArtifactFinding> artifacts;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class ArtifactScanner {
    private:
        struct NamedArtifact {
            const wchar_t* name;
            const char* kind;
            const char* label;
            int risk;
        };

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

            WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                result.data(),
                requiredSize,
                nullptr,
                nullptr
            );

            return result;
        }

    public:
        /*
         * Letar efter kända sync-objekt och fönsterklasser som
         * ofta hör till cheat-verktyg.
         */
        static ArtifactScanResult ScanKnownArtifacts(
            int baseRiskWeight = 55
        ) {
            ArtifactScanResult result{};

            static const NamedArtifact mutexes[] = {
                {L"Cheat Engine", "mutex", "Cheat Engine", 70},
                {L"CEHYPERSCANNER", "mutex", "Cheat Engine hyperscan", 70},
                {L"WindowGUIMutex", "mutex", "Possible CE GUI mutex", 45},
                {L"DBWIN_BUFFER_READY", "mutex", "Debug output monitor", 35},
                {L"x64dbg", "mutex", "x64dbg", 65},
                {L"x32dbg", "mutex", "x32dbg", 65},
                {L"OLLYDBG", "mutex", "OllyDbg", 65},
                {L"WinDbgRemote", "mutex", "WinDbg remote", 60}
            };

            for (const NamedArtifact& artifact : mutexes) {
                HANDLE mutex = OpenMutexW(
                    SYNCHRONIZE,
                    FALSE,
                    artifact.name
                );

                if (mutex == nullptr) {
                    continue;
                }

                CloseHandle(mutex);

                ArtifactFinding finding{};
                finding.kind = artifact.kind;
                finding.name = WideToUtf8(artifact.name);
                finding.riskScore =
                    std::max(baseRiskWeight, artifact.risk);
                finding.reasons.push_back(
                    std::string("Known ") + artifact.kind +
                    " is present: " + artifact.label
                );

                result.artifacts.push_back(std::move(finding));
            }

            static const NamedArtifact windows[] = {
                {L"OLLYDBG", "window_class", "OllyDbg main window", 70},
                {L"WinDbgFrameClass", "window_class", "WinDbg frame", 65}
            };

            for (const NamedArtifact& artifact : windows) {
                HWND hwnd = FindWindowW(artifact.name, nullptr);

                if (hwnd == nullptr) {
                    continue;
                }

                ArtifactFinding finding{};
                finding.kind = artifact.kind;
                finding.name = WideToUtf8(artifact.name);
                finding.riskScore =
                    std::max(baseRiskWeight, artifact.risk);
                finding.reasons.push_back(
                    std::string("Known window class is present: ") +
                    artifact.label
                );

                result.artifacts.push_back(std::move(finding));
            }

            struct TitleSearch {
                bool found = false;
            } titleSearch;

            EnumWindows(
                [](HWND hwnd, LPARAM lParam) -> BOOL {
                    auto* search =
                        reinterpret_cast<TitleSearch*>(lParam);

                    wchar_t title[512]{};

                    if (GetWindowTextW(hwnd, title, 512) <= 0) {
                        return TRUE;
                    }

                    if (
                        wcsstr(title, L"Cheat Engine") != nullptr ||
                        wcsstr(title, L"x64dbg") != nullptr ||
                        wcsstr(title, L"x32dbg") != nullptr ||
                        wcsstr(title, L"Process Hacker") != nullptr ||
                        wcsstr(title, L"System Informer") != nullptr
                    ) {
                        search->found = true;
                        return FALSE;
                    }

                    return TRUE;
                },
                reinterpret_cast<LPARAM>(&titleSearch)
            );

            if (titleSearch.found) {
                ArtifactFinding finding{};
                finding.kind = "window_title";
                finding.name = "cheat_or_debugger_ui";
                finding.riskScore = std::max(baseRiskWeight, 65);
                finding.reasons.push_back(
                    "A cheat/debugger UI window title was detected"
                );
                result.artifacts.push_back(std::move(finding));
            }

            result.errorCode = ERROR_SUCCESS;
            return result;
        }
    };

} // namespace Mjolnir
