#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <cstdint>
#include <cctype>
#include <string>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "ntdll.lib")

namespace Mjolnir {

    struct ParentProcessInfo {
        DWORD parentProcessId = 0;
        std::string parentProcessName;
        std::string parentProcessPath;
        std::string imagePath;

        bool resolved = false;
        bool parentResolved = false;
        bool insideExpectedRoot = false;

        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    class ProcessInspector {
    private:
        struct ProcessBasicInformationLocal {
            NTSTATUS ExitStatus;
            PVOID PebBaseAddress;
            ULONG_PTR AffinityMask;
            LONG BasePriority;
            ULONG_PTR UniqueProcessId;
            ULONG_PTR InheritedFromUniqueProcessId;
        };

        using NtQueryInformationProcessFn =
            NTSTATUS(NTAPI*)(
                HANDLE ProcessHandle,
                PROCESSINFOCLASS ProcessInformationClass,
                PVOID ProcessInformation,
                ULONG ProcessInformationLength,
                PULONG ReturnLength
            );

        static std::string ToLower(std::string value) {
            for (char& character : value) {
                character = static_cast<char>(
                    std::tolower(
                        static_cast<unsigned char>(character)
                    )
                );
            }

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

        static std::string GetBaseName(const std::string& path) {
            const std::size_t separator =
                path.find_last_of("\\/");

            if (separator == std::string::npos) {
                return path;
            }

            return path.substr(separator + 1);
        }

        static std::string ResolveProcessPath(DWORD pid) {
            HANDLE process = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                pid
            );

            if (process == nullptr) {
                return {};
            }

            std::wstring path(32768, L'\0');
            DWORD pathLength =
                static_cast<DWORD>(path.size());

            const BOOL ok = QueryFullProcessImageNameW(
                process,
                0,
                path.data(),
                &pathLength
            );

            CloseHandle(process);

            if (!ok) {
                return {};
            }

            path.resize(pathLength);
            return WideToUtf8(path);
        }

        static bool StartsWithInsensitive(
            const std::string& value,
            const std::string& prefix
        ) {
            if (value.size() < prefix.size()) {
                return false;
            }

            for (std::size_t index = 0;
                 index < prefix.size();
                 ++index) {
                const auto left = static_cast<unsigned char>(
                    value[index]
                );
                const auto right = static_cast<unsigned char>(
                    prefix[index]
                );

                if (std::tolower(left) != std::tolower(right)) {
                    return false;
                }
            }

            return true;
        }

    public:
        static ParentProcessInfo InspectTarget(
            HANDLE processHandle,
            DWORD targetPid,
            const std::vector<std::string>& expectedRoots,
            const std::unordered_set<std::string>&
                trustedParents,
            int unknownProcessWeight = 10
        ) {
            ParentProcessInfo info{};

            if (
                processHandle == nullptr ||
                processHandle == INVALID_HANDLE_VALUE ||
                targetPid == 0
            ) {
                return info;
            }

            info.imagePath = ResolveProcessPath(targetPid);
            info.resolved = !info.imagePath.empty();

            if (!info.resolved) {
                info.riskScore += 15;
                info.reasons.push_back(
                    "Could not resolve target image path"
                );
            } else if (!expectedRoots.empty()) {
                const std::string normalizedImage =
                    ToLower(info.imagePath);

                for (const std::string& root : expectedRoots) {
                    if (
                        StartsWithInsensitive(
                            normalizedImage,
                            ToLower(root)
                        )
                    ) {
                        info.insideExpectedRoot = true;
                        break;
                    }
                }

                if (!info.insideExpectedRoot) {
                    info.riskScore += 20;
                    info.reasons.push_back(
                        "Target image is outside expected install roots"
                    );
                }
            }

            auto* ntQuery =
                reinterpret_cast<NtQueryInformationProcessFn>(
                    GetProcAddress(
                        GetModuleHandleW(L"ntdll.dll"),
                        "NtQueryInformationProcess"
                    )
                );

            if (ntQuery != nullptr) {
                ProcessBasicInformationLocal basic{};
                const NTSTATUS status = ntQuery(
                    processHandle,
                    ProcessBasicInformation,
                    &basic,
                    sizeof(basic),
                    nullptr
                );

                if (NT_SUCCESS(status)) {
                    info.parentProcessId = static_cast<DWORD>(
                        basic.InheritedFromUniqueProcessId
                    );
                }
            }

            if (info.parentProcessId == 0) {
                info.riskScore += 10;
                info.reasons.push_back(
                    "Parent process could not be resolved"
                );
                return info;
            }

            info.parentProcessPath =
                ResolveProcessPath(info.parentProcessId);
            info.parentProcessName =
                GetBaseName(info.parentProcessPath);
            info.parentResolved =
                !info.parentProcessName.empty();

            if (!info.parentResolved) {
                info.riskScore += unknownProcessWeight + 5;
                info.reasons.push_back(
                    "Parent process image could not be opened"
                );
                return info;
            }

            const std::string normalizedParent =
                ToLower(info.parentProcessName);

            static const std::unordered_set<std::string>
                defaultTrustedParents = {
                    "explorer.exe",
                    "cmd.exe",
                    "powershell.exe",
                    "pwsh.exe",
                    "steam.exe",
                    "steamwebhelper.exe",
                    "epicgameslauncher.exe",
                    "origin.exe",
                    "eadesktop.exe",
                    "upc.exe",
                    "ubisoftconnect.exe",
                    "battlenet.exe",
                    "agent.exe",
                    "riotclientservices.exe",
                    "galaxyclient.exe",
                    "services.exe",
                    "svchost.exe"
                };

            const bool trusted =
                trustedParents.find(normalizedParent) !=
                    trustedParents.end() ||
                defaultTrustedParents.find(normalizedParent) !=
                    defaultTrustedParents.end();

            if (!trusted) {
                info.riskScore += unknownProcessWeight + 15;
                info.reasons.push_back(
                    "Parent process '" +
                    info.parentProcessName +
                    "' is not a known launcher/shell"
                );
            }

            return info;
        }
    };

} // namespace Mjolnir
