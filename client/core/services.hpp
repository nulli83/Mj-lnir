#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cctype>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif

namespace Mjolnir {

    struct ServiceFinding {
        std::string serviceName;
        std::string displayName;
        DWORD state = 0;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct ServiceScanResult {
        std::vector<ServiceFinding> services;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class ServiceScanner {
    private:
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

    public:
        static ServiceScanResult ScanSuspiciousServices(
            int baseRiskWeight = 60
        ) {
            ServiceScanResult result{};

            SC_HANDLE manager = OpenSCManagerW(
                nullptr,
                nullptr,
                SC_MANAGER_ENUMERATE_SERVICE
            );

            if (manager == nullptr) {
                result.errorCode = GetLastError();
                return result;
            }

            DWORD bytesNeeded = 0;
            DWORD serviceCount = 0;
            DWORD resumeHandle = 0;

            EnumServicesStatusExW(
                manager,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32 | SERVICE_DRIVER,
                SERVICE_STATE_ALL,
                nullptr,
                0,
                &bytesNeeded,
                &serviceCount,
                &resumeHandle,
                nullptr
            );

            if (bytesNeeded == 0) {
                CloseServiceHandle(manager);
                result.errorCode = GetLastError();
                return result;
            }

            std::vector<std::uint8_t> buffer(bytesNeeded);
            resumeHandle = 0;

            if (
                !EnumServicesStatusExW(
                    manager,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32 | SERVICE_DRIVER,
                    SERVICE_STATE_ALL,
                    buffer.data(),
                    bytesNeeded,
                    &bytesNeeded,
                    &serviceCount,
                    &resumeHandle,
                    nullptr
                )
            ) {
                result.errorCode = GetLastError();
                CloseServiceHandle(manager);
                return result;
            }

            static const char* suspiciousOnly[] = {
                "capcom",
                "msio",
                "asio2",
                "gdrv",
                "glckio2",
                "dbutil",
                "iqvw64e",
                "winio",
                "rtcore64",
                "rtcore32",
                "echo_driver",
                "kdmapper",
                "processhacker",
                "kprocesshacker"
            };

            auto* entries =
                reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(
                    buffer.data()
                );

            for (DWORD index = 0; index < serviceCount; ++index) {
                const std::string serviceName = ToLower(
                    WideToUtf8(
                        entries[index].lpServiceName
                            ? entries[index].lpServiceName
                            : L""
                    )
                );

                const std::string displayName = ToLower(
                    WideToUtf8(
                        entries[index].lpDisplayName
                            ? entries[index].lpDisplayName
                            : L""
                    )
                );

                bool matched = false;

                for (const char* needle : suspiciousOnly) {
                    if (
                        serviceName.find(needle) !=
                            std::string::npos ||
                        displayName.find(needle) !=
                            std::string::npos
                    ) {
                        matched = true;
                        break;
                    }
                }

                if (!matched) {
                    continue;
                }

                ServiceFinding finding{};
                finding.serviceName = serviceName;
                finding.displayName = displayName;
                finding.state =
                    entries[index]
                        .ServiceStatusProcess
                        .dwCurrentState;
                finding.riskScore = baseRiskWeight;

                if (
                    finding.state == SERVICE_RUNNING ||
                    finding.state == SERVICE_START_PENDING
                ) {
                    finding.riskScore += 15;
                    finding.reasons.push_back(
                        "Suspicious service is running"
                    );
                } else {
                    finding.reasons.push_back(
                        "Suspicious service is installed"
                    );
                }

                result.services.push_back(std::move(finding));
            }

            CloseServiceHandle(manager);
            result.errorCode = ERROR_SUCCESS;
            return result;
        }
    };

} // namespace Mjolnir
