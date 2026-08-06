#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <psapi.h>

#include <cctype>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "psapi.lib")
#endif

namespace Mjolnir {

    struct DeviceFinding {
        std::string devicePath;
        std::string label;
        bool present = false;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct DriverFinding {
        std::string imagePath;
        std::string baseName;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct DeviceScanResult {
        std::vector<DeviceFinding> devices;
        std::vector<DriverFinding> drivers;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class DeviceScanner {
    private:
        struct KnownDevice {
            const wchar_t* path;
            const char* label;
            int risk;
        };

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

        static bool DeviceExists(const wchar_t* path) {
            HANDLE handle = CreateFileW(
                path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr
            );

            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
                return true;
            }

            const DWORD error = GetLastError();

            /*
             * Access denied betyder ofta att enheten finns
             * men kräver högre privilegier.
             */
            return
                error == ERROR_ACCESS_DENIED ||
                error == ERROR_SHARING_VIOLATION;
        }

    public:
        static DeviceScanResult ScanKnownThreats(
            int deviceRiskWeight = 70,
            int driverRiskWeight = 60
        ) {
            DeviceScanResult result{};

            static const KnownDevice knownDevices[] = {
                {L"\\\\.\\Capcom", "Capcom vulnerable driver", 90},
                {L"\\\\.\\MsIo64", "MsIo vulnerable driver", 85},
                {L"\\\\.\\MsIo32", "MsIo vulnerable driver", 85},
                {L"\\\\.\\AsIO", "ASUS AsIO vulnerable driver", 80},
                {L"\\\\.\\AsIO2", "ASUS AsIO2 vulnerable driver", 80},
                {L"\\\\.\\GLCKIO2", "Gigabyte GLCKIO2", 80},
                {L"\\\\.\\gdrv", "Gigabyte gdrv", 80},
                {L"\\\\.\\Athral", "Atheros Athral", 75},
                {L"\\\\.\\DBUtil_2_3", "Dell DBUtil", 85},
                {L"\\\\.\\DBUtilDrv2", "Dell DBUtilDrv2", 85},
                {L"\\\\.\\iqvw64e", "Intel Network Adapter diagnostic", 80},
                {L"\\\\.\\Nal", "Intel Nal", 80},
                {L"\\\\.\\WinIO", "WinIO direct port IO", 85},
                {L"\\\\.\\WinIO64", "WinIO64 direct port IO", 85},
                {L"\\\\.\\PhysMem", "Physical memory device", 90},
                {L"\\\\.\\PhysicalMemory", "Physical memory section", 90},
                {L"\\\\.\\amsdk", "AMD amsdk", 75},
                {L"\\\\.\\Hwinfo64aio", "HWiNFO kernel IO", 50},
                {L"\\\\.\\RTCore64", "MSI RTCore64", 85},
                {L"\\\\.\\RTCore32", "MSI RTCore32", 85}
            };

            for (const KnownDevice& device : knownDevices) {
                if (!DeviceExists(device.path)) {
                    continue;
                }

                DeviceFinding finding{};
                finding.devicePath = WideToUtf8(device.path);
                finding.label = device.label;
                finding.present = true;
                finding.riskScore =
                    deviceRiskWeight > device.risk
                        ? deviceRiskWeight
                        : device.risk;
                finding.reasons.push_back(
                    "Known risky kernel device is present: " +
                    finding.label
                );

                result.devices.push_back(std::move(finding));
            }

            /*
             * EnumDeviceDrivers ger laddade kernel-images.
             * Vi flaggar några kända cheat/vuln-drivrutiner.
             */
            DWORD bytesNeeded = 0;
            EnumDeviceDrivers(nullptr, 0, &bytesNeeded);

            if (bytesNeeded > 0) {
                const DWORD count =
                    bytesNeeded / sizeof(LPVOID);

                std::vector<LPVOID> drivers(count);
                DWORD bytesReturned = 0;

                if (
                    EnumDeviceDrivers(
                        drivers.data(),
                        bytesNeeded,
                        &bytesReturned
                    )
                ) {
                    static const char* suspiciousNames[] = {
                        "capcom.sys",
                        "msio64.sys",
                        "msio32.sys",
                        "asio.sys",
                        "asio2.sys",
                        "gdrv.sys",
                        "glckio2.sys",
                        "dbutil_2_3.sys",
                        "dbutildrv2.sys",
                        "iqvw64e.sys",
                        "winio64.sys",
                        "winio32.sys",
                        "rtcore64.sys",
                        "rtcore32.sys",
                        "echo_driver.sys",
                        "pmdriver64.sys",
                        "kdmapper.sys"
                    };

                    char pathBuffer[MAX_PATH]{};

                    for (DWORD index = 0;
                         index < bytesReturned / sizeof(LPVOID);
                         ++index) {
                        if (
                            !GetDeviceDriverFileNameA(
                                drivers[index],
                                pathBuffer,
                                MAX_PATH
                            )
                        ) {
                            continue;
                        }

                        const std::string path =
                            ToLower(pathBuffer);
                        const std::string baseName =
                            GetBaseName(path);

                        for (const char* suspicious :
                             suspiciousNames) {
                            if (baseName == suspicious) {
                                DriverFinding finding{};
                                finding.imagePath = path;
                                finding.baseName = baseName;
                                finding.riskScore =
                                    driverRiskWeight;
                                finding.reasons.push_back(
                                    "Loaded kernel driver matches known risky image"
                                );

                                result.drivers.push_back(
                                    std::move(finding)
                                );
                                break;
                            }
                        }
                    }
                }
            }

            result.errorCode = ERROR_SUCCESS;
            return result;
        }
    };

} // namespace Mjolnir
