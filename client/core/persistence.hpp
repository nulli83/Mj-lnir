#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cctype>
#include <string>
#include <vector>

namespace Mjolnir {

    struct PersistenceFinding {
        std::string location;
        std::string value;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct PersistenceScanResult {
        std::vector<PersistenceFinding> findings;
        std::size_t keysInspected = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    /*
     * Skannar vanliga autostart-platser efter kända cheat/debug-strängar.
     */
    class PersistenceScanner {
    private:
        static std::string ToLower(std::string value) {
            for (char& character : value) {
                character = static_cast<char>(
                    std::tolower(static_cast<unsigned char>(character))
                );
            }
            return value;
        }

        static bool LooksSuspicious(const std::string& haystack) {
            static const char* needles[] = {
                "cheatengine",
                "cheat engine",
                "x64dbg",
                "x32dbg",
                "ollydbg",
                "ida64",
                "ida.exe",
                "processhacker",
                "systeminformer",
                "extreme injector",
                "extremeinjector",
                "sharpod",
                "kdmapper",
                "vacbypass",
                "spoofer",
                "hwid",
                "aimbot",
                "wallhack",
                "esp.exe",
                "reclass",
                "megadumper",
                "scyllahide",
                "titanhide",
                "hyperhide",
            };

            for (const char* needle : needles) {
                if (haystack.find(needle) != std::string::npos) {
                    return true;
                }
            }

            return false;
        }

        static void ScanRunKey(
            HKEY root,
            const wchar_t* subKey,
            const char* label,
            int baseWeight,
            PersistenceScanResult& result
        ) {
            HKEY key = nullptr;
            if (
                RegOpenKeyExW(
                    root,
                    subKey,
                    0,
                    KEY_READ | KEY_WOW64_64KEY,
                    &key
                ) != ERROR_SUCCESS
            ) {
                return;
            }

            for (DWORD index = 0; ; ++index) {
                wchar_t name[256] = {};
                wchar_t data[1024] = {};
                DWORD nameSize = static_cast<DWORD>(std::size(name));
                DWORD dataSize = static_cast<DWORD>(sizeof(data));
                DWORD type = 0;

                const LONG status = RegEnumValueW(
                    key,
                    index,
                    name,
                    &nameSize,
                    nullptr,
                    &type,
                    reinterpret_cast<LPBYTE>(data),
                    &dataSize
                );

                if (status == ERROR_NO_MORE_ITEMS) {
                    break;
                }

                if (status != ERROR_SUCCESS) {
                    continue;
                }

                ++result.keysInspected;

                if (type != REG_SZ && type != REG_EXPAND_SZ) {
                    continue;
                }

                char nameUtf8[256] = {};
                char dataUtf8[1024] = {};
                WideCharToMultiByte(
                    CP_UTF8, 0, name, -1, nameUtf8, sizeof(nameUtf8), nullptr, nullptr
                );
                WideCharToMultiByte(
                    CP_UTF8, 0, data, -1, dataUtf8, sizeof(dataUtf8), nullptr, nullptr
                );

                const std::string combined = ToLower(
                    std::string(nameUtf8) + " " + dataUtf8
                );

                if (!LooksSuspicious(combined)) {
                    continue;
                }

                PersistenceFinding finding{};
                finding.location = label;
                finding.value = std::string(nameUtf8) + "=" + dataUtf8;
                finding.riskScore = baseWeight;
                finding.reasons.push_back(
                    "Autorun entry matches known cheat/debug tooling pattern"
                );
                result.findings.push_back(std::move(finding));
            }

            RegCloseKey(key);
        }

        static void ScanAppInit(
            int baseWeight,
            PersistenceScanResult& result
        ) {
            HKEY key = nullptr;
            if (
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                    0,
                    KEY_READ | KEY_WOW64_64KEY,
                    &key
                ) != ERROR_SUCCESS
            ) {
                return;
            }

            ++result.keysInspected;

            wchar_t data[1024] = {};
            DWORD dataSize = static_cast<DWORD>(sizeof(data));
            DWORD type = 0;
            if (
                RegQueryValueExW(
                    key,
                    L"AppInit_DLLs",
                    nullptr,
                    &type,
                    reinterpret_cast<LPBYTE>(data),
                    &dataSize
                ) == ERROR_SUCCESS &&
                (type == REG_SZ || type == REG_EXPAND_SZ)
            ) {
                char utf8[1024] = {};
                WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    data,
                    -1,
                    utf8,
                    sizeof(utf8),
                    nullptr,
                    nullptr
                );

                std::string value = utf8;
                while (
                    !value.empty() &&
                    std::isspace(static_cast<unsigned char>(value.front()))
                ) {
                    value.erase(value.begin());
                }

                if (!value.empty()) {
                    PersistenceFinding finding{};
                    finding.location = "HKLM\\...\\Windows\\AppInit_DLLs";
                    finding.value = value;
                    finding.riskScore = baseWeight + 15;
                    finding.reasons.push_back(
                        "Non-empty AppInit_DLLs (classic DLL injection persistence)"
                    );
                    result.findings.push_back(std::move(finding));
                }
            }

            RegCloseKey(key);
        }

        static void ScanIfeoDebuggers(
            int baseWeight,
            PersistenceScanResult& result
        ) {
            HKEY root = nullptr;
            if (
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    L"Software\\Microsoft\\Windows NT\\CurrentVersion\\"
                    L"Image File Execution Options",
                    0,
                    KEY_READ | KEY_WOW64_64KEY,
                    &root
                ) != ERROR_SUCCESS
            ) {
                return;
            }

            for (DWORD index = 0; ; ++index) {
                wchar_t subName[256] = {};
                DWORD subNameSize = static_cast<DWORD>(std::size(subName));
                const LONG enumStatus = RegEnumKeyExW(
                    root,
                    index,
                    subName,
                    &subNameSize,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr
                );

                if (enumStatus == ERROR_NO_MORE_ITEMS) {
                    break;
                }
                if (enumStatus != ERROR_SUCCESS) {
                    continue;
                }

                ++result.keysInspected;

                HKEY sub = nullptr;
                if (
                    RegOpenKeyExW(
                        root,
                        subName,
                        0,
                        KEY_READ | KEY_WOW64_64KEY,
                        &sub
                    ) != ERROR_SUCCESS
                ) {
                    continue;
                }

                wchar_t debugger[1024] = {};
                DWORD debuggerSize = static_cast<DWORD>(sizeof(debugger));
                DWORD type = 0;
                const LONG queryStatus = RegQueryValueExW(
                    sub,
                    L"Debugger",
                    nullptr,
                    &type,
                    reinterpret_cast<LPBYTE>(debugger),
                    &debuggerSize
                );
                RegCloseKey(sub);

                if (
                    queryStatus != ERROR_SUCCESS ||
                    (type != REG_SZ && type != REG_EXPAND_SZ)
                ) {
                    continue;
                }

                char nameUtf8[256] = {};
                char debuggerUtf8[1024] = {};
                WideCharToMultiByte(
                    CP_UTF8, 0, subName, -1, nameUtf8, sizeof(nameUtf8), nullptr, nullptr
                );
                WideCharToMultiByte(
                    CP_UTF8,
                    0,
                    debugger,
                    -1,
                    debuggerUtf8,
                    sizeof(debuggerUtf8),
                    nullptr,
                    nullptr
                );

                const std::string combined = ToLower(
                    std::string(nameUtf8) + " " + debuggerUtf8
                );

                PersistenceFinding finding{};
                finding.location = "HKLM\\...\\IFEO\\" + std::string(nameUtf8);
                finding.value = std::string("Debugger=") + debuggerUtf8;
                finding.riskScore = baseWeight + 20;
                if (LooksSuspicious(combined)) {
                    finding.reasons.push_back(
                        "IFEO Debugger matches cheat/debug tooling pattern"
                    );
                } else {
                    finding.reasons.push_back(
                        "IFEO Debugger redirect present (process hijack vector)"
                    );
                }
                result.findings.push_back(std::move(finding));
            }

            RegCloseKey(root);
        }

    public:
        static PersistenceScanResult Scan(int baseWeight = 50) {
            PersistenceScanResult result{};

            ScanRunKey(
                HKEY_CURRENT_USER,
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\...\\Run",
                baseWeight,
                result
            );
            ScanRunKey(
                HKEY_LOCAL_MACHINE,
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\...\\Run",
                baseWeight + 10,
                result
            );
            ScanRunKey(
                HKEY_CURRENT_USER,
                L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKCU\\...\\RunOnce",
                baseWeight,
                result
            );
            ScanRunKey(
                HKEY_LOCAL_MACHINE,
                L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKLM\\...\\RunOnce",
                baseWeight + 10,
                result
            );

            ScanAppInit(baseWeight, result);
            ScanIfeoDebuggers(baseWeight, result);

            return result;
        }
    };

} // namespace Mjolnir
