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

            return result;
        }
    };

} // namespace Mjolnir
