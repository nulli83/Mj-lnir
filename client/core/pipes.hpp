#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cctype>
#include <string>
#include <vector>

namespace Mjolnir {

    struct PipeFinding {
        std::string pipeName;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct PipeScanResult {
        std::vector<PipeFinding> findings;
        std::size_t pipesInspected = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class PipeScanner {
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

        static bool ContainsAny(
            const std::string& value,
            const std::vector<const char*>& needles
        ) {
            for (const char* needle : needles) {
                if (value.find(needle) != std::string::npos) {
                    return true;
                }
            }

            return false;
        }

    public:
        static PipeScanResult ScanSuspiciousPipes(
            int baseWeight = 50
        ) {
            PipeScanResult result{};

            WIN32_FIND_DATAW findData{};
            HANDLE find = FindFirstFileW(L"\\\\.\\pipe\\*", &findData);

            if (find == INVALID_HANDLE_VALUE) {
                result.errorCode = GetLastError();
                /*
                 * ACCESS_DENIED is common without elevation — treat as soft fail.
                 */
                if (result.errorCode == ERROR_ACCESS_DENIED) {
                    result.errorCode = ERROR_SUCCESS;
                }
                return result;
            }

            static const std::vector<const char*> suspicious = {
                "cheatengine",
                "ce-",
                "cedebugger",
                "x64dbg",
                "x32dbg",
                "ollydbg",
                "ida-",
                "ida_pro",
                "titanengine",
                "scylla",
                "extremedumper",
                "megadumper",
                "processhacker",
                "systeminformer",
                "rehollow",
                "sharpod",
                "kdmapper",
                "iqvw",
                "dbk32",
                "dbk64",
                "veiled",
                "hyperhide",
                "titanhide",
                "sandmap",
                "manualmap",
            };

            do {
                ++result.pipesInspected;
                const std::string name = ToLower(
                    [&]() {
                        char narrow[MAX_PATH] = {};
                        WideCharToMultiByte(
                            CP_UTF8,
                            0,
                            findData.cFileName,
                            -1,
                            narrow,
                            sizeof(narrow),
                            nullptr,
                            nullptr
                        );
                        return std::string(narrow);
                    }()
                );

                if (name.empty() || name == "mjolnir_ipc") {
                    continue;
                }

                if (!ContainsAny(name, suspicious)) {
                    continue;
                }

                PipeFinding finding{};
                finding.pipeName = name;
                finding.riskScore = baseWeight;
                finding.reasons.push_back(
                    "Named pipe matches known cheat/debug tooling pattern"
                );
                result.findings.push_back(std::move(finding));
            } while (FindNextFileW(find, &findData));

            FindClose(find);
            return result;
        }
    };

} // namespace Mjolnir
