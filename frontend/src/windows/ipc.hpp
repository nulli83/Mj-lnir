#pragma once

#include <windows.h>
#include <string>
#include <iostream>

namespace Mjolnir {

    class IpcClient {
    private:
        HANDLE hPipe = INVALID_HANDLE_VALUE;
        std::wstring pipeName = L"\\\\.\\pipe\\mjolnir_ipc";

    public:
        bool Connect() {
            hPipe = CreateFileW(
                pipeName.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            );

            return hPipe != INVALID_HANDLE_VALUE;
        }

        // Serializes security telemetry into a clean JSON payload string
        bool SendJsonAlert(const std::string& level, const std::string& category, const std::string& details, DWORD pid) {
            if (hPipe == INVALID_HANDLE_VALUE) {
                if (!Connect()) return false;
            }

            // Manual JSON construction to maintain a dependency-free C++ core
            std::string jsonPayload = "{"
                "\"level\":\"" + level + "\","
                "\"category\":\"" + category + "\","
                "\"details\":\"" + details + "\","
                "\"pid\":" + std::to_string(pid) +
            "}";

            DWORD bytesWritten = 0;
            BOOL success = WriteFile(
                hPipe,
                jsonPayload.c_str(),
                static_cast<DWORD>(jsonPayload.size()),
                &bytesWritten,
                NULL
            );

            if (!success) {
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
                return false;
            }

            return true;
        }

        ~IpcClient() {
            if (hPipe != INVALID_HANDLE_VALUE) {
                CloseHandle(hPipe);
            }
        }
    };

} // namespace Mjolnir
