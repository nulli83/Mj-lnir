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
            // Try to connect to the Rust orchestrator named pipe server
            hPipe = CreateFileW(
                pipeName.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            );

            if (hPipe == INVALID_HANDLE_VALUE) {
                return false; // Orchestrator might not be running yet
            }

            // Change pipe read mode to message-type mode if needed
            DWORD dwMode = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);

            return true;
        }

        bool SendAlert(const std::string& message) {
            if (hPipe == INVALID_HANDLE_VALUE) {
                if (!Connect()) return false;
            }

            DWORD bytesWritten = 0;
            BOOL success = WriteFile(
                hPipe,
                message.c_str(),
                static_cast<DWORD>(message.size()),
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
