#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <chrono>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

namespace Mjolnir {

    class IpcClient {
    private:
        HANDLE pipe_ = INVALID_HANDLE_VALUE;
        std::wstring pipeName_ = L"\\\\.\\pipe\\mjolnir_ipc";
        mutable std::mutex mutex_;

        static std::string EscapeJson(const std::string& value) {
            std::ostringstream escaped;

            for (unsigned char character : value) {
                switch (character) {
                    case '"':
                        escaped << "\\\"";
                        break;
                    case '\\':
                        escaped << "\\\\";
                        break;
                    case '\b':
                        escaped << "\\b";
                        break;
                    case '\f':
                        escaped << "\\f";
                        break;
                    case '\n':
                        escaped << "\\n";
                        break;
                    case '\r':
                        escaped << "\\r";
                        break;
                    case '\t':
                        escaped << "\\t";
                        break;
                    default:
                        if (character < 0x20) {
                            escaped
                                << "\\u"
                                << std::hex
                                << std::setw(4)
                                << std::setfill('0')
                                << static_cast<int>(character)
                                << std::dec;
                        } else {
                            escaped << static_cast<char>(
                                character
                            );
                        }
                        break;
                }
            }

            return escaped.str();
        }

        void DisconnectLocked() {
            if (pipe_ != INVALID_HANDLE_VALUE) {
                CloseHandle(pipe_);
                pipe_ = INVALID_HANDLE_VALUE;
            }
        }

        bool ConnectLocked() {
            if (pipe_ != INVALID_HANDLE_VALUE) {
                return true;
            }

            for (int attempt = 0; attempt < 5; ++attempt) {
                pipe_ = CreateFileW(
                    pipeName_.c_str(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    nullptr,
                    OPEN_EXISTING,
                    0,
                    nullptr
                );

                if (pipe_ != INVALID_HANDLE_VALUE) {
                    DWORD mode = PIPE_READMODE_BYTE;
                    SetNamedPipeHandleState(
                        pipe_,
                        &mode,
                        nullptr,
                        nullptr
                    );
                    return true;
                }

                const DWORD error = GetLastError();

                if (error == ERROR_PIPE_BUSY) {
                    WaitNamedPipeW(pipeName_.c_str(), 1000);
                    continue;
                }

                if (error == ERROR_FILE_NOT_FOUND) {
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(150)
                    );
                    continue;
                }

                break;
            }

            return false;
        }

    public:
        IpcClient() = default;

        explicit IpcClient(std::wstring pipeName)
            : pipeName_(std::move(pipeName)) {}

        IpcClient(const IpcClient&) = delete;
        IpcClient& operator=(const IpcClient&) = delete;

        bool Connect() {
            std::lock_guard<std::mutex> lock(mutex_);
            return ConnectLocked();
        }

        bool IsConnected() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return pipe_ != INVALID_HANDLE_VALUE;
        }

        bool SendJsonAlert(
            const std::string& level,
            const std::string& category,
            const std::string& details,
            DWORD pid,
            int riskScore = 0
        ) {
            std::ostringstream json;

            json
                << '{'
                << "\"level\":\"" << EscapeJson(level) << "\","
                << "\"category\":\""
                << EscapeJson(category) << "\","
                << "\"details\":\""
                << EscapeJson(details) << "\","
                << "\"pid\":" << pid << ','
                << "\"risk_score\":" << riskScore
                << "}\n";

            const std::string payload = json.str();

            std::lock_guard<std::mutex> lock(mutex_);

            if (!ConnectLocked()) {
                return false;
            }

            DWORD bytesWritten = 0;

            const BOOL success = WriteFile(
                pipe_,
                payload.data(),
                static_cast<DWORD>(payload.size()),
                &bytesWritten,
                nullptr
            );

            if (
                !success ||
                bytesWritten != payload.size()
            ) {
                DisconnectLocked();
                return false;
            }

            return true;
        }

        void Disconnect() {
            std::lock_guard<std::mutex> lock(mutex_);
            DisconnectLocked();
        }

        ~IpcClient() {
            Disconnect();
        }
    };

} // namespace Mjolnir
