#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <bcrypt.h>

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace Mjolnir {

    class IpcClient {
    private:
        HANDLE pipe_ = INVALID_HANDLE_VALUE;
        std::wstring pipeName_ = L"\\\\.\\pipe\\mjolnir_ipc";
        mutable std::mutex mutex_;
        std::string hmacSecret_;
        std::uint64_t nonce_ = 0;

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

        static std::string BytesToHex(
            const std::uint8_t* data,
            std::size_t length
        ) {
            static constexpr char kHex[] = "0123456789abcdef";
            std::string hex;
            hex.resize(length * 2);

            for (std::size_t index = 0; index < length; ++index) {
                hex[index * 2] =
                    kHex[(data[index] >> 4) & 0x0F];
                hex[index * 2 + 1] =
                    kHex[data[index] & 0x0F];
            }

            return hex;
        }

        static bool HmacSha256Hex(
            const std::string& secret,
            const std::string& message,
            std::string& outHex
        ) {
            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            bool ok = false;

            const NTSTATUS openStatus = BCryptOpenAlgorithmProvider(
                &algorithm,
                BCRYPT_SHA256_ALGORITHM,
                nullptr,
                BCRYPT_ALG_HANDLE_HMAC_FLAG
            );

            if (openStatus < 0 || algorithm == nullptr) {
                return false;
            }

            DWORD hashLength = 0;
            DWORD bytesCopied = 0;

            if (
                BCryptGetProperty(
                    algorithm,
                    BCRYPT_HASH_LENGTH,
                    reinterpret_cast<PUCHAR>(&hashLength),
                    sizeof(hashLength),
                    &bytesCopied,
                    0
                ) < 0 ||
                hashLength == 0
            ) {
                BCryptCloseAlgorithmProvider(algorithm, 0);
                return false;
            }

            std::vector<std::uint8_t> digest(hashLength);

            if (
                BCryptCreateHash(
                    algorithm,
                    &hash,
                    nullptr,
                    0,
                    reinterpret_cast<PUCHAR>(
                        const_cast<char*>(secret.data())
                    ),
                    static_cast<ULONG>(secret.size()),
                    0
                ) >= 0 &&
                hash != nullptr &&
                BCryptHashData(
                    hash,
                    reinterpret_cast<PUCHAR>(
                        const_cast<char*>(message.data())
                    ),
                    static_cast<ULONG>(message.size()),
                    0
                ) >= 0 &&
                BCryptFinishHash(
                    hash,
                    digest.data(),
                    hashLength,
                    0
                ) >= 0
            ) {
                outHex = BytesToHex(digest.data(), digest.size());
                ok = true;
            }

            if (hash != nullptr) {
                BCryptDestroyHash(hash);
            }

            BCryptCloseAlgorithmProvider(algorithm, 0);
            return ok;
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

        void SetHmacSecret(std::string secret) {
            std::lock_guard<std::mutex> lock(mutex_);
            hmacSecret_ = std::move(secret);
        }

        bool HasHmacSecret() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return !hmacSecret_.empty();
        }

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
            const auto now = std::chrono::system_clock::now();
            const auto unixSeconds =
                std::chrono::duration_cast<std::chrono::seconds>(
                    now.time_since_epoch()
                ).count();

            std::uint64_t nonce = 0;
            std::string secret;

            {
                std::lock_guard<std::mutex> lock(mutex_);
                nonce = ++nonce_;
                secret = hmacSecret_;
            }

            std::ostringstream canonical;
            canonical
                << "1|"
                << unixSeconds << '|'
                << nonce << '|'
                << level << '|'
                << category << '|'
                << details << '|'
                << pid << '|'
                << riskScore;

            std::string macHex;
            const bool signedFrame =
                !secret.empty() &&
                HmacSha256Hex(secret, canonical.str(), macHex);

            std::ostringstream json;

            json
                << '{'
                << "\"v\":1,"
                << "\"ts\":" << unixSeconds << ','
                << "\"n\":" << nonce << ','
                << "\"level\":\"" << EscapeJson(level) << "\","
                << "\"category\":\""
                << EscapeJson(category) << "\","
                << "\"details\":\""
                << EscapeJson(details) << "\","
                << "\"pid\":" << pid << ','
                << "\"risk_score\":" << riskScore;

            if (signedFrame) {
                json << ",\"mac\":\"" << macHex << '"';
            }

            json << "}\n";

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
