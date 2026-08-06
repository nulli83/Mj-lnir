#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstdint>
#include <string>

namespace Mjolnir {

    /*
     * Delad heartbeat mellan mjolnir_core och mjolnir_watchdog.
     */
    struct TwinHeartbeat {
        std::uint64_t coreHeartbeat;
        std::uint64_t watchdogHeartbeat;
        DWORD corePid;
        DWORD watchdogPid;
        std::uint64_t magic;
    };

    inline constexpr std::uint64_t kTwinMagic = 0x4D4A4C4E52545744ULL; // MJLNRTWD
    inline constexpr wchar_t kTwinMappingName[] = L"Local\\MjolnirTwinHeartbeat";
    inline constexpr wchar_t kTwinMutexName[] = L"Local\\MjolnirTwinMutex";

    class TwinWatchdogClient {
    private:
        HANDLE mapping_ = nullptr;
        HANDLE mutex_ = nullptr;
        TwinHeartbeat* view_ = nullptr;
        bool createdMapping_ = false;

    public:
        TwinWatchdogClient() = default;

        TwinWatchdogClient(const TwinWatchdogClient&) = delete;
        TwinWatchdogClient& operator=(const TwinWatchdogClient&) = delete;

        ~TwinWatchdogClient() {
            Close();
        }

        bool OpenOrCreate(bool asCore) {
            Close();

            mutex_ = CreateMutexW(nullptr, FALSE, kTwinMutexName);

            if (mutex_ == nullptr) {
                return false;
            }

            mapping_ = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                nullptr,
                PAGE_READWRITE,
                0,
                sizeof(TwinHeartbeat),
                kTwinMappingName
            );

            if (mapping_ == nullptr) {
                return false;
            }

            createdMapping_ = GetLastError() != ERROR_ALREADY_EXISTS;

            view_ = static_cast<TwinHeartbeat*>(
                MapViewOfFile(
                    mapping_,
                    FILE_MAP_ALL_ACCESS,
                    0,
                    0,
                    sizeof(TwinHeartbeat)
                )
            );

            if (view_ == nullptr) {
                return false;
            }

            WaitForSingleObject(mutex_, INFINITE);

            if (createdMapping_ || view_->magic != kTwinMagic) {
                view_->magic = kTwinMagic;
                view_->coreHeartbeat = 0;
                view_->watchdogHeartbeat = 0;
                view_->corePid = 0;
                view_->watchdogPid = 0;
            }

            if (asCore) {
                view_->corePid = GetCurrentProcessId();
            } else {
                view_->watchdogPid = GetCurrentProcessId();
            }

            ReleaseMutex(mutex_);
            return true;
        }

        void PulseCore() {
            if (view_ == nullptr || mutex_ == nullptr) {
                return;
            }

            WaitForSingleObject(mutex_, INFINITE);
            ++view_->coreHeartbeat;
            view_->corePid = GetCurrentProcessId();
            ReleaseMutex(mutex_);
        }

        void PulseWatchdog() {
            if (view_ == nullptr || mutex_ == nullptr) {
                return;
            }

            WaitForSingleObject(mutex_, INFINITE);
            ++view_->watchdogHeartbeat;
            view_->watchdogPid = GetCurrentProcessId();
            ReleaseMutex(mutex_);
        }

        TwinHeartbeat Snapshot() const {
            TwinHeartbeat copy{};

            if (view_ == nullptr || mutex_ == nullptr) {
                return copy;
            }

            WaitForSingleObject(mutex_, INFINITE);
            copy = *view_;
            ReleaseMutex(mutex_);
            return copy;
        }

        void Close() {
            if (view_ != nullptr) {
                UnmapViewOfFile(view_);
                view_ = nullptr;
            }

            if (mapping_ != nullptr) {
                CloseHandle(mapping_);
                mapping_ = nullptr;
            }

            if (mutex_ != nullptr) {
                CloseHandle(mutex_);
                mutex_ = nullptr;
            }
        }
    };

    inline bool LaunchSiblingProcess(
        const std::wstring& executablePath,
        const std::wstring& arguments
    ) {
        std::wstring command = L"\"" + executablePath + L"\" " + arguments;

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);

        PROCESS_INFORMATION information{};

        const BOOL created = CreateProcessW(
            executablePath.c_str(),
            command.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startup,
            &information
        );

        if (!created) {
            return false;
        }

        CloseHandle(information.hThread);
        CloseHandle(information.hProcess);
        return true;
    }

    inline std::wstring GetDirectoryFromPath(const std::wstring& path) {
        const auto slash = path.find_last_of(L"\\/");

        if (slash == std::wstring::npos) {
            return L".";
        }

        return path.substr(0, slash);
    }

    inline std::wstring GetSelfDirectory() {
        std::wstring path(32768, L'\0');
        DWORD length = static_cast<DWORD>(path.size());

        if (
            !QueryFullProcessImageNameW(
                GetCurrentProcess(),
                0,
                path.data(),
                &length
            )
        ) {
            return L".";
        }

        path.resize(length);
        return GetDirectoryFromPath(path);
    }

    inline bool IsProcessAlive(DWORD pid) {
        if (pid == 0) {
            return false;
        }

        HANDLE process = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid
        );

        if (process == nullptr) {
            return false;
        }

        DWORD exitCode = 0;
        const BOOL ok = GetExitCodeProcess(process, &exitCode);
        CloseHandle(process);

        return ok && exitCode == STILL_ACTIVE;
    }

} // namespace Mjolnir
