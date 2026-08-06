#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <thread>

#include "twin_watchdog.hpp"

namespace {

    std::wstring GetSelfPath() {
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
            return {};
        }

        path.resize(length);
        return path;
    }

    std::wstring JoinPath(
        const std::wstring& directory,
        const std::wstring& file
    ) {
        if (
            directory.empty() ||
            directory.back() == L'\\' ||
            directory.back() == L'/'
        ) {
            return directory + file;
        }

        return directory + L'\\' + file;
    }

} // namespace

int wmain(int argc, wchar_t** argv) {
    DWORD parentPid = 0;

    for (int index = 1; index < argc; ++index) {
        const std::wstring argument = argv[index];

        if (argument.rfind(L"--parent=", 0) == 0) {
            parentPid = static_cast<DWORD>(
                std::wcstoul(argument.c_str() + 9, nullptr, 10)
            );
        }
    }

    Mjolnir::TwinWatchdogClient twin;

    if (!twin.OpenOrCreate(false)) {
        return 1;
    }

    const std::wstring selfDir = Mjolnir::GetSelfDirectory();
    const std::wstring corePath =
        JoinPath(selfDir, L"mjolnir_core.exe");

    std::uint64_t lastCoreHeartbeat = 0;
    int stalledCycles = 0;

    while (true) {
        twin.PulseWatchdog();

        const auto snapshot = twin.Snapshot();

        if (snapshot.corePid != 0) {
            parentPid = snapshot.corePid;
        }

        const bool coreAlive =
            parentPid != 0 &&
            Mjolnir::IsProcessAlive(parentPid);

        if (!coreAlive) {
            const std::wstring args =
                L"--spawned-by-watchdog --watchdog-pid=" +
                std::to_wstring(GetCurrentProcessId());

            Mjolnir::LaunchSiblingProcess(corePath, args);
            stalledCycles = 0;
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }

        if (snapshot.coreHeartbeat == lastCoreHeartbeat) {
            ++stalledCycles;
        } else {
            stalledCycles = 0;
            lastCoreHeartbeat = snapshot.coreHeartbeat;
        }

        /*
         * Om core lever men heartbeat hängt sig länge:
         * starta en ny instans (den gamla kan vara fryst/patchad).
         */
        if (stalledCycles >= 6) {
            HANDLE process = OpenProcess(
                PROCESS_TERMINATE,
                FALSE,
                parentPid
            );

            if (process != nullptr) {
                TerminateProcess(process, 2);
                CloseHandle(process);
            }

            const std::wstring args =
                L"--spawned-by-watchdog --watchdog-pid=" +
                std::to_wstring(GetCurrentProcessId());

            Mjolnir::LaunchSiblingProcess(corePath, args);
            stalledCycles = 0;
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }

    return 0;
}
