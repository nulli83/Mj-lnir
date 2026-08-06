#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#pragma comment(lib, "ntdll.lib")

namespace Mjolnir {

    struct ModuleRange {
        std::uintptr_t base = 0;
        std::uintptr_t end = 0;
        std::string name;
    };

    struct SuspiciousThreadInfo {
        DWORD threadId = 0;
        DWORD processId = 0;
        std::uintptr_t startAddress = 0;

        bool startOutsideModules = false;
        bool hiddenFromSnapshot = false;

        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct ThreadScanResult {
        std::vector<SuspiciousThreadInfo> threads;
        std::size_t threadsInspected = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class ThreadScanner {
    private:
        using NtQueryInformationThreadFn =
            NTSTATUS(NTAPI*)(
                HANDLE ThreadHandle,
                ULONG ThreadInformationClass,
                PVOID ThreadInformation,
                ULONG ThreadInformationLength,
                PULONG ReturnLength
            );

        static NtQueryInformationThreadFn ResolveNtQueryThread() {
            static NtQueryInformationThreadFn function =
                reinterpret_cast<NtQueryInformationThreadFn>(
                    GetProcAddress(
                        GetModuleHandleW(L"ntdll.dll"),
                        "NtQueryInformationThread"
                    )
                );

            return function;
        }

        static bool AddressInModules(
            std::uintptr_t address,
            const std::vector<ModuleRange>& ranges
        ) {
            for (const ModuleRange& range : ranges) {
                if (
                    address >= range.base &&
                    address < range.end
                ) {
                    return true;
                }
            }

            return false;
        }

    public:
        static std::vector<ModuleRange> BuildModuleRanges(
            DWORD pid
        ) {
            std::vector<ModuleRange> ranges;

            HANDLE snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                pid
            );

            if (snapshot == INVALID_HANDLE_VALUE) {
                return ranges;
            }

            MODULEENTRY32W entry{};
            entry.dwSize = sizeof(entry);

            if (Module32FirstW(snapshot, &entry)) {
                do {
                    ModuleRange range{};
                    range.base =
                        reinterpret_cast<std::uintptr_t>(
                            entry.modBaseAddr
                        );
                    range.end =
                        range.base +
                        static_cast<std::uintptr_t>(
                            entry.modBaseSize
                        );

                    char narrowName[MAX_PATH]{};
                    WideCharToMultiByte(
                        CP_UTF8,
                        0,
                        entry.szModule,
                        -1,
                        narrowName,
                        static_cast<int>(sizeof(narrowName)),
                        nullptr,
                        nullptr
                    );

                    range.name = narrowName;
                    ranges.push_back(std::move(range));

                    entry.dwSize = sizeof(entry);
                } while (Module32NextW(snapshot, &entry));
            }

            CloseHandle(snapshot);
            return ranges;
        }

        static ThreadScanResult ScanSuspiciousThreads(
            DWORD targetPid,
            int baseRiskWeight = 30
        ) {
            ThreadScanResult result{};

            if (targetPid == 0) {
                result.errorCode = ERROR_INVALID_PARAMETER;
                return result;
            }

            auto* ntQueryThread = ResolveNtQueryThread();

            if (ntQueryThread == nullptr) {
                result.errorCode = ERROR_PROC_NOT_FOUND;
                return result;
            }

            const std::vector<ModuleRange> modules =
                BuildModuleRanges(targetPid);

            if (modules.empty()) {
                result.errorCode = ERROR_PARTIAL_COPY;
                return result;
            }

            HANDLE snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPTHREAD,
                0
            );

            if (snapshot == INVALID_HANDLE_VALUE) {
                result.errorCode = GetLastError();
                return result;
            }

            THREADENTRY32 entry{};
            entry.dwSize = sizeof(entry);

            /*
             * ThreadQuerySetWin32StartAddress = 9
             */
            constexpr ULONG ThreadQuerySetWin32StartAddress = 9;

            if (Thread32First(snapshot, &entry)) {
                do {
                    if (entry.th32OwnerProcessID != targetPid) {
                        continue;
                    }

                    ++result.threadsInspected;

                    HANDLE thread = OpenThread(
                        THREAD_QUERY_INFORMATION |
                        THREAD_QUERY_LIMITED_INFORMATION,
                        FALSE,
                        entry.th32ThreadID
                    );

                    if (thread == nullptr) {
                        continue;
                    }

                    PVOID startAddress = nullptr;
                    const NTSTATUS status = ntQueryThread(
                        thread,
                        ThreadQuerySetWin32StartAddress,
                        &startAddress,
                        sizeof(startAddress),
                        nullptr
                    );

                    CloseHandle(thread);

                    if (!NT_SUCCESS(status) ||
                        startAddress == nullptr) {
                        continue;
                    }

                    const std::uintptr_t address =
                        reinterpret_cast<std::uintptr_t>(
                            startAddress
                        );

                    if (AddressInModules(address, modules)) {
                        continue;
                    }

                    SuspiciousThreadInfo info{};
                    info.threadId = entry.th32ThreadID;
                    info.processId = targetPid;
                    info.startAddress = address;
                    info.startOutsideModules = true;
                    info.riskScore = baseRiskWeight;
                    info.reasons.push_back(
                        "Thread start address is outside all loaded modules"
                    );

                    /*
                     * Extra vikt för starts i privata/lågt minne
                     * som ofta används vid manuell mapping.
                     */
                    if (address < 0x10000) {
                        info.riskScore += 15;
                        info.reasons.push_back(
                            "Start address is in a suspiciously low range"
                        );
                    }

                    result.threads.push_back(std::move(info));

                } while (Thread32Next(snapshot, &entry));
            }

            CloseHandle(snapshot);

            std::sort(
                result.threads.begin(),
                result.threads.end(),
                [](
                    const SuspiciousThreadInfo& first,
                    const SuspiciousThreadInfo& second
                ) {
                    return first.riskScore > second.riskScore;
                }
            );

            result.errorCode = ERROR_SUCCESS;
            return result;
        }
    };

} // namespace Mjolnir
