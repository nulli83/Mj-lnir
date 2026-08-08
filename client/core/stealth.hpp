#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <cstdint>
#include <string>
#include <vector>

#pragma comment(lib, "ntdll.lib")

namespace Mjolnir {

    struct StealthFinding {
        DWORD threadId = 0;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct StealthScanResult {
        std::vector<StealthFinding> findings;
        std::size_t threadsInspected = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    /*
     * Avancerad stealth-detektion:
     * - ProcessInstrumentationCallback satt (anti-debug/ETW-bypass klass)
     * - ThreadHideFromDebugger på trådar i målprocessen
     */
    class StealthScanner {
    private:
        using NtQueryInformationProcessFn =
            NTSTATUS(NTAPI*)(
                HANDLE,
                PROCESSINFOCLASS,
                PVOID,
                ULONG,
                PULONG
            );

        using NtQueryInformationThreadFn =
            NTSTATUS(NTAPI*)(
                HANDLE,
                ULONG,
                PVOID,
                ULONG,
                PULONG
            );

        struct InstrumentationCallbackInfo {
            ULONG Version;
            ULONG Reserved;
            PVOID Callback;
        };

        static NtQueryInformationProcessFn ResolveNtQueryProcess() {
            static auto* function =
                reinterpret_cast<NtQueryInformationProcessFn>(
                    GetProcAddress(
                        GetModuleHandleW(L"ntdll.dll"),
                        "NtQueryInformationProcess"
                    )
                );
            return function;
        }

        static NtQueryInformationThreadFn ResolveNtQueryThread() {
            static auto* function =
                reinterpret_cast<NtQueryInformationThreadFn>(
                    GetProcAddress(
                        GetModuleHandleW(L"ntdll.dll"),
                        "NtQueryInformationThread"
                    )
                );
            return function;
        }

    public:
        static StealthScanResult Scan(
            HANDLE process,
            DWORD targetPid,
            int baseWeight = 65
        ) {
            StealthScanResult result{};

            if (process == nullptr || targetPid == 0) {
                result.errorCode = ERROR_INVALID_PARAMETER;
                return result;
            }

            auto* ntQueryProcess = ResolveNtQueryProcess();
            if (ntQueryProcess != nullptr) {
                /*
                 * ProcessInstrumentationCallback = 40
                 */
                constexpr PROCESSINFOCLASS kInstrumentation =
                    static_cast<PROCESSINFOCLASS>(40);

                InstrumentationCallbackInfo info{};
                const NTSTATUS status = ntQueryProcess(
                    process,
                    kInstrumentation,
                    &info,
                    sizeof(info),
                    nullptr
                );

                if (NT_SUCCESS(status) && info.Callback != nullptr) {
                    StealthFinding finding{};
                    finding.riskScore = baseWeight + 20;
                    finding.reasons.push_back(
                        "ProcessInstrumentationCallback is installed"
                    );
                    result.findings.push_back(std::move(finding));
                }
            }

            auto* ntQueryThread = ResolveNtQueryThread();
            if (ntQueryThread == nullptr) {
                return result;
            }

            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot == INVALID_HANDLE_VALUE) {
                return result;
            }

            THREADENTRY32 entry{};
            entry.dwSize = sizeof(entry);

            if (!Thread32First(snapshot, &entry)) {
                CloseHandle(snapshot);
                return result;
            }

            /*
             * ThreadHideFromDebugger = 17
             */
            constexpr ULONG kThreadHideFromDebugger = 17;

            do {
                if (entry.th32OwnerProcessID != targetPid) {
                    continue;
                }

                ++result.threadsInspected;

                HANDLE thread = OpenThread(
                    THREAD_QUERY_INFORMATION,
                    FALSE,
                    entry.th32ThreadID
                );

                if (thread == nullptr) {
                    continue;
                }

                ULONG hidden = 0;
                const NTSTATUS status = ntQueryThread(
                    thread,
                    kThreadHideFromDebugger,
                    &hidden,
                    sizeof(hidden),
                    nullptr
                );

                CloseHandle(thread);

                if (NT_SUCCESS(status) && hidden != 0) {
                    StealthFinding finding{};
                    finding.threadId = entry.th32ThreadID;
                    finding.riskScore = baseWeight;
                    finding.reasons.push_back(
                        "ThreadHideFromDebugger is set"
                    );
                    result.findings.push_back(std::move(finding));
                }
            } while (Thread32Next(snapshot, &entry));

            CloseHandle(snapshot);
            return result;
        }
    };

} // namespace Mjolnir
