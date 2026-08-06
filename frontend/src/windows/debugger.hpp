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

    struct DebuggerFinding {
        bool attached = false;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    class DebuggerDetector {
    private:
        using NtQueryInformationProcessFn =
            NTSTATUS(NTAPI*)(
                HANDLE ProcessHandle,
                PROCESSINFOCLASS ProcessInformationClass,
                PVOID ProcessInformation,
                ULONG ProcessInformationLength,
                PULONG ReturnLength
            );

        static NtQueryInformationProcessFn ResolveNtQuery() {
            static NtQueryInformationProcessFn function =
                reinterpret_cast<NtQueryInformationProcessFn>(
                    GetProcAddress(
                        GetModuleHandleW(L"ntdll.dll"),
                        "NtQueryInformationProcess"
                    )
                );

            return function;
        }

        static void AddReason(
            DebuggerFinding& finding,
            int amount,
            const std::string& reason
        ) {
            finding.attached = true;
            finding.riskScore += amount;
            finding.reasons.push_back(reason);
        }

        static bool QueryDebugPort(HANDLE processHandle) {
            auto* ntQuery = ResolveNtQuery();

            if (ntQuery == nullptr) {
                return false;
            }

            /*
             * ProcessDebugPort = 7
             */
            constexpr PROCESSINFOCLASS ProcessDebugPortClass =
                static_cast<PROCESSINFOCLASS>(7);

            ULONG_PTR debugPort = 0;
            const NTSTATUS status = ntQuery(
                processHandle,
                ProcessDebugPortClass,
                &debugPort,
                sizeof(debugPort),
                nullptr
            );

            return NT_SUCCESS(status) && debugPort != 0;
        }

        static bool QueryDebugFlags(HANDLE processHandle) {
            auto* ntQuery = ResolveNtQuery();

            if (ntQuery == nullptr) {
                return false;
            }

            /*
             * ProcessDebugFlags = 31
             * När NoDebugInherit är 0 är processen oftast
             * under aktiv debugging.
             */
            constexpr PROCESSINFOCLASS ProcessDebugFlags =
                static_cast<PROCESSINFOCLASS>(31);

            ULONG debugFlags = 1;
            const NTSTATUS status = ntQuery(
                processHandle,
                ProcessDebugFlags,
                &debugFlags,
                sizeof(debugFlags),
                nullptr
            );

            return NT_SUCCESS(status) && debugFlags == 0;
        }

        static bool QueryDebugObject(HANDLE processHandle) {
            auto* ntQuery = ResolveNtQuery();

            if (ntQuery == nullptr) {
                return false;
            }

            /*
             * ProcessDebugObjectHandle = 30
             */
            constexpr PROCESSINFOCLASS
                ProcessDebugObjectHandle =
                    static_cast<PROCESSINFOCLASS>(30);

            HANDLE debugObject = nullptr;
            const NTSTATUS status = ntQuery(
                processHandle,
                ProcessDebugObjectHandle,
                &debugObject,
                sizeof(debugObject),
                nullptr
            );

            if (NT_SUCCESS(status) && debugObject != nullptr) {
                CloseHandle(debugObject);
                return true;
            }

            return false;
        }

        static bool HasHardwareBreakpoints(
            HANDLE processHandle
        ) {
            HANDLE snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPTHREAD,
                0
            );

            if (snapshot == INVALID_HANDLE_VALUE) {
                return false;
            }

            const DWORD targetPid =
                GetProcessId(processHandle);

            THREADENTRY32 entry{};
            entry.dwSize = sizeof(entry);

            bool found = false;

            if (Thread32First(snapshot, &entry)) {
                do {
                    if (entry.th32OwnerProcessID != targetPid) {
                        continue;
                    }

                    HANDLE thread = OpenThread(
                        THREAD_GET_CONTEXT |
                        THREAD_QUERY_INFORMATION,
                        FALSE,
                        entry.th32ThreadID
                    );

                    if (thread == nullptr) {
                        continue;
                    }

                    CONTEXT context{};
                    context.ContextFlags =
                        CONTEXT_DEBUG_REGISTERS;

                    if (GetThreadContext(thread, &context)) {
                        if (
                            context.Dr0 != 0 ||
                            context.Dr1 != 0 ||
                            context.Dr2 != 0 ||
                            context.Dr3 != 0
                        ) {
                            found = true;
                        }
                    }

                    CloseHandle(thread);

                    if (found) {
                        break;
                    }

                } while (Thread32Next(snapshot, &entry));
            }

            CloseHandle(snapshot);
            return found;
        }

    public:
        static DebuggerFinding InspectProcess(
            HANDLE processHandle,
            int debuggerRiskWeight = 40
        ) {
            DebuggerFinding finding{};

            if (
                processHandle == nullptr ||
                processHandle == INVALID_HANDLE_VALUE
            ) {
                return finding;
            }

            BOOL remoteDebugger = FALSE;

            if (
                CheckRemoteDebuggerPresent(
                    processHandle,
                    &remoteDebugger
                ) &&
                remoteDebugger
            ) {
                AddReason(
                    finding,
                    debuggerRiskWeight,
                    "CheckRemoteDebuggerPresent reported an attached debugger"
                );
            }

            if (QueryDebugPort(processHandle)) {
                AddReason(
                    finding,
                    finding.attached ? 10 : debuggerRiskWeight,
                    "NtQueryInformationProcess(ProcessDebugPort) is non-zero"
                );
            }

            if (QueryDebugFlags(processHandle)) {
                AddReason(
                    finding,
                    finding.attached ? 8 : (debuggerRiskWeight / 2 + 5),
                    "ProcessDebugFlags indicates active debugging"
                );
            }

            if (QueryDebugObject(processHandle)) {
                AddReason(
                    finding,
                    finding.attached ? 10 : debuggerRiskWeight,
                    "Process owns a debug object handle"
                );
            }

            if (HasHardwareBreakpoints(processHandle)) {
                AddReason(
                    finding,
                    finding.attached ? 12 : (debuggerRiskWeight / 2 + 10),
                    "Hardware breakpoints detected on one or more threads"
                );
            }

            return finding;
        }

        static DebuggerFinding InspectCurrentProcess(
            int debuggerRiskWeight = 40
        ) {
            DebuggerFinding finding =
                InspectProcess(
                    GetCurrentProcess(),
                    debuggerRiskWeight
                );

            if (IsDebuggerPresent()) {
                AddReason(
                    finding,
                    debuggerRiskWeight,
                    "IsDebuggerPresent() returned true for the security core"
                );
            }

            return finding;
        }
    };

} // namespace Mjolnir
