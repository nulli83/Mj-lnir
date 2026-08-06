#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "ntdll.lib")

namespace Mjolnir {

    struct ExternalHandleInfo {
        DWORD ownerProcessId = 0;
        std::string ownerProcessName;
        std::string ownerProcessPath;

        USHORT handleValue = 0;
        ACCESS_MASK grantedAccess = 0;

        bool dangerousAccess = false;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct HandleScanResult {
        std::vector<ExternalHandleInfo> handles;
        DWORD errorCode = ERROR_SUCCESS;
        std::size_t totalHandlesInspected = 0;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class HandleScanner {
    private:
        /*
         * Minimala NT-strukturer för SystemHandleInformation.
         * WinSDK-exponeringen varierar mellan versioner, så vi
         * håller dem lokala och stabila.
         */
        struct SystemHandleEntry {
            ULONG ProcessId;
            BYTE ObjectTypeNumber;
            BYTE Flags;
            USHORT Handle;
            PVOID Object;
            ACCESS_MASK GrantedAccess;
        };

        struct SystemHandleInformation {
            ULONG HandleCount;
            SystemHandleEntry Handles[1];
        };

        using NtQuerySystemInformationFn =
            NTSTATUS(NTAPI*)(
                ULONG SystemInformationClass,
                PVOID SystemInformation,
                ULONG SystemInformationLength,
                PULONG ReturnLength
            );

        class ScopedHandle {
        public:
            explicit ScopedHandle(HANDLE handle = nullptr)
                : handle_(handle) {}

            ~ScopedHandle() {
                Reset();
            }

            ScopedHandle(const ScopedHandle&) = delete;
            ScopedHandle& operator=(const ScopedHandle&) = delete;

            ScopedHandle(ScopedHandle&& other) noexcept
                : handle_(other.handle_) {
                other.handle_ = nullptr;
            }

            ScopedHandle& operator=(ScopedHandle&& other) noexcept {
                if (this != &other) {
                    Reset();
                    handle_ = other.handle_;
                    other.handle_ = nullptr;
                }

                return *this;
            }

            HANDLE Get() const {
                return handle_;
            }

            bool IsValid() const {
                return handle_ != nullptr &&
                       handle_ != INVALID_HANDLE_VALUE;
            }

            void Reset(HANDLE newHandle = nullptr) {
                if (IsValid()) {
                    CloseHandle(handle_);
                }

                handle_ = newHandle;
            }

        private:
            HANDLE handle_;
        };

        static std::string ToLower(std::string value) {
            std::transform(
                value.begin(),
                value.end(),
                value.begin(),
                [](unsigned char character) {
                    return static_cast<char>(
                        std::tolower(character)
                    );
                }
            );

            return value;
        }

        static std::string WideToUtf8(const std::wstring& value) {
            if (value.empty()) {
                return {};
            }

            const int requiredSize = WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                nullptr,
                0,
                nullptr,
                nullptr
            );

            if (requiredSize <= 0) {
                return {};
            }

            std::string result(
                static_cast<std::size_t>(requiredSize),
                '\0'
            );

            WideCharToMultiByte(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                result.data(),
                requiredSize,
                nullptr,
                nullptr
            );

            return result;
        }

        static std::string GetBaseName(const std::string& path) {
            const std::size_t separator =
                path.find_last_of("\\/");

            if (separator == std::string::npos) {
                return path;
            }

            return path.substr(separator + 1);
        }

        static std::string ResolveProcessPath(DWORD pid) {
            ScopedHandle process(
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    pid
                )
            );

            if (!process.IsValid()) {
                return {};
            }

            std::wstring path(32768, L'\0');
            DWORD pathLength =
                static_cast<DWORD>(path.size());

            if (!QueryFullProcessImageNameW(
                    process.Get(),
                    0,
                    path.data(),
                    &pathLength
                )) {
                return {};
            }

            path.resize(pathLength);
            return WideToUtf8(path);
        }

        static bool IsDangerousAccess(ACCESS_MASK access) {
            constexpr ACCESS_MASK dangerous =
                PROCESS_VM_WRITE |
                PROCESS_VM_OPERATION |
                PROCESS_CREATE_THREAD |
                PROCESS_DUP_HANDLE |
                PROCESS_SUSPEND_RESUME |
                PROCESS_SET_INFORMATION |
                PROCESS_VM_READ;

            return (access & dangerous) != 0;
        }

        static std::string DescribeAccess(ACCESS_MASK access) {
            std::string description;

            auto append = [&description](const char* flag) {
                if (!description.empty()) {
                    description += "|";
                }

                description += flag;
            };

            if (access & PROCESS_VM_READ) {
                append("VM_READ");
            }

            if (access & PROCESS_VM_WRITE) {
                append("VM_WRITE");
            }

            if (access & PROCESS_VM_OPERATION) {
                append("VM_OPERATION");
            }

            if (access & PROCESS_CREATE_THREAD) {
                append("CREATE_THREAD");
            }

            if (access & PROCESS_DUP_HANDLE) {
                append("DUP_HANDLE");
            }

            if (access & PROCESS_SUSPEND_RESUME) {
                append("SUSPEND_RESUME");
            }

            if (access & PROCESS_SET_INFORMATION) {
                append("SET_INFORMATION");
            }

            if (access & PROCESS_TERMINATE) {
                append("TERMINATE");
            }

            if (description.empty()) {
                description = "LIMITED";
            }

            return description;
        }

        static NtQuerySystemInformationFn ResolveNtQuery() {
            static NtQuerySystemInformationFn function =
                reinterpret_cast<NtQuerySystemInformationFn>(
                    GetProcAddress(
                        GetModuleHandleW(L"ntdll.dll"),
                        "NtQuerySystemInformation"
                    )
                );

            return function;
        }

    public:
        /*
         * Letar efter processer som håller öppna handles mot
         * targetPid. Kräver ofta förhöjda rättigheter för att
         * kunna duplicera handles från andra processer.
         */
        static HandleScanResult ScanExternalHandles(
            DWORD targetPid,
            const std::unordered_set<std::string>&
                trustedProcesses = {},
            int baseRiskWeight = 35
        ) {
            HandleScanResult result{};

            if (targetPid == 0) {
                result.errorCode = ERROR_INVALID_PARAMETER;
                return result;
            }

            auto* ntQuery = ResolveNtQuery();

            if (ntQuery == nullptr) {
                result.errorCode = ERROR_PROC_NOT_FOUND;
                return result;
            }

            constexpr ULONG SystemHandleInformation = 16;

            ULONG bufferSize = 1 << 20;
            std::vector<std::uint8_t> buffer(bufferSize);
            NTSTATUS status = 0;

            for (int attempt = 0; attempt < 8; ++attempt) {
                ULONG returnLength = 0;

                status = ntQuery(
                    SystemHandleInformation,
                    buffer.data(),
                    bufferSize,
                    &returnLength
                );

                if (NT_SUCCESS(status)) {
                    break;
                }

                /*
                 * STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
                 */
                if (
                    status !=
                        static_cast<NTSTATUS>(0xC0000004L) ||
                    returnLength == 0
                ) {
                    result.errorCode =
                        ERROR_INVALID_FUNCTION;
                    return result;
                }

                bufferSize = returnLength + (1 << 16);
                buffer.resize(bufferSize);
            }

            if (!NT_SUCCESS(status)) {
                result.errorCode = ERROR_INSUFFICIENT_BUFFER;
                return result;
            }

            auto* handleInfo =
                reinterpret_cast<SystemHandleInformation*>(
                    buffer.data()
                );

            const DWORD selfPid = GetCurrentProcessId();

            std::unordered_set<std::string> normalizedTrusted;

            for (const std::string& name : trustedProcesses) {
                normalizedTrusted.insert(ToLower(name));
            }

            for (
                ULONG index = 0;
                index < handleInfo->HandleCount;
                ++index
            ) {
                const SystemHandleEntry& entry =
                    handleInfo->Handles[index];

                ++result.totalHandlesInspected;

                if (entry.ProcessId == targetPid) {
                    continue;
                }

                if (entry.ProcessId == selfPid) {
                    continue;
                }

                if (entry.ProcessId == 0 || entry.ProcessId == 4) {
                    continue;
                }

                ScopedHandle ownerProcess(
                    OpenProcess(
                        PROCESS_DUP_HANDLE |
                        PROCESS_QUERY_LIMITED_INFORMATION,
                        FALSE,
                        entry.ProcessId
                    )
                );

                if (!ownerProcess.IsValid()) {
                    continue;
                }

                HANDLE duplicated = nullptr;

                const BOOL duplicatedOk = DuplicateHandle(
                    ownerProcess.Get(),
                    reinterpret_cast<HANDLE>(
                        static_cast<ULONG_PTR>(entry.Handle)
                    ),
                    GetCurrentProcess(),
                    &duplicated,
                    0,
                    FALSE,
                    DUPLICATE_SAME_ACCESS
                );

                if (!duplicatedOk || duplicated == nullptr) {
                    continue;
                }

                const DWORD duplicatedPid =
                    GetProcessId(duplicated);

                CloseHandle(duplicated);

                if (duplicatedPid != targetPid) {
                    continue;
                }

                ExternalHandleInfo info{};
                info.ownerProcessId = entry.ProcessId;
                info.handleValue = entry.Handle;
                info.grantedAccess = entry.GrantedAccess;
                info.ownerProcessPath =
                    ResolveProcessPath(entry.ProcessId);
                info.ownerProcessName =
                    GetBaseName(info.ownerProcessPath);
                info.dangerousAccess =
                    IsDangerousAccess(entry.GrantedAccess);

                const std::string normalizedOwner =
                    ToLower(info.ownerProcessName);

                const bool trusted =
                    !normalizedOwner.empty() &&
                    normalizedTrusted.find(normalizedOwner) !=
                        normalizedTrusted.end();

                if (info.dangerousAccess) {
                    info.riskScore += baseRiskWeight;
                    info.reasons.push_back(
                        "External process holds dangerous access (" +
                        DescribeAccess(entry.GrantedAccess) +
                        ")"
                    );
                } else {
                    info.riskScore +=
                        std::max(5, baseRiskWeight / 3);
                    info.reasons.push_back(
                        "External process holds a handle to the target"
                    );
                }

                if (trusted) {
                    info.riskScore = std::max(
                        0,
                        info.riskScore - 25
                    );

                    info.reasons.push_back(
                        "Owner process is trusted/whitelisted"
                    );
                } else if (normalizedOwner.empty()) {
                    info.riskScore += 10;
                    info.reasons.push_back(
                        "Could not resolve owner process identity"
                    );
                } else {
                    info.riskScore += 10;
                    info.reasons.push_back(
                        "Owner process is not whitelisted"
                    );
                }

                /*
                 * Extremt farliga rättigheter får extra vikt.
                 */
                if (
                    (entry.GrantedAccess & PROCESS_VM_WRITE) != 0 ||
                    (entry.GrantedAccess & PROCESS_CREATE_THREAD) != 0
                ) {
                    info.riskScore += 20;
                    info.reasons.push_back(
                        "Handle allows memory write and/or remote thread creation"
                    );
                }

                if (info.riskScore >= 20) {
                    result.handles.push_back(std::move(info));
                }
            }

            std::sort(
                result.handles.begin(),
                result.handles.end(),
                [](
                    const ExternalHandleInfo& first,
                    const ExternalHandleInfo& second
                ) {
                    return first.riskScore > second.riskScore;
                }
            );

            result.errorCode = ERROR_SUCCESS;
            return result;
        }
    };

} // namespace Mjolnir
