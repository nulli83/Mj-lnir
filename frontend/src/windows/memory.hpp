#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace Mjolnir {

    struct PatternScanResult {
        std::uintptr_t address = 0;
        std::size_t bytesScanned = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Found() const {
            return address != 0;
        }
    };

    class MemoryManager {
    private:
        class ScopedHandle {
        public:
            explicit ScopedHandle(
                HANDLE handle = INVALID_HANDLE_VALUE
            ) : handle_(handle) {}

            ~ScopedHandle() {
                Reset();
            }

            ScopedHandle(const ScopedHandle&) = delete;
            ScopedHandle& operator=(const ScopedHandle&) = delete;

            ScopedHandle(ScopedHandle&& other) noexcept
                : handle_(other.handle_) {
                other.handle_ = INVALID_HANDLE_VALUE;
            }

            ScopedHandle& operator=(ScopedHandle&& other) noexcept {
                if (this != &other) {
                    Reset();
                    handle_ = other.handle_;
                    other.handle_ = INVALID_HANDLE_VALUE;
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

            void Reset(
                HANDLE newHandle = INVALID_HANDLE_VALUE
            ) {
                if (IsValid()) {
                    CloseHandle(handle_);
                }

                handle_ = newHandle;
            }

        private:
            HANDLE handle_;
        };

        static bool IsReadableProtection(DWORD protection) {
            if (
                (protection & PAGE_GUARD) != 0 ||
                (protection & PAGE_NOACCESS) != 0
            ) {
                return false;
            }

            const DWORD baseProtection = protection & 0xFF;

            switch (baseProtection) {
                case PAGE_READONLY:
                case PAGE_READWRITE:
                case PAGE_WRITECOPY:
                case PAGE_EXECUTE_READ:
                case PAGE_EXECUTE_READWRITE:
                case PAGE_EXECUTE_WRITECOPY:
                    return true;

                default:
                    return false;
            }
        }

        static bool IsValidMask(const std::string& mask) {
            if (mask.empty()) {
                return false;
            }

            return std::all_of(
                mask.begin(),
                mask.end(),
                [](char value) {
                    return value == 'x' ||
                           value == 'X' ||
                           value == '?';
                }
            );
        }

        static bool MatchesPattern(
            const unsigned char* buffer,
            const std::vector<unsigned char>& signature,
            const std::string& mask
        ) {
            for (std::size_t index = 0;
                 index < signature.size();
                 ++index) {

                if (
                    mask[index] != '?' &&
                    buffer[index] != signature[index]
                ) {
                    return false;
                }
            }

            return true;
        }

        static std::uintptr_t SafeRegionEnd(
            std::uintptr_t base,
            SIZE_T regionSize
        ) {
            constexpr std::uintptr_t maximum =
                std::numeric_limits<std::uintptr_t>::max();

            if (regionSize > maximum - base) {
                return maximum;
            }

            return base +
                   static_cast<std::uintptr_t>(regionSize);
        }

    public:
        static std::vector<DWORD> GetProcessIdsByName(
            const std::wstring& processName
        ) {
            std::vector<DWORD> processIds;

            if (processName.empty()) {
                return processIds;
            }

            ScopedHandle snapshot(
                CreateToolhelp32Snapshot(
                    TH32CS_SNAPPROCESS,
                    0
                )
            );

            if (!snapshot.IsValid()) {
                return processIds;
            }

            PROCESSENTRY32W entry{};
            entry.dwSize = sizeof(entry);

            if (!Process32FirstW(snapshot.Get(), &entry)) {
                return processIds;
            }

            do {
                if (
                    _wcsicmp(
                        entry.szExeFile,
                        processName.c_str()
                    ) == 0
                ) {
                    processIds.push_back(
                        entry.th32ProcessID
                    );
                }

                entry.dwSize = sizeof(entry);

            } while (
                Process32NextW(snapshot.Get(), &entry)
            );

            return processIds;
        }

        static DWORD GetProcessIdByName(
            const std::wstring& processName
        ) {
            const std::vector<DWORD> processIds =
                GetProcessIdsByName(processName);

            if (processIds.empty()) {
                return 0;
            }

            return processIds.front();
        }

        static HANDLE OpenTargetProcess(
            DWORD pid,
            DWORD desiredAccess =
                PROCESS_QUERY_INFORMATION |
                PROCESS_VM_READ
        ) {
            if (pid == 0) {
                SetLastError(ERROR_INVALID_PARAMETER);
                return nullptr;
            }

            return OpenProcess(
                desiredAccess,
                FALSE,
                pid
            );
        }

        static bool IsProcessAlive(HANDLE processHandle) {
            if (
                processHandle == nullptr ||
                processHandle == INVALID_HANDLE_VALUE
            ) {
                return false;
            }

            DWORD exitCode = 0;

            if (!GetExitCodeProcess(
                    processHandle,
                    &exitCode
                )) {
                return false;
            }

            return exitCode == STILL_ACTIVE;
        }

        static std::wstring GetProcessImagePath(
            HANDLE processHandle
        ) {
            if (
                processHandle == nullptr ||
                processHandle == INVALID_HANDLE_VALUE
            ) {
                return {};
            }

            std::wstring path(32768, L'\0');
            DWORD pathLength =
                static_cast<DWORD>(path.size());

            if (!QueryFullProcessImageNameW(
                    processHandle,
                    0,
                    path.data(),
                    &pathLength
                )) {
                return {};
            }

            path.resize(pathLength);
            return path;
        }

        static bool IsAddressReadable(
            HANDLE processHandle,
            std::uintptr_t address
        ) {
            if (
                processHandle == nullptr ||
                processHandle == INVALID_HANDLE_VALUE ||
                address == 0
            ) {
                return false;
            }

            MEMORY_BASIC_INFORMATION information{};

            if (
                VirtualQueryEx(
                    processHandle,
                    reinterpret_cast<LPCVOID>(address),
                    &information,
                    sizeof(information)
                ) == 0
            ) {
                return false;
            }

            return
                information.State == MEM_COMMIT &&
                IsReadableProtection(
                    information.Protect
                );
        }

        static bool ReadBuffer(
            HANDLE processHandle,
            std::uintptr_t address,
            void* destination,
            std::size_t size,
            std::size_t* bytesReadResult = nullptr
        ) {
            if (
                processHandle == nullptr ||
                processHandle == INVALID_HANDLE_VALUE ||
                address == 0 ||
                destination == nullptr ||
                size == 0
            ) {
                SetLastError(ERROR_INVALID_PARAMETER);
                return false;
            }

            SIZE_T bytesRead = 0;

            const BOOL success = ReadProcessMemory(
                processHandle,
                reinterpret_cast<LPCVOID>(address),
                destination,
                size,
                &bytesRead
            );

            if (bytesReadResult != nullptr) {
                *bytesReadResult =
                    static_cast<std::size_t>(bytesRead);
            }

            return success != FALSE &&
                   bytesRead == size;
        }

        template <typename T>
        static bool ReadMemory(
            HANDLE processHandle,
            std::uintptr_t address,
            T& destination
        ) {
            return ReadBuffer(
                processHandle,
                address,
                &destination,
                sizeof(T)
            );
        }

        static PatternScanResult ScanPatternDetailed(
            HANDLE processHandle,
            const std::vector<unsigned char>& signature,
            const std::string& mask,
            std::uintptr_t startAddress,
            std::size_t searchSize,
            std::size_t chunkSize = 1024 * 1024
        ) {
            PatternScanResult result{};

            if (
                processHandle == nullptr ||
                processHandle == INVALID_HANDLE_VALUE ||
                startAddress == 0 ||
                signature.empty() ||
                signature.size() != mask.size() ||
                !IsValidMask(mask) ||
                searchSize < signature.size()
            ) {
                result.errorCode =
                    ERROR_INVALID_PARAMETER;

                return result;
            }

            constexpr std::uintptr_t maximumAddress =
                std::numeric_limits<std::uintptr_t>::max();

            if (searchSize > maximumAddress - startAddress) {
                result.errorCode =
                    ERROR_ARITHMETIC_OVERFLOW;

                return result;
            }

            chunkSize = std::max(
                chunkSize,
                signature.size()
            );

            const std::uintptr_t searchEnd =
                startAddress +
                static_cast<std::uintptr_t>(searchSize);

            SYSTEM_INFO systemInfo{};
            GetSystemInfo(&systemInfo);

            const std::size_t pageSize =
                std::max<std::size_t>(
                    systemInfo.dwPageSize,
                    4096
                );

            std::uintptr_t cursor = startAddress;

            while (cursor < searchEnd) {
                MEMORY_BASIC_INFORMATION information{};

                const SIZE_T querySize = VirtualQueryEx(
                    processHandle,
                    reinterpret_cast<LPCVOID>(cursor),
                    &information,
                    sizeof(information)
                );

                if (querySize == 0) {
                    const std::uintptr_t remaining =
                        searchEnd - cursor;

                    cursor += std::min<std::uintptr_t>(
                        remaining,
                        pageSize
                    );

                    continue;
                }

                const std::uintptr_t regionBase =
                    reinterpret_cast<std::uintptr_t>(
                        information.BaseAddress
                    );

                const std::uintptr_t regionEnd =
                    SafeRegionEnd(
                        regionBase,
                        information.RegionSize
                    );

                const std::uintptr_t readableStart =
                    std::max(cursor, regionBase);

                const std::uintptr_t readableEnd =
                    std::min(searchEnd, regionEnd);

                const bool readable =
                    information.State == MEM_COMMIT &&
                    IsReadableProtection(
                        information.Protect
                    );

                if (
                    readable &&
                    readableStart < readableEnd
                ) {
                    std::uintptr_t readCursor =
                        readableStart;

                    while (readCursor < readableEnd) {
                        const std::size_t remaining =
                            static_cast<std::size_t>(
                                readableEnd - readCursor
                            );

                        const std::size_t requestedSize =
                            std::min(
                                remaining,
                                chunkSize
                            );

                        std::vector<unsigned char> buffer(
                            requestedSize
                        );

                        SIZE_T bytesRead = 0;

                        ReadProcessMemory(
                            processHandle,
                            reinterpret_cast<LPCVOID>(
                                readCursor
                            ),
                            buffer.data(),
                            requestedSize,
                            &bytesRead
                        );

                        const std::size_t actualBytesRead =
                            static_cast<std::size_t>(
                                bytesRead
                            );

                        if (actualBytesRead == 0) {
                            readCursor +=
                                std::min<std::size_t>(
                                    remaining,
                                    pageSize
                                );

                            continue;
                        }

                        result.bytesScanned +=
                            actualBytesRead;

                        if (
                            actualBytesRead >=
                            signature.size()
                        ) {
                            const std::size_t lastOffset =
                                actualBytesRead -
                                signature.size();

                            for (
                                std::size_t offset = 0;
                                offset <= lastOffset;
                                ++offset
                            ) {
                                if (
                                    MatchesPattern(
                                        buffer.data() + offset,
                                        signature,
                                        mask
                                    )
                                ) {
                                    result.address =
                                        readCursor + offset;

                                    result.errorCode =
                                        ERROR_SUCCESS;

                                    return result;
                                }
                            }
                        }

                        std::size_t advance =
                            actualBytesRead;

                        /*
                         * Behåll överlappning mellan block så att
                         * ett mönster som korsar blockgränsen hittas.
                         */
                        if (
                            actualBytesRead >=
                            signature.size() &&
                            readCursor +
                                actualBytesRead <
                                readableEnd
                        ) {
                            advance -=
                                signature.size() - 1;
                        }

                        if (advance == 0) {
                            advance = 1;
                        }

                        readCursor += advance;
                    }
                }

                const std::uintptr_t nextCursor =
                    std::max(
                        regionEnd,
                        cursor +
                        static_cast<std::uintptr_t>(
                            pageSize
                        )
                    );

                if (nextCursor <= cursor) {
                    break;
                }

                cursor = std::min(
                    nextCursor,
                    searchEnd
                );
            }

            result.errorCode = ERROR_NOT_FOUND;
            return result;
        }

        /*
         * Kompatibilitetsfunktion för din nuvarande kod.
         * Den detaljerade versionen ovan är bättre eftersom
         * den även returnerar felkod och antal skannade bytes.
         */
        static std::uintptr_t ScanPattern(
            HANDLE processHandle,
            const unsigned char* signature,
            const char* mask,
            std::uintptr_t startAddress,
            std::size_t searchSize
        ) {
            if (signature == nullptr || mask == nullptr) {
                SetLastError(ERROR_INVALID_PARAMETER);
                return 0;
            }

            const std::size_t patternLength =
                std::strlen(mask);

            if (patternLength == 0) {
                SetLastError(ERROR_INVALID_PARAMETER);
                return 0;
            }

            const std::vector<unsigned char>
                signatureVector(
                    signature,
                    signature + patternLength
                );

            const PatternScanResult result =
                ScanPatternDetailed(
                    processHandle,
                    signatureVector,
                    std::string(mask),
                    startAddress,
                    searchSize
                );

            if (!result.Found()) {
                SetLastError(result.errorCode);
                return 0;
            }

            return result.address;
        }
    };

} // namespace Mjolnir
