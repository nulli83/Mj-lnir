#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace Mjolnir {

    struct ImageIntegrityFinding {
        std::string modulePath;
        std::uintptr_t moduleBase = 0;

        bool headerWiped = false;
        std::size_t hookLikePatches = 0;
        std::size_t bytesCompared = 0;

        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct ImageIntegrityScanResult {
        std::vector<ImageIntegrityFinding> findings;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    class ImageIntegrityScanner {
    private:
        static std::wstring Utf8ToWide(const std::string& value) {
            if (value.empty()) {
                return {};
            }

            const int requiredSize = MultiByteToWideChar(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                nullptr,
                0
            );

            if (requiredSize <= 0) {
                return {};
            }

            std::wstring wide(
                static_cast<std::size_t>(requiredSize),
                L'\0'
            );

            MultiByteToWideChar(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                wide.data(),
                requiredSize
            );

            return wide;
        }

        static bool ReadFileBytes(
            const std::string& path,
            std::vector<std::uint8_t>& bytes
        ) {
            const std::wstring widePath = Utf8ToWide(path);

            HANDLE file = CreateFileW(
                widePath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            if (file == INVALID_HANDLE_VALUE) {
                return false;
            }

            LARGE_INTEGER fileSize{};

            if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart <= 0) {
                CloseHandle(file);
                return false;
            }

            if (fileSize.QuadPart > 64LL * 1024LL * 1024LL) {
                CloseHandle(file);
                return false;
            }

            bytes.resize(static_cast<std::size_t>(fileSize.QuadPart));

            std::size_t totalRead = 0;

            while (totalRead < bytes.size()) {
                DWORD chunk = 0;
                const DWORD toRead = static_cast<DWORD>(
                    std::min<std::size_t>(
                        bytes.size() - totalRead,
                        1024 * 1024
                    )
                );

                if (
                    !ReadFile(
                        file,
                        bytes.data() + totalRead,
                        toRead,
                        &chunk,
                        nullptr
                    ) ||
                    chunk == 0
                ) {
                    CloseHandle(file);
                    return false;
                }

                totalRead += chunk;
            }

            CloseHandle(file);
            return true;
        }

        static bool LooksLikeHook(
            const std::uint8_t* memoryBytes,
            const std::uint8_t* diskBytes,
            std::size_t length
        ) {
            if (length < 5) {
                return false;
            }

            if (
                memoryBytes[0] == diskBytes[0] &&
                memoryBytes[1] == diskBytes[1]
            ) {
                return false;
            }

            if (memoryBytes[0] == 0xE9 || memoryBytes[0] == 0xEB) {
                return true;
            }

            if (memoryBytes[0] == 0xFF && memoryBytes[1] == 0x25) {
                return true;
            }

            if (
                length >= 12 &&
                memoryBytes[0] == 0x48 &&
                memoryBytes[1] == 0xB8 &&
                memoryBytes[10] == 0xFF &&
                memoryBytes[11] == 0xE0
            ) {
                return true;
            }

            if (
                memoryBytes[0] == 0xCC &&
                diskBytes[0] != 0xCC
            ) {
                return true;
            }

            return false;
        }

        static const IMAGE_SECTION_HEADER* FindSection(
            const IMAGE_NT_HEADERS64* ntHeaders,
            const char* name
        ) {
            const auto* section = IMAGE_FIRST_SECTION(ntHeaders);

            for (
                unsigned index = 0;
                index < ntHeaders->FileHeader.NumberOfSections;
                ++index
            ) {
                char sectionName[9]{};
                std::memcpy(
                    sectionName,
                    section[index].Name,
                    8
                );

                if (_stricmp(sectionName, name) == 0) {
                    return &section[index];
                }
            }

            return nullptr;
        }

    public:
        static ImageIntegrityScanResult ScanModule(
            HANDLE processHandle,
            std::uintptr_t moduleBase,
            const std::string& modulePath,
            int baseRiskWeight = 60
        ) {
            ImageIntegrityScanResult result{};

            if (
                processHandle == nullptr ||
                processHandle == INVALID_HANDLE_VALUE ||
                moduleBase == 0 ||
                modulePath.empty()
            ) {
                result.errorCode = ERROR_INVALID_PARAMETER;
                return result;
            }

            ImageIntegrityFinding finding{};
            finding.modulePath = modulePath;
            finding.moduleBase = moduleBase;

            IMAGE_DOS_HEADER remoteDos{};
            SIZE_T bytesRead = 0;

            if (
                !ReadProcessMemory(
                    processHandle,
                    reinterpret_cast<LPCVOID>(moduleBase),
                    &remoteDos,
                    sizeof(remoteDos),
                    &bytesRead
                ) ||
                bytesRead != sizeof(remoteDos)
            ) {
                result.errorCode = ERROR_PARTIAL_COPY;
                return result;
            }

            if (remoteDos.e_magic != IMAGE_DOS_SIGNATURE) {
                finding.headerWiped = true;
                finding.riskScore += baseRiskWeight;
                finding.reasons.push_back(
                    "In-memory MZ header is missing (possible module stomping)"
                );
            }

            std::vector<std::uint8_t> diskImage;

            if (!ReadFileBytes(modulePath, diskImage)) {
                if (finding.riskScore > 0) {
                    result.findings.push_back(std::move(finding));
                }

                result.errorCode = ERROR_SUCCESS;
                return result;
            }

            if (
                diskImage.size() < sizeof(IMAGE_DOS_HEADER)
            ) {
                result.errorCode = ERROR_BAD_FORMAT;
                return result;
            }

            const auto* diskDos =
                reinterpret_cast<const IMAGE_DOS_HEADER*>(
                    diskImage.data()
                );

            if (
                diskDos->e_magic != IMAGE_DOS_SIGNATURE ||
                diskDos->e_lfanew <= 0 ||
                static_cast<std::size_t>(diskDos->e_lfanew) +
                    sizeof(IMAGE_NT_HEADERS64) >
                    diskImage.size()
            ) {
                result.errorCode = ERROR_BAD_FORMAT;
                return result;
            }

            const auto* diskNt =
                reinterpret_cast<const IMAGE_NT_HEADERS64*>(
                    diskImage.data() + diskDos->e_lfanew
                );

            if (
                diskNt->Signature != IMAGE_NT_SIGNATURE ||
                diskNt->OptionalHeader.Magic !=
                    IMAGE_NT_OPTIONAL_HDR64_MAGIC
            ) {
                result.errorCode = ERROR_NOT_SUPPORTED;
                return result;
            }

            const IMAGE_SECTION_HEADER* textSection =
                FindSection(diskNt, ".text");

            if (textSection == nullptr) {
                textSection = FindSection(diskNt, "CODE");
            }

            if (
                textSection != nullptr &&
                textSection->SizeOfRawData > 0 &&
                textSection->PointerToRawData +
                    textSection->SizeOfRawData <=
                    diskImage.size()
            ) {
                const std::size_t compareSize = std::min<std::size_t>(
                    textSection->SizeOfRawData,
                    1024 * 1024
                );

                std::vector<std::uint8_t> remoteText(compareSize);

                if (
                    ReadProcessMemory(
                        processHandle,
                        reinterpret_cast<LPCVOID>(
                            moduleBase +
                            textSection->VirtualAddress
                        ),
                        remoteText.data(),
                        compareSize,
                        &bytesRead
                    ) &&
                    bytesRead == compareSize
                ) {
                    const std::uint8_t* diskText =
                        diskImage.data() +
                        textSection->PointerToRawData;

                    finding.bytesCompared = compareSize;

                    for (
                        std::size_t offset = 0;
                        offset + 16 <= compareSize;
                        offset += 16
                    ) {
                        if (
                            LooksLikeHook(
                                remoteText.data() + offset,
                                diskText + offset,
                                16
                            )
                        ) {
                            ++finding.hookLikePatches;
                        }
                    }

                    if (finding.hookLikePatches > 0) {
                        finding.riskScore +=
                            baseRiskWeight +
                            static_cast<int>(
                                std::min<std::size_t>(
                                    finding.hookLikePatches * 2,
                                    40
                                )
                            );

                        finding.reasons.push_back(
                            "Hook-like patches detected in .text versus disk image (" +
                            std::to_string(finding.hookLikePatches) +
                            " sites)"
                        );
                    }
                }
            }

            if (finding.riskScore > 0) {
                result.findings.push_back(std::move(finding));
            }

            result.errorCode = ERROR_SUCCESS;
            return result;
        }
    };

} // namespace Mjolnir
