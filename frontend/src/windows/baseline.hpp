#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace Mjolnir {

    struct BaselineSnapshot {
        DWORD processId = 0;
        bool established = false;

        std::unordered_set<std::string> moduleNames;
        std::unordered_map<std::string, std::uint32_t> moduleTextCrc;
        std::uint32_t mainTextCrc = 0;
        std::uintptr_t mainModuleBase = 0;
        std::string mainModulePath;
    };

    struct BaselineFinding {
        std::string kind;
        std::string details;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct BaselineDiffResult {
        std::vector<BaselineFinding> findings;
        bool baselineReady = false;
    };

    class SessionBaseline {
    private:
        BaselineSnapshot snapshot_;

        static std::string ToLower(std::string value) {
            for (char& character : value) {
                character = static_cast<char>(
                    std::tolower(
                        static_cast<unsigned char>(character)
                    )
                );
            }

            return value;
        }

        static std::uint32_t Crc32(
            const std::uint8_t* data,
            std::size_t length
        ) {
            std::uint32_t crc = 0xFFFFFFFFu;

            for (std::size_t index = 0; index < length; ++index) {
                crc ^= data[index];

                for (int bit = 0; bit < 8; ++bit) {
                    const std::uint32_t mask =
                        -(crc & 1u);
                    crc = (crc >> 1) ^ (0xEDB88320u & mask);
                }
            }

            return ~crc;
        }

        static bool ReadRemoteTextCrc(
            HANDLE processHandle,
            std::uintptr_t moduleBase,
            std::uint32_t& crcOut,
            std::size_t maxBytes = 256 * 1024
        ) {
            IMAGE_DOS_HEADER dos{};
            SIZE_T bytesRead = 0;

            if (
                !ReadProcessMemory(
                    processHandle,
                    reinterpret_cast<LPCVOID>(moduleBase),
                    &dos,
                    sizeof(dos),
                    &bytesRead
                ) ||
                bytesRead != sizeof(dos) ||
                dos.e_magic != IMAGE_DOS_SIGNATURE
            ) {
                return false;
            }

            IMAGE_NT_HEADERS64 nt{};

            if (
                !ReadProcessMemory(
                    processHandle,
                    reinterpret_cast<LPCVOID>(
                        moduleBase +
                        static_cast<std::uintptr_t>(dos.e_lfanew)
                    ),
                    &nt,
                    sizeof(nt),
                    &bytesRead
                ) ||
                bytesRead != sizeof(nt) ||
                nt.Signature != IMAGE_NT_SIGNATURE ||
                nt.OptionalHeader.Magic !=
                    IMAGE_NT_OPTIONAL_HDR64_MAGIC
            ) {
                return false;
            }

            IMAGE_SECTION_HEADER sections[96]{};
            const unsigned sectionCount = std::min<unsigned>(
                nt.FileHeader.NumberOfSections,
                96
            );

            const std::uintptr_t sectionAddress =
                moduleBase +
                static_cast<std::uintptr_t>(dos.e_lfanew) +
                sizeof(DWORD) +
                sizeof(IMAGE_FILE_HEADER) +
                nt.FileHeader.SizeOfOptionalHeader;

            if (
                !ReadProcessMemory(
                    processHandle,
                    reinterpret_cast<LPCVOID>(sectionAddress),
                    sections,
                    sectionCount * sizeof(IMAGE_SECTION_HEADER),
                    &bytesRead
                ) ||
                bytesRead < sizeof(IMAGE_SECTION_HEADER)
            ) {
                return false;
            }

            const IMAGE_SECTION_HEADER* text = nullptr;

            for (unsigned index = 0; index < sectionCount; ++index) {
                char name[9]{};
                std::memcpy(name, sections[index].Name, 8);

                if (
                    _stricmp(name, ".text") == 0 ||
                    _stricmp(name, "CODE") == 0
                ) {
                    text = &sections[index];
                    break;
                }
            }

            if (text == nullptr || text->Misc.VirtualSize == 0) {
                return false;
            }

            const std::size_t size = std::min<std::size_t>(
                text->Misc.VirtualSize,
                maxBytes
            );

            std::vector<std::uint8_t> buffer(size);

            if (
                !ReadProcessMemory(
                    processHandle,
                    reinterpret_cast<LPCVOID>(
                        moduleBase + text->VirtualAddress
                    ),
                    buffer.data(),
                    size,
                    &bytesRead
                ) ||
                bytesRead == 0
            ) {
                return false;
            }

            crcOut = Crc32(buffer.data(), bytesRead);
            return true;
        }

    public:
        void Reset() {
            snapshot_ = BaselineSnapshot{};
        }

        bool Established() const {
            return snapshot_.established;
        }

        DWORD ProcessId() const {
            return snapshot_.processId;
        }

        void Establish(
            DWORD processId,
            HANDLE processHandle,
            const std::vector<std::pair<std::string, std::uintptr_t>>&
                modules,
            const std::string& mainModulePath,
            std::uintptr_t mainModuleBase
        ) {
            Reset();

            snapshot_.processId = processId;
            snapshot_.mainModulePath = mainModulePath;
            snapshot_.mainModuleBase = mainModuleBase;

            for (const auto& module : modules) {
                snapshot_.moduleNames.insert(ToLower(module.first));

                std::uint32_t crc = 0;

                if (
                    ReadRemoteTextCrc(
                        processHandle,
                        module.second,
                        crc
                    )
                ) {
                    snapshot_.moduleTextCrc[ToLower(module.first)] =
                        crc;
                }
            }

            if (mainModuleBase != 0) {
                ReadRemoteTextCrc(
                    processHandle,
                    mainModuleBase,
                    snapshot_.mainTextCrc
                );
            }

            snapshot_.established = true;
        }

        BaselineDiffResult Diff(
            HANDLE processHandle,
            const std::vector<std::pair<std::string, std::uintptr_t>>&
                modules,
            const std::unordered_set<std::string>& whitelistedModules,
            int newModuleWeight = 40,
            int codeMutationWeight = 65
        ) const {
            BaselineDiffResult result{};
            result.baselineReady = snapshot_.established;

            if (!snapshot_.established) {
                return result;
            }

            std::unordered_set<std::string> currentNames;

            for (const auto& module : modules) {
                const std::string name = ToLower(module.first);
                currentNames.insert(name);

                if (
                    snapshot_.moduleNames.find(name) ==
                        snapshot_.moduleNames.end() &&
                    whitelistedModules.find(name) ==
                        whitelistedModules.end()
                ) {
                    BaselineFinding finding{};
                    finding.kind = "module_birth";
                    finding.details = name;
                    finding.riskScore = newModuleWeight;
                    finding.reasons.push_back(
                        "Module appeared after session baseline was established"
                    );
                    result.findings.push_back(std::move(finding));
                }

                const auto crcIterator =
                    snapshot_.moduleTextCrc.find(name);

                if (crcIterator == snapshot_.moduleTextCrc.end()) {
                    continue;
                }

                std::uint32_t currentCrc = 0;

                if (
                    !ReadRemoteTextCrc(
                        processHandle,
                        module.second,
                        currentCrc
                    )
                ) {
                    continue;
                }

                if (currentCrc != crcIterator->second) {
                    BaselineFinding finding{};
                    finding.kind = "code_mutation";
                    finding.details = name;
                    finding.riskScore = codeMutationWeight;
                    finding.reasons.push_back(
                        "Module .text CRC changed versus session baseline"
                    );
                    result.findings.push_back(std::move(finding));
                }
            }

            return result;
        }
    };

} // namespace Mjolnir
