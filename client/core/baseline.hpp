#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif

namespace Mjolnir {

    struct BaselineSnapshot {
        DWORD processId = 0;
        bool established = false;
        bool loadedFromDisk = false;

        std::string gameImageHash;
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
        bool loadedFromDisk = false;
    };

    class SessionBaseline {
    private:
        BaselineSnapshot snapshot_;
        std::filesystem::path baselineDirectory_ = "baselines";

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
                    const std::uint32_t mask = -(crc & 1u);
                    crc = (crc >> 1) ^ (0xEDB88320u & mask);
                }
            }

            return ~crc;
        }

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

        static std::string ComputeFileSha256(
            const std::string& path
        ) {
            const std::wstring wide = Utf8ToWide(path);

            HANDLE file = CreateFileW(
                wide.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            if (file == INVALID_HANDLE_VALUE) {
                return {};
            }

            HCRYPTPROV provider = 0;
            HCRYPTHASH hash = 0;
            std::string digest;

            if (
                CryptAcquireContextW(
                    &provider,
                    nullptr,
                    nullptr,
                    PROV_RSA_AES,
                    CRYPT_VERIFYCONTEXT
                )
            ) {
                if (
                    CryptCreateHash(
                        provider,
                        CALG_SHA_256,
                        0,
                        0,
                        &hash
                    )
                ) {
                    std::vector<std::uint8_t> buffer(1024 * 1024);
                    DWORD bytesRead = 0;
                    bool ok = true;

                    while (
                        ReadFile(
                            file,
                            buffer.data(),
                            static_cast<DWORD>(buffer.size()),
                            &bytesRead,
                            nullptr
                        ) &&
                        bytesRead > 0
                    ) {
                        if (
                            !CryptHashData(
                                hash,
                                buffer.data(),
                                bytesRead,
                                0
                            )
                        ) {
                            ok = false;
                            break;
                        }
                    }

                    if (ok) {
                        BYTE hashBytes[32]{};
                        DWORD hashSize = sizeof(hashBytes);

                        if (
                            CryptGetHashParam(
                                hash,
                                HP_HASHVAL,
                                hashBytes,
                                &hashSize,
                                0
                            )
                        ) {
                            static const char* hex = "0123456789abcdef";
                            digest.reserve(hashSize * 2);

                            for (DWORD index = 0; index < hashSize; ++index) {
                                digest.push_back(
                                    hex[(hashBytes[index] >> 4) & 0x0F]
                                );
                                digest.push_back(
                                    hex[hashBytes[index] & 0x0F]
                                );
                            }
                        }
                    }

                    CryptDestroyHash(hash);
                }

                CryptReleaseContext(provider, 0);
            }

            CloseHandle(file);
            return digest;
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

        std::filesystem::path BaselineFilePath(
            const std::string& gameHash
        ) const {
            return baselineDirectory_ / (gameHash + ".baseline");
        }

        bool LoadFromDisk(const std::string& gameHash) {
            if (gameHash.empty()) {
                return false;
            }

            const auto path = BaselineFilePath(gameHash);
            std::ifstream input(path, std::ios::binary);

            if (!input.is_open()) {
                return false;
            }

            BaselineSnapshot loaded{};
            loaded.gameImageHash = gameHash;

            std::string line;

            while (std::getline(input, line)) {
                if (line.empty() || line[0] == '#') {
                    continue;
                }

                const auto separator = line.find('=');

                if (separator == std::string::npos) {
                    continue;
                }

                const std::string key = line.substr(0, separator);
                const std::string value = line.substr(separator + 1);

                if (key == "main_path") {
                    loaded.mainModulePath = value;
                } else if (key == "main_text_crc") {
                    loaded.mainTextCrc =
                        static_cast<std::uint32_t>(
                            std::strtoul(value.c_str(), nullptr, 10)
                        );
                } else if (key == "module") {
                    const auto pipe = value.find('|');

                    if (pipe == std::string::npos) {
                        loaded.moduleNames.insert(ToLower(value));
                    } else {
                        const std::string name =
                            ToLower(value.substr(0, pipe));
                        const std::uint32_t crc =
                            static_cast<std::uint32_t>(
                                std::strtoul(
                                    value.c_str() + pipe + 1,
                                    nullptr,
                                    10
                                )
                            );

                        loaded.moduleNames.insert(name);
                        loaded.moduleTextCrc[name] = crc;
                    }
                }
            }

            if (loaded.moduleNames.empty()) {
                return false;
            }

            loaded.established = true;
            loaded.loadedFromDisk = true;
            snapshot_ = std::move(loaded);
            return true;
        }

        bool SaveToDisk() const {
            if (
                !snapshot_.established ||
                snapshot_.gameImageHash.empty()
            ) {
                return false;
            }

            std::error_code error;
            std::filesystem::create_directories(
                baselineDirectory_,
                error
            );

            const auto path =
                BaselineFilePath(snapshot_.gameImageHash);

            std::ofstream output(path, std::ios::binary | std::ios::trunc);

            if (!output.is_open()) {
                return false;
            }

            output
                << "schema=1\n"
                << "game_hash=" << snapshot_.gameImageHash << '\n'
                << "main_path=" << snapshot_.mainModulePath << '\n'
                << "main_text_crc=" << snapshot_.mainTextCrc << '\n';

            for (const std::string& name : snapshot_.moduleNames) {
                output << "module=" << name;

                const auto crcIterator =
                    snapshot_.moduleTextCrc.find(name);

                if (crcIterator != snapshot_.moduleTextCrc.end()) {
                    output << '|' << crcIterator->second;
                }

                output << '\n';
            }

            return output.good();
        }

    public:
        void SetBaselineDirectory(
            const std::filesystem::path& directory
        ) {
            baselineDirectory_ = directory;
        }

        void Reset() {
            snapshot_ = BaselineSnapshot{};
        }

        bool Established() const {
            return snapshot_.established;
        }

        bool LoadedFromDisk() const {
            return snapshot_.loadedFromDisk;
        }

        DWORD ProcessId() const {
            return snapshot_.processId;
        }

        const std::string& GameImageHash() const {
            return snapshot_.gameImageHash;
        }

        /*
         * Försök ladda persistent baseline för game build.
         * Om ingen finns: skapa från nuvarande session och spara.
         */
        void Establish(
            DWORD processId,
            HANDLE processHandle,
            const std::vector<std::pair<std::string, std::uintptr_t>>&
                modules,
            const std::string& mainModulePath,
            std::uintptr_t mainModuleBase,
            bool persistToDisk = true
        ) {
            const std::string gameHash =
                ComputeFileSha256(mainModulePath);

            if (
                persistToDisk &&
                !gameHash.empty() &&
                LoadFromDisk(gameHash)
            ) {
                snapshot_.processId = processId;
                snapshot_.mainModuleBase = mainModuleBase;

                if (snapshot_.mainModulePath.empty()) {
                    snapshot_.mainModulePath = mainModulePath;
                }

                return;
            }

            Reset();

            snapshot_.processId = processId;
            snapshot_.mainModulePath = mainModulePath;
            snapshot_.mainModuleBase = mainModuleBase;
            snapshot_.gameImageHash = gameHash;
            snapshot_.loadedFromDisk = false;

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

            if (persistToDisk && !gameHash.empty()) {
                SaveToDisk();
            }
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
            result.loadedFromDisk = snapshot_.loadedFromDisk;

            if (!snapshot_.established) {
                return result;
            }

            for (const auto& module : modules) {
                const std::string name = ToLower(module.first);

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
                        snapshot_.loadedFromDisk
                            ? "Module not present in persistent baseline for this game build"
                            : "Module appeared after session baseline was established"
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
                        "Module .text CRC changed versus baseline"
                    );
                    result.findings.push_back(std::move(finding));
                }
            }

            return result;
        }
    };

} // namespace Mjolnir
