#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <system_error>
#include <unordered_map>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#endif

namespace Mjolnir {

    struct FileIntegrityInfo {
        std::string path;
        std::string sha256;
        std::string publisher;

        bool exists = false;
        bool signedFile = false;
        bool signatureValid = false;
        bool microsoftPublisher = false;
        bool fromCache = false;

        DWORD errorCode = ERROR_SUCCESS;
        std::vector<std::string> reasons;
    };

    class IntegrityChecker {
    private:
        struct CacheEntry {
            FileIntegrityInfo info;
            std::filesystem::file_time_type writeTime{};
            std::chrono::steady_clock::time_point cachedAt{};
        };

        inline static std::mutex cacheMutex_;
        inline static std::unordered_map<std::string, CacheEntry>
            cache_;

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

            std::wstring result(
                static_cast<std::size_t>(requiredSize),
                L'\0'
            );

            MultiByteToWideChar(
                CP_UTF8,
                0,
                value.c_str(),
                static_cast<int>(value.size()),
                result.data(),
                requiredSize
            );

            return result;
        }

        static std::string BytesToHex(
            const std::uint8_t* data,
            std::size_t length
        ) {
            std::ostringstream hex;

            hex << std::hex << std::setfill('0');

            for (std::size_t index = 0; index < length; ++index) {
                hex << std::setw(2)
                    << static_cast<int>(data[index]);
            }

            return hex.str();
        }

        static std::string NormalizeCacheKey(
            const std::string& filePath
        ) {
            return ToLower(filePath);
        }

    public:
        static std::string ComputeSha256(
            const std::string& filePath
        ) {
            const std::wstring widePath =
                Utf8ToWide(filePath);

            HANDLE fileHandle = CreateFileW(
                widePath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ |
                FILE_SHARE_WRITE |
                FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            if (
                fileHandle == nullptr ||
                fileHandle == INVALID_HANDLE_VALUE
            ) {
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
                    std::vector<std::uint8_t> buffer(
                        1024 * 1024
                    );

                    DWORD bytesRead = 0;
                    bool success = true;

                    while (
                        ReadFile(
                            fileHandle,
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
                            success = false;
                            break;
                        }
                    }

                    if (success) {
                        DWORD hashSize = 0;
                        DWORD hashSizeLength =
                            sizeof(hashSize);

                        if (
                            CryptGetHashParam(
                                hash,
                                HP_HASHSIZE,
                                reinterpret_cast<BYTE*>(
                                    &hashSize
                                ),
                                &hashSizeLength,
                                0
                            )
                        ) {
                            std::vector<std::uint8_t>
                                hashBytes(hashSize);

                            if (
                                CryptGetHashParam(
                                    hash,
                                    HP_HASHVAL,
                                    hashBytes.data(),
                                    &hashSize,
                                    0
                                )
                            ) {
                                digest = BytesToHex(
                                    hashBytes.data(),
                                    hashBytes.size()
                                );
                            }
                        }
                    }

                    CryptDestroyHash(hash);
                }

                CryptReleaseContext(provider, 0);
            }

            CloseHandle(fileHandle);
            return ToLower(digest);
        }

        static bool VerifyEmbeddedSignature(
            const std::string& filePath
        ) {
            const std::wstring widePath =
                Utf8ToWide(filePath);

            WINTRUST_FILE_INFO fileInfo{};
            fileInfo.cbStruct = sizeof(fileInfo);
            fileInfo.pcwszFilePath = widePath.c_str();
            fileInfo.hFile = nullptr;
            fileInfo.pgKnownSubject = nullptr;

            GUID policy =
                WINTRUST_ACTION_GENERIC_VERIFY_V2;

            WINTRUST_DATA trustData{};
            trustData.cbStruct = sizeof(trustData);
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks =
                WTD_REVOKE_NONE;
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.pFile = &fileInfo;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;
            trustData.dwProvFlags =
                WTD_CACHE_ONLY_URL_RETRIEVAL;

            const LONG status = WinVerifyTrust(
                static_cast<HWND>(INVALID_HANDLE_VALUE),
                &policy,
                &trustData
            );

            trustData.dwStateAction =
                WTD_STATEACTION_CLOSE;

            WinVerifyTrust(
                static_cast<HWND>(INVALID_HANDLE_VALUE),
                &policy,
                &trustData
            );

            return status == ERROR_SUCCESS;
        }

        static std::string ExtractPublisher(
            const std::string& filePath
        ) {
            const std::wstring widePath =
                Utf8ToWide(filePath);

            HCERTSTORE certificateStore = nullptr;
            HCRYPTMSG cryptographicMessage = nullptr;

            const BOOL queried = CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                widePath.c_str(),
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                nullptr,
                nullptr,
                nullptr,
                &certificateStore,
                &cryptographicMessage,
                nullptr
            );

            if (!queried) {
                return {};
            }

            std::string publisher;
            DWORD signerInfoSize = 0;

            CryptMsgGetParam(
                cryptographicMessage,
                CMSG_SIGNER_INFO_PARAM,
                0,
                nullptr,
                &signerInfoSize
            );

            if (signerInfoSize > 0) {
                std::vector<std::uint8_t> signerBuffer(
                    signerInfoSize
                );

                if (
                    CryptMsgGetParam(
                        cryptographicMessage,
                        CMSG_SIGNER_INFO_PARAM,
                        0,
                        signerBuffer.data(),
                        &signerInfoSize
                    )
                ) {
                    auto* signerInfo =
                        reinterpret_cast<CMSG_SIGNER_INFO*>(
                            signerBuffer.data()
                        );

                    CERT_INFO certInfo{};
                    certInfo.Issuer =
                        signerInfo->Issuer;
                    certInfo.SerialNumber =
                        signerInfo->SerialNumber;

                    PCCERT_CONTEXT certificate =
                        CertFindCertificateInStore(
                            certificateStore,
                            X509_ASN_ENCODING |
                            PKCS_7_ASN_ENCODING,
                            0,
                            CERT_FIND_SUBJECT_CERT,
                            &certInfo,
                            nullptr
                        );

                    if (certificate != nullptr) {
                        const DWORD nameSize =
                            CertGetNameStringW(
                                certificate,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0,
                                nullptr,
                                nullptr,
                                0
                            );

                        if (nameSize > 1) {
                            std::wstring name(
                                nameSize,
                                L'\0'
                            );

                            CertGetNameStringW(
                                certificate,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0,
                                nullptr,
                                name.data(),
                                nameSize
                            );

                            name.resize(nameSize - 1);
                            publisher = WideToUtf8(name);
                        }

                        CertFreeCertificateContext(
                            certificate
                        );
                    }
                }
            }

            if (cryptographicMessage != nullptr) {
                CryptMsgClose(cryptographicMessage);
            }

            if (certificateStore != nullptr) {
                CertCloseStore(certificateStore, 0);
            }

            return publisher;
        }

        static FileIntegrityInfo InspectFile(
            const std::string& filePath,
            bool useCache = true
        ) {
            FileIntegrityInfo info{};
            info.path = filePath;

            if (filePath.empty()) {
                info.errorCode = ERROR_INVALID_PARAMETER;
                info.reasons.push_back("Empty file path");
                return info;
            }

            const std::wstring widePath =
                Utf8ToWide(filePath);

            const DWORD attributes =
                GetFileAttributesW(widePath.c_str());

            if (attributes == INVALID_FILE_ATTRIBUTES) {
                info.errorCode = GetLastError();
                info.reasons.push_back(
                    "File does not exist or is inaccessible"
                );
                return info;
            }

            info.exists = true;

            std::error_code filesystemError;
            const auto writeTime =
                std::filesystem::last_write_time(
                    std::filesystem::path(filePath),
                    filesystemError
                );

            const std::string cacheKey =
                NormalizeCacheKey(filePath);

            if (useCache && !filesystemError) {
                std::lock_guard<std::mutex> lock(cacheMutex_);

                const auto iterator = cache_.find(cacheKey);

                if (iterator != cache_.end()) {
                    const auto age =
                        std::chrono::steady_clock::now() -
                        iterator->second.cachedAt;

                    if (
                        iterator->second.writeTime == writeTime &&
                        age < std::chrono::minutes(10)
                    ) {
                        info = iterator->second.info;
                        info.fromCache = true;
                        return info;
                    }
                }
            }

            info.sha256 = ComputeSha256(filePath);

            if (info.sha256.empty()) {
                info.reasons.push_back(
                    "SHA-256 could not be computed"
                );
            }

            info.signatureValid =
                VerifyEmbeddedSignature(filePath);
            info.signedFile = info.signatureValid;

            if (info.signatureValid) {
                info.publisher =
                    ExtractPublisher(filePath);

                const std::string loweredPublisher =
                    ToLower(info.publisher);

                info.microsoftPublisher =
                    loweredPublisher.find("microsoft") !=
                    std::string::npos;

                info.reasons.push_back(
                    "Valid Authenticode signature"
                );
            } else {
                info.reasons.push_back(
                    "Missing or invalid Authenticode signature"
                );
            }

            if (useCache && !filesystemError) {
                std::lock_guard<std::mutex> lock(cacheMutex_);

                CacheEntry entry{};
                entry.info = info;
                entry.writeTime = writeTime;
                entry.cachedAt =
                    std::chrono::steady_clock::now();

                cache_[cacheKey] = std::move(entry);

                /*
                 * Enkel bound så cachen inte växer utan tak.
                 */
                if (cache_.size() > 512) {
                    cache_.clear();
                    cache_[cacheKey] = CacheEntry{
                        info,
                        writeTime,
                        std::chrono::steady_clock::now()
                    };
                }
            }

            return info;
        }

        static void ClearCache() {
            std::lock_guard<std::mutex> lock(cacheMutex_);
            cache_.clear();
        }
    };

} // namespace Mjolnir
