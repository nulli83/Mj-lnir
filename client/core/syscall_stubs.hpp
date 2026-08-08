#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <psapi.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "psapi.lib")

namespace Mjolnir {

    struct SyscallStubFinding {
        std::string moduleName;
        std::string functionName;
        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    struct SyscallStubScanResult {
        std::vector<SyscallStubFinding> findings;
        std::size_t stubsChecked = 0;
        DWORD errorCode = ERROR_SUCCESS;

        bool Success() const {
            return errorCode == ERROR_SUCCESS;
        }
    };

    /*
     * Jämför prologues för kritiska Nt*/Zw* stubs i remote ntdll
     * mot lokala stubs. Inline JMP / trampolines eller trasiga
     * syscall-sekvenser är starka tecken på usermode hooks /
     * "direct syscalls"-bypass-lager.
     */
    class SyscallStubScanner {
    private:
        static bool ReadBytes(
            HANDLE process,
            std::uintptr_t address,
            void* buffer,
            std::size_t size
        ) {
            SIZE_T bytesRead = 0;
            return ReadProcessMemory(
                       process,
                       reinterpret_cast<LPCVOID>(address),
                       buffer,
                       size,
                       &bytesRead
                   ) != FALSE &&
                   bytesRead == size;
        }

        static bool LooksLikeInlineHook(const std::uint8_t* bytes) {
            return
                bytes[0] == 0xE9 ||                 // jmp rel32
                bytes[0] == 0xE8 ||                 // call rel32
                (bytes[0] == 0xFF && bytes[1] == 0x25) || // jmp [rip+imm]
                (bytes[0] == 0x48 && bytes[1] == 0xB8) || // mov rax, imm64
                (bytes[0] == 0x48 && bytes[1] == 0xFF && bytes[2] == 0x25);
        }

        static bool LooksLikeSyscallStub(const std::uint8_t* bytes) {
            /*
             * Vanlig x64 ntdll-stub:
             *   4C 8B D1       mov r10, rcx
             *   B8 xx xx xx xx mov eax, SSN
             *   ... optional test/jne ...
             *   0F 05          syscall
             */
            if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1) {
                return true;
            }

            /*
             * Vissa builds börjar med mov eax direkt.
             */
            if (bytes[0] == 0xB8) {
                return true;
            }

            return false;
        }

        static std::uintptr_t FindRemoteNtdll(HANDLE process) {
            HMODULE modules[512] = {};
            DWORD needed = 0;

            if (
                !EnumProcessModulesEx(
                    process,
                    modules,
                    sizeof(modules),
                    &needed,
                    LIST_MODULES_ALL
                )
            ) {
                return 0;
            }

            const DWORD count = needed / sizeof(HMODULE);
            for (DWORD index = 0; index < count; ++index) {
                wchar_t path[MAX_PATH] = {};
                if (
                    GetModuleFileNameExW(
                        process,
                        modules[index],
                        path,
                        MAX_PATH
                    ) == 0
                ) {
                    continue;
                }

                const wchar_t* file = path;
                for (wchar_t* cursor = path; *cursor != L'\0'; ++cursor) {
                    if (*cursor == L'\\' || *cursor == L'/') {
                        file = cursor + 1;
                    }
                }

                if (_wcsicmp(file, L"ntdll.dll") == 0) {
                    return reinterpret_cast<std::uintptr_t>(modules[index]);
                }
            }

            return 0;
        }

        static std::uintptr_t RemoteExportAddress(
            HANDLE process,
            std::uintptr_t moduleBase,
            const char* name
        ) {
            IMAGE_DOS_HEADER dos{};
            if (
                !ReadBytes(process, moduleBase, &dos, sizeof(dos)) ||
                dos.e_magic != IMAGE_DOS_SIGNATURE
            ) {
                return 0;
            }

            IMAGE_NT_HEADERS64 nt{};
            if (
                !ReadBytes(
                    process,
                    moduleBase + static_cast<std::uintptr_t>(dos.e_lfanew),
                    &nt,
                    sizeof(nt)
                ) ||
                nt.Signature != IMAGE_NT_SIGNATURE
            ) {
                return 0;
            }

            const auto& dir =
                nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (dir.VirtualAddress == 0) {
                return 0;
            }

            IMAGE_EXPORT_DIRECTORY exports{};
            if (
                !ReadBytes(
                    process,
                    moduleBase + dir.VirtualAddress,
                    &exports,
                    sizeof(exports)
                )
            ) {
                return 0;
            }

            for (DWORD index = 0; index < exports.NumberOfNames; ++index) {
                DWORD nameRva = 0;
                if (
                    !ReadBytes(
                        process,
                        moduleBase + exports.AddressOfNames + index * sizeof(DWORD),
                        &nameRva,
                        sizeof(nameRva)
                    )
                ) {
                    continue;
                }

                char remoteName[64] = {};
                if (
                    !ReadBytes(
                        process,
                        moduleBase + nameRva,
                        remoteName,
                        sizeof(remoteName) - 1
                    )
                ) {
                    continue;
                }

                if (std::strcmp(remoteName, name) != 0) {
                    continue;
                }

                WORD ordinal = 0;
                if (
                    !ReadBytes(
                        process,
                        moduleBase +
                            exports.AddressOfNameOrdinals +
                            index * sizeof(WORD),
                        &ordinal,
                        sizeof(ordinal)
                    )
                ) {
                    return 0;
                }

                DWORD funcRva = 0;
                if (
                    !ReadBytes(
                        process,
                        moduleBase +
                            exports.AddressOfFunctions +
                            ordinal * sizeof(DWORD),
                        &funcRva,
                        sizeof(funcRva)
                    )
                ) {
                    return 0;
                }

                return moduleBase + funcRva;
            }

            return 0;
        }

    public:
        static SyscallStubScanResult ScanCriticalStubs(
            HANDLE process,
            int baseWeight = 60
        ) {
            SyscallStubScanResult result{};

            if (process == nullptr) {
                result.errorCode = ERROR_INVALID_HANDLE;
                return result;
            }

            HMODULE localNtdll = GetModuleHandleW(L"ntdll.dll");
            const std::uintptr_t remoteNtdll = FindRemoteNtdll(process);

            if (localNtdll == nullptr || remoteNtdll == 0) {
                result.errorCode = ERROR_MOD_NOT_FOUND;
                return result;
            }

            static const char* kExports[] = {
                "NtProtectVirtualMemory",
                "NtWriteVirtualMemory",
                "NtReadVirtualMemory",
                "NtOpenProcess",
                "NtCreateThreadEx",
                "NtAllocateVirtualMemory",
                "NtMapViewOfSection",
                "NtQueryInformationProcess",
                "NtQuerySystemInformation",
                "NtSetInformationThread",
                "NtGetContextThread",
                "NtSetContextThread",
                "NtSuspendThread",
                "NtResumeThread",
            };

            for (const char* exportName : kExports) {
                FARPROC localProc = GetProcAddress(localNtdll, exportName);
                if (localProc == nullptr) {
                    continue;
                }

                const std::uintptr_t remoteAddress =
                    RemoteExportAddress(process, remoteNtdll, exportName);
                if (remoteAddress == 0) {
                    continue;
                }

                ++result.stubsChecked;

                std::uint8_t localBytes[16] = {};
                std::uint8_t remoteBytes[16] = {};
                std::memcpy(localBytes, reinterpret_cast<const void*>(localProc), sizeof(localBytes));

                if (!ReadBytes(process, remoteAddress, remoteBytes, sizeof(remoteBytes))) {
                    continue;
                }

                SyscallStubFinding finding{};
                finding.moduleName = "ntdll.dll";
                finding.functionName = exportName;
                finding.riskScore = baseWeight;

                if (LooksLikeInlineHook(remoteBytes)) {
                    finding.reasons.push_back(
                        "Stub prologue looks like an inline trampoline/JMP"
                    );
                }

                if (
                    LooksLikeSyscallStub(localBytes) &&
                    !LooksLikeSyscallStub(remoteBytes)
                ) {
                    finding.reasons.push_back(
                        "Expected syscall stub pattern is missing remotely"
                    );
                }

                /*
                 * SSN (mov eax imm32) kan skilja sig mellan builds, men
                 * första tre byten (mov r10, rcx) bör matcha lokalt.
                 * Jämför bytes 0-2 och 8-15; tillåt differens på SSN.
                 */
                if (
                    localBytes[0] == 0x4C &&
                    localBytes[1] == 0x8B &&
                    localBytes[2] == 0xD1 &&
                    (
                        remoteBytes[0] != localBytes[0] ||
                        remoteBytes[1] != localBytes[1] ||
                        remoteBytes[2] != localBytes[2]
                    )
                ) {
                    finding.reasons.push_back(
                        "mov r10, rcx prologue mismatch versus local ntdll"
                    );
                }

                if (!finding.reasons.empty()) {
                    if (finding.reasons.size() > 1) {
                        finding.riskScore += 15;
                    }
                    result.findings.push_back(std::move(finding));
                }
            }

            return result;
        }
    };

} // namespace Mjolnir
