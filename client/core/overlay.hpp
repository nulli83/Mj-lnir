#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <dwmapi.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "user32.lib")
#endif

namespace Mjolnir {

    struct WindowInfo {
        HWND hWnd = nullptr;
        DWORD processId = 0;

        std::string title;
        std::string className;
        std::string processName;
        std::string processPath;

        RECT bounds{};

        LONG_PTR style = 0;
        LONG_PTR extendedStyle = 0;

        bool visible = false;
        bool cloaked = false;
        bool layered = false;
        bool transparent = false;
        bool topmost = false;
        bool toolWindow = false;
        bool noActivate = false;
        bool trustedProcess = false;

        // Hur stor del av spelets fönster som täcks.
        double targetCoverage = 0.0;

        // Hur stor del av overlay-fönstret som ligger ovanpå spelet.
        double overlayCoverage = 0.0;

        int riskScore = 0;
        std::vector<std::string> reasons;
    };

    class OverlayDetector {
    private:
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

        struct MainWindowSearchContext {
            DWORD targetPid = 0;
            HWND result = nullptr;
        };

        struct EnumerationContext {
            DWORD targetPid = 0;
            HWND targetWindow = nullptr;
            RECT targetBounds{};
            int riskThreshold = 40;

            const std::unordered_set<std::string>* allowedProcesses = nullptr;
            std::vector<WindowInfo>* results = nullptr;
        };

        static std::string ToLower(std::string value) {
            std::transform(
                value.begin(),
                value.end(),
                value.begin(),
                [](unsigned char character) {
                    return static_cast<char>(std::tolower(character));
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
            const std::size_t separator = path.find_last_of("\\/");

            if (separator == std::string::npos) {
                return path;
            }

            return path.substr(separator + 1);
        }

        static std::string GetWindowTitle(HWND hwnd) {
            const int titleLength = GetWindowTextLengthW(hwnd);

            if (titleLength <= 0) {
                return {};
            }

            std::wstring title(
                static_cast<std::size_t>(titleLength + 1),
                L'\0'
            );

            const int copiedCharacters = GetWindowTextW(
                hwnd,
                title.data(),
                static_cast<int>(title.size())
            );

            if (copiedCharacters <= 0) {
                return {};
            }

            title.resize(static_cast<std::size_t>(copiedCharacters));
            return WideToUtf8(title);
        }

        static std::string GetWindowClassName(HWND hwnd) {
            wchar_t className[512]{};

            const int copiedCharacters = GetClassNameW(
                hwnd,
                className,
                static_cast<int>(std::size(className))
            );

            if (copiedCharacters <= 0) {
                return {};
            }

            return WideToUtf8(
                std::wstring(
                    className,
                    static_cast<std::size_t>(copiedCharacters)
                )
            );
        }

        static std::string GetProcessPath(DWORD pid) {
            ScopedHandle processHandle(
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    pid
                )
            );

            if (!processHandle.IsValid()) {
                return {};
            }

            std::wstring path(32768, L'\0');
            DWORD pathLength = static_cast<DWORD>(path.size());

            if (!QueryFullProcessImageNameW(
                    processHandle.Get(),
                    0,
                    path.data(),
                    &pathLength
                )) {
                return {};
            }

            path.resize(pathLength);
            return WideToUtf8(path);
        }

        static bool GetWindowBounds(HWND hwnd, RECT& bounds) {
            const HRESULT result = DwmGetWindowAttribute(
                hwnd,
                DWMWA_EXTENDED_FRAME_BOUNDS,
                &bounds,
                sizeof(bounds)
            );

            if (SUCCEEDED(result)) {
                return true;
            }

            return GetWindowRect(hwnd, &bounds) != FALSE;
        }

        static bool IsWindowCloaked(HWND hwnd) {
            DWORD cloaked = 0;

            const HRESULT result = DwmGetWindowAttribute(
                hwnd,
                DWMWA_CLOAKED,
                &cloaked,
                sizeof(cloaked)
            );

            return SUCCEEDED(result) && cloaked != 0;
        }

        static std::int64_t CalculateArea(const RECT& rectangle) {
            const std::int64_t width = std::max<std::int64_t>(
                0,
                static_cast<std::int64_t>(rectangle.right) -
                static_cast<std::int64_t>(rectangle.left)
            );

            const std::int64_t height = std::max<std::int64_t>(
                0,
                static_cast<std::int64_t>(rectangle.bottom) -
                static_cast<std::int64_t>(rectangle.top)
            );

            return width * height;
        }

        static RECT CalculateIntersection(
            const RECT& first,
            const RECT& second
        ) {
            RECT intersection{};

            intersection.left = std::max(first.left, second.left);
            intersection.top = std::max(first.top, second.top);
            intersection.right = std::min(first.right, second.right);
            intersection.bottom = std::min(first.bottom, second.bottom);

            if (
                intersection.right <= intersection.left ||
                intersection.bottom <= intersection.top
            ) {
                return RECT{};
            }

            return intersection;
        }

        static bool IsSuspiciousPath(const std::string& processPath) {
            const std::string path = ToLower(processPath);

            static const std::vector<std::string> suspiciousSegments = {
                "\\appdata\\local\\temp\\",
                "\\windows\\temp\\",
                "\\downloads\\",
                "\\public\\downloads\\"
            };

            for (const std::string& segment : suspiciousSegments) {
                if (path.find(segment) != std::string::npos) {
                    return true;
                }
            }

            return false;
        }

        static void AddRisk(
            WindowInfo& window,
            int amount,
            const std::string& reason
        ) {
            window.riskScore += amount;
            window.reasons.push_back(reason);
        }

        static void CalculateRisk(WindowInfo& window) {
            if (window.layered) {
                AddRisk(
                    window,
                    15,
                    "Window uses WS_EX_LAYERED"
                );
            }

            if (window.transparent) {
                AddRisk(
                    window,
                    25,
                    "Window uses WS_EX_TRANSPARENT"
                );
            }

            if (window.topmost) {
                AddRisk(
                    window,
                    15,
                    "Window is always-on-top"
                );
            }

            if (window.toolWindow) {
                AddRisk(
                    window,
                    5,
                    "Window uses WS_EX_TOOLWINDOW"
                );
            }

            if (window.noActivate) {
                AddRisk(
                    window,
                    10,
                    "Window uses WS_EX_NOACTIVATE"
                );
            }

            if (
                window.layered &&
                window.transparent &&
                window.topmost
            ) {
                AddRisk(
                    window,
                    20,
                    "Layered, click-through and topmost combination"
                );
            }

            if (window.title.empty()) {
                AddRisk(
                    window,
                    5,
                    "Window has no visible title"
                );
            }

            if (window.targetCoverage >= 0.80) {
                AddRisk(
                    window,
                    25,
                    "Window covers at least 80 percent of target"
                );
            } else if (window.targetCoverage >= 0.25) {
                AddRisk(
                    window,
                    15,
                    "Window covers at least 25 percent of target"
                );
            } else if (window.overlayCoverage >= 0.80) {
                AddRisk(
                    window,
                    10,
                    "Most of the overlay is positioned over target"
                );
            }

            if (IsSuspiciousPath(window.processPath)) {
                AddRisk(
                    window,
                    30,
                    "Process runs from a suspicious directory"
                );
            }

            if (window.processName.empty()) {
                AddRisk(
                    window,
                    10,
                    "Process identity could not be resolved"
                );
            } else if (!window.trustedProcess) {
                AddRisk(
                    window,
                    10,
                    "Overlay process is not whitelisted"
                );
            }

            if (window.trustedProcess) {
                window.riskScore = std::max(
                    0,
                    window.riskScore - 30
                );

                window.reasons.push_back(
                    "Risk reduced because process is whitelisted"
                );
            }
        }

        static BOOL CALLBACK FindMainWindowCallback(
            HWND hwnd,
            LPARAM lParam
        ) {
            auto* context =
                reinterpret_cast<MainWindowSearchContext*>(lParam);

            if (!context) {
                return FALSE;
            }

            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);

            if (pid != context->targetPid) {
                return TRUE;
            }

            if (!IsWindowVisible(hwnd)) {
                return TRUE;
            }

            if (IsIconic(hwnd)) {
                return TRUE;
            }

            if (GetWindow(hwnd, GW_OWNER) != nullptr) {
                return TRUE;
            }

            context->result = hwnd;
            return FALSE;
        }

        static HWND FindMainWindow(DWORD targetPid) {
            MainWindowSearchContext context{};
            context.targetPid = targetPid;

            EnumWindows(
                FindMainWindowCallback,
                reinterpret_cast<LPARAM>(&context)
            );

            return context.result;
        }

        static BOOL CALLBACK EnumWindowsCallback(
            HWND hwnd,
            LPARAM lParam
        ) {
            auto* context =
                reinterpret_cast<EnumerationContext*>(lParam);

            if (
                !context ||
                !context->results ||
                !context->allowedProcesses
            ) {
                return FALSE;
            }

            if (hwnd == context->targetWindow) {
                return TRUE;
            }

            if (!IsWindowVisible(hwnd)) {
                return TRUE;
            }

            if (IsIconic(hwnd)) {
                return TRUE;
            }

            if (IsWindowCloaked(hwnd)) {
                return TRUE;
            }

            DWORD processId = 0;
            GetWindowThreadProcessId(hwnd, &processId);

            if (
                processId == 0 ||
                processId == context->targetPid ||
                processId == GetCurrentProcessId()
            ) {
                return TRUE;
            }

            RECT windowBounds{};

            if (!GetWindowBounds(hwnd, windowBounds)) {
                return TRUE;
            }

            const RECT intersection = CalculateIntersection(
                context->targetBounds,
                windowBounds
            );

            const std::int64_t intersectionArea =
                CalculateArea(intersection);

            if (intersectionArea <= 0) {
                return TRUE;
            }

            const std::int64_t targetArea =
                CalculateArea(context->targetBounds);

            const std::int64_t overlayArea =
                CalculateArea(windowBounds);

            if (targetArea <= 0 || overlayArea <= 0) {
                return TRUE;
            }

            WindowInfo window{};
            window.hWnd = hwnd;
            window.processId = processId;
            window.title = GetWindowTitle(hwnd);
            window.className = GetWindowClassName(hwnd);
            window.processPath = GetProcessPath(processId);
            window.processName = GetBaseName(window.processPath);
            window.bounds = windowBounds;
            window.visible = true;

            window.style = GetWindowLongPtrW(hwnd, GWL_STYLE);
            window.extendedStyle =
                GetWindowLongPtrW(hwnd, GWL_EXSTYLE);

            window.layered =
                (window.extendedStyle & WS_EX_LAYERED) != 0;

            window.transparent =
                (window.extendedStyle & WS_EX_TRANSPARENT) != 0;

            window.topmost =
                (window.extendedStyle & WS_EX_TOPMOST) != 0;

            window.toolWindow =
                (window.extendedStyle & WS_EX_TOOLWINDOW) != 0;

            window.noActivate =
                (window.extendedStyle & WS_EX_NOACTIVATE) != 0;

            window.targetCoverage =
                static_cast<double>(intersectionArea) /
                static_cast<double>(targetArea);

            window.overlayCoverage =
                static_cast<double>(intersectionArea) /
                static_cast<double>(overlayArea);

            const std::string normalizedProcessName =
                ToLower(window.processName);

            window.trustedProcess =
                context->allowedProcesses->find(
                    normalizedProcessName
                ) != context->allowedProcesses->end();

            CalculateRisk(window);

            if (window.riskScore >= context->riskThreshold) {
                context->results->push_back(std::move(window));
            }

            return TRUE;
        }

    public:
        static std::vector<WindowInfo> DetectSuspiciousOverlays(
            DWORD targetPid,
            const std::unordered_set<std::string>& allowedProcesses = {},
            int riskThreshold = 40
        ) {
            std::vector<WindowInfo> suspiciousWindows;

            if (targetPid == 0) {
                return suspiciousWindows;
            }

            const HWND targetWindow = FindMainWindow(targetPid);

            if (!targetWindow) {
                return suspiciousWindows;
            }

            RECT targetBounds{};

            if (!GetWindowBounds(targetWindow, targetBounds)) {
                return suspiciousWindows;
            }

            std::unordered_set<std::string> normalizedAllowedProcesses;

            for (const std::string& process : allowedProcesses) {
                normalizedAllowedProcesses.insert(
                    ToLower(process)
                );
            }

            EnumerationContext context{};
            context.targetPid = targetPid;
            context.targetWindow = targetWindow;
            context.targetBounds = targetBounds;
            context.riskThreshold = std::max(0, riskThreshold);
            context.allowedProcesses = &normalizedAllowedProcesses;
            context.results = &suspiciousWindows;

            EnumWindows(
                EnumWindowsCallback,
                reinterpret_cast<LPARAM>(&context)
            );

            std::sort(
                suspiciousWindows.begin(),
                suspiciousWindows.end(),
                [](const WindowInfo& first, const WindowInfo& second) {
                    return first.riskScore > second.riskScore;
                }
            );

            return suspiciousWindows;
        }
    };

} // namespace Mjolnir
