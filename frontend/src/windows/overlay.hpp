#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace Mjolnir {

    struct WindowInfo {
        HWND hWnd;
        DWORD processId;
        std::string title;
    };

    class OverlayDetector {
    private:
        static BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
            auto* windows = reinterpret_cast<std::vector<WindowInfo>*>(lParam);
            
            if (!IsWindowVisible(hwnd)) return TRUE;

            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);

            char title[256];
            GetWindowTextA(hwnd, title, sizeof(title));

            if (strlen(title) > 0) {
                windows->push_back({hwnd, pid, std::string(title)});
            }

            return TRUE;
        }

    public:
        static std::vector<WindowInfo> GetActiveWindows() {
            std::vector<WindowInfo> windows;
            EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&windows));
            return windows;
        }
    };

} // namespace Mjolnir
