#include <Windows.h>
#include <fstream>
#include <iostream>
#include <string>

#include "dbg.h"
#include "defs.h"
#include "manager.h"
#include "mem.h"
#include "utils.h"

DWORD MainThread(HMODULE Module) {
    // dll output to console
    // AllocConsole();
    // FILE* Dummy;
    // freopen_s(&Dummy, "CONOUT$", "w", stdout);
    // freopen_s(&Dummy, "CONIN$", "r", stdin);

    // dll output to file
    std::ofstream outfile("dumper_output.log");
    std::cout.rdbuf(outfile.rdbuf()); // 将 std::cout 的缓冲区替换为文件的缓冲区

    auto t_1 = std::chrono::high_resolution_clock::now();

    std::cout << "Started Dumper" << std::endl;
    std::cout << "Image Base: " << GetImageBase() << '\n' << std::endl;

    Manager::Init("48 8D 15 08 C4 02 ?? E8 63 ?? ?? ??");

    auto t_C = std::chrono::high_resolution_clock::now();
    auto ms_int_ =
        std::chrono::duration_cast<std::chrono::milliseconds>(t_C - t_1);
    std::chrono::duration<double, std::milli> ms_double_ = t_C - t_1;
    std::cout << "Dump took (" << ms_double_.count() << "ms)" << std::endl;

    while (true) {
        if (GetAsyncKeyState(VK_F6) & 1) {
            // fclose(stdout);
            // if (Dummy) fclose(Dummy);

            outfile.close();
            FreeLibraryAndExitThread(Module, 0);
        }

        Sleep(100);
    }

    return 0;
}

LRESULT CALLBACK GetMsgProc(int nCode, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

extern "C" __declspec(dllexport) void CALLBACK Inject(HWND hwnd,
                                                      HINSTANCE hinst,
                                                      LPSTR pszCmdLine,
                                                      int nCmdShow) {
    std::string windowHandle = pszCmdLine;
    auto threadId = GetWindowThreadProcessId(
        (HWND)std::stoul(windowHandle, nullptr, 0), NULL);
    auto hhook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)GetMsgProc,
                                  (HINSTANCE)&__ImageBase, threadId);
    Sleep(5000);
}

BOOL IsRunDll32() {
    char szMainModulePath[MAX_PATH];
    DWORD dwMainModulePathLength =
        GetModuleFileNameA(NULL, szMainModulePath, sizeof(szMainModulePath));

    return dwMainModulePathLength > 13 &&
           _stricmp(szMainModulePath + dwMainModulePathLength - 13,
                    "\\rundll32.exe") == 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        if (!IsRunDll32()) {
            GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                               (LPCSTR)hModule, &hModule);
            CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread,
                         hModule, 0, nullptr);
        } else {
            CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread,
                         hModule, 0, nullptr);
        }

        break;
    }

    return TRUE;
}
