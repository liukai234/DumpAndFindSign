#include <Windows.h>
#include <fstream>
#include <iostream>
#include <string>

#include "dbg.h"
#include "defs.h"
#include "mem.h"
#include "utils.h"

unsigned int hexStringToLittleEndian(const std::string& hexString) {
	unsigned int result = 0;
	for (size_t i = hexString.length(); i > 0; i -= 2) {
		std::string byteString = hexString.substr(i - 2, 2);
		unsigned int byte;
		std::istringstream(byteString) >> std::hex >> byte;
		result = (result << 8) | byte;
	}
	return result;
}

std::string memoryToHexString(const char* memory, SIZE_T size) {
	std::ostringstream oss;
	for (SIZE_T i = 0; i < size; ++i) {
		if (i > 0) {
			oss << " ";
		}
		oss << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
			<< static_cast<int>(static_cast<unsigned char>(memory[i]));
	}
	return oss.str();
}

void DumpMem(uintptr_t SearchBase, DWORD SearchRange, std::string path) {

    std::ofstream dumpFile(path, std::ios::binary);

    const size_t bufferSize = 4096;
    char buffer[bufferSize];

    for (size_t i = 0; i < SearchRange; i += bufferSize) {
        size_t remaining = SearchRange - i;
        size_t toRead = (remaining < bufferSize) ? remaining : bufferSize;

        auto CurrentAddress = reinterpret_cast<const char *>(SearchBase + i);

        memcpy(buffer, CurrentAddress, toRead);
        dumpFile.write(buffer, toRead);
    }
}

void Init(std::string signature) {
    std::cout << "[Enter] void Init(std::string signature)" << std::endl;

    const auto [ImageBase, ImageSize] = GetImageBaseAndSize();
    std::cout << "ImageBase: " << std::hex << ImageBase << std::dec
              << " ImageSize: " << ImageSize << std::endl;

    // MemDump
    // std::cout << "MemDump Start" << std::endl;
    // DumpMem(ImageBase, ImageSize, "dumper7_memscan.bin");
    // return;

    void *signatureAddress =
        scan_idastyle((void *)ImageBase, ImageSize, signature);
    if (!signatureAddress) {
        std::cout << "signature [ " << signature << " ] NOT found" << std::endl;
    }

    std::cout << "signature [ " << signature << " ] found: " << std::hex
              << signatureAddress << std::dec << std::endl;

    // Locate global var
    const int signatureOffsets = 0x36;

    // memcpy(buffer, reinterpret_cast<const char *>(signatureAddress + 0x39),
    // 8); auto ObjectArrayOffset =
    //     hexStringToLittleEndian(memoryToHexString(buffer, 8));
    // std::cout << "GUObjectArraySignatureOffset: " << std::hex
    //           << ObjectArrayOffset << std::dec << std::endl;

    // auto ObjectArray = signatureAddress + 0x36 + ObjectArrayOffset +
    //                    0x1; // lea rcx,[rip+0xf815555] to GObjects addr
    // std::cout << "ObjectArray: " << std::hex << ObjectArray << std::dec
    //           << std::endl;

    // Decrypt
    // auto temp = __ROL4__(ObjectArray ^ 0xFAACB5FC, 10);
    // auto ObjectArrayDecrypt = temp ^ (temp << 16) ^ 0x10E4EC2C;
    // std::cout << "ObjectArrayDecrypt: " << std::hex << ObjectArrayDecrypt
    //           << std::dec << std::endl;

    // // Init(/*GObjects*/ObjectArrayDecrypt, /*ChunkSize*/0x10000,
    // // /*bIsChunked*/true);

    // std::cout << "ObjectArray::Init" << std::endl;
    return;
}

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

    Init("48 8D 15 08 C4 02 ?? E8 63 ?? ?? ??");

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
