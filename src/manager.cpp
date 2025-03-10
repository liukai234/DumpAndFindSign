#include <fstream>
#include <iostream>
#include <string>

#include "manager.h"
#include "mem.h"
#include "utils.h"
#include <iomanip>

void Manager::DumpMem(uintptr_t SearchBase, DWORD SearchRange, std::string path) {

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

void Manager::Init(std::string signature) {
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

unsigned int hexStringToLittleEndian(const std::string &hexString) {
    unsigned int result = 0;
    for (size_t i = hexString.length(); i > 0; i -= 2) {
        std::string byteString = hexString.substr(i - 2, 2);
        unsigned int byte;
        std::istringstream(byteString) >> std::hex >> byte;
        result = (result << 8) | byte;
    }
    return result;
}

std::string memoryToHexString(const char *memory, SIZE_T size) {
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
