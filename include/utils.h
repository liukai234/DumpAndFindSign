#ifndef UTILS_H
#define UTILS_H

#include <Windows.h>
#include <utility>

struct CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

struct TEB {
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    struct PEB *ProcessEnvironmentBlock;
};

struct PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    BYTE MoreFunnyPadding[0x3];
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    BYTE MoreFunnyPadding2[0x7];
    HANDLE ShutdownThreadId;
};

struct PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN SpareBits : 1;
        };
    };
    BYTE ManuallyAddedPaddingCauseTheCompilerIsStupid
        [0x4]; // It doesn't 0x8 byte align the pointers properly
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PEB_LDR_DATA *Ldr;
};

inline _TEB *_NtCurrentTeb() {
    return reinterpret_cast<struct _TEB *>(
        __readgsqword(((LONG) __builtin_offsetof(NT_TIB, Self))));
}

inline PEB *GetPEB() {
    return reinterpret_cast<TEB *>(_NtCurrentTeb())->ProcessEnvironmentBlock;
}

inline uintptr_t GetImageBase() {
    return reinterpret_cast<uintptr_t>(GetPEB()->ImageBaseAddress);
}

inline std::pair<uintptr_t, uintptr_t> GetImageBaseAndSize() {
    uintptr_t ImageBase = GetImageBase();
    PIMAGE_NT_HEADERS NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
        ImageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase)->e_lfanew);

    return {ImageBase, NtHeader->OptionalHeader.SizeOfImage};
}

#endif // UTILS_H