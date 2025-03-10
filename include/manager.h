#include "utils.h"
#include <string>

class Manager {
public:
    void static Init(std::string signature);
    void static DumpMem(uintptr_t SearchBase, DWORD SearchRange, std::string path);
};
