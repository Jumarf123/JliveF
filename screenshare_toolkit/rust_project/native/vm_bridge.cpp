#include "vmaware.hpp"

#include <cstring>
#include <string>

extern "C" int ss_detect_vm(char* buffer, unsigned long long length) {
    const bool detected = VM::detect();

    if (buffer != nullptr && length > 0) {
        std::string brand = VM::brand();
        if (brand.size() + 1 > length) {
            brand.resize(static_cast<std::size_t>(length - 1));
        }
        std::memcpy(buffer, brand.c_str(), brand.size());
        buffer[brand.size()] = '\0';
    }

    return detected ? 1 : 0;
}
