#include "trustverify.hpp"

extern "C" int ss_verify_signature(const wchar_t* path) {
    if (path == nullptr) {
        return 0;
    }

    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(path) ? 1 : 0;
}
