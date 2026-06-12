#ifndef QUILL_IDENTITYMANAGER_H
#define QUILL_IDENTITYMANAGER_H

#include "DilithiumSign.h"
#include <filesystem>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;

// Persistent ML-DSA identity; QID2 encrypts at rest when passphrase is set.
class IdentityManager {
public:
    static void activate(const std::filesystem::path& dir,
                         const std::string& passphrase);

    static void deactivate();

    static SignatureKeyPair load_or_generate(const std::string& level);

    static std::string fingerprint(const Bytes& public_key);

    static std::filesystem::path identity_dir();
};

#endif // QUILL_IDENTITYMANAGER_H
