#pragma once

#include <cstdint>
#include <cstring>

#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

namespace pcapture::decode {

// Endian helpers. ntohs/ntohl exist on both platforms but we keep thin
// wrappers so call sites are explicit and future big-endian tweaks (Q-in-Q
// custom tags, e.g.) are localized here.
inline std::uint16_t read_be16(const std::uint8_t* p) {
    std::uint16_t v;
    std::memcpy(&v, p, 2);
    return ntohs(v);
}

inline std::uint32_t read_be32(const std::uint8_t* p) {
    std::uint32_t v;
    std::memcpy(&v, p, 4);
    return ntohl(v);
}

} // namespace pcapture::decode
