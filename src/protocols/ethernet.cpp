#include "protocols/ethernet.hpp"
#include "common/byte_reader.hpp"

#include <cstring>

namespace pcapture::decode::ethernet {

constexpr std::size_t kHeaderSize = 14;

ParseError parse(const std::uint8_t* data, std::size_t len, Ethernet& out, std::size_t& consumed) {
    consumed = 0;
    if (len < kHeaderSize) return ParseError::TooShort;
    std::memcpy(out.dst.data(), data + 0, 6);
    std::memcpy(out.src.data(), data + 6, 6);
    out.ethertype = read_be16(data + 12);
    consumed = kHeaderSize;
    return ParseError::Ok;
}

} // namespace pcapture::decode::ethernet
