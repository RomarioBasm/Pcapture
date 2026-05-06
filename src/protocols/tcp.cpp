#include "protocols/tcp.hpp"
#include "common/byte_reader.hpp"

namespace pcapture::decode::tcp {

ParseError parse(const std::uint8_t* data, std::size_t len, Tcp& out, std::size_t& consumed) {
    consumed = 0;
    if (len < 20) return ParseError::TooShort;

    out.sport = read_be16(data + 0);
    out.dport = read_be16(data + 2);
    out.seq   = read_be32(data + 4);
    out.ack   = read_be32(data + 8);

    const std::uint8_t data_offset_words = (data[12] >> 4) & 0x0F;
    if (data_offset_words < 5) return ParseError::Malformed;
    const std::size_t header_bytes = static_cast<std::size_t>(data_offset_words) * 4u;
    if (len < header_bytes) return ParseError::TooShort;

    out.flags  = data[13]; // CWR ECE URG ACK PSH RST SYN FIN
    out.window = read_be16(data + 14);

    consumed = header_bytes;
    return ParseError::Ok;
}

} // namespace pcapture::decode::tcp
