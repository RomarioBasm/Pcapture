#pragma once

#include "model/protocol_model.hpp"

#include <cstddef>
#include <cstdint>

namespace pcapture::decode::ipv4 {

ParseError parse(const std::uint8_t* data, std::size_t len, Ipv4& out, std::size_t& consumed);

} // namespace pcapture::decode::ipv4
