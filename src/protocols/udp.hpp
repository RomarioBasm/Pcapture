#pragma once

#include "model/protocol_model.hpp"

#include <cstddef>
#include <cstdint>

namespace pcapture::decode::udp {

ParseError parse(const std::uint8_t* data, std::size_t len, Udp& out, std::size_t& consumed);

} // namespace pcapture::decode::udp
