#pragma once

#include "model/protocol_model.hpp"

#include <cstddef>
#include <cstdint>

namespace pcapture::decode::arp {

ParseError parse(const std::uint8_t* data, std::size_t len, Arp& out, std::size_t& consumed);

} // namespace pcapture::decode::arp
