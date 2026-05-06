#pragma once

#include "model/protocol_model.hpp"

#include <cstddef>
#include <cstdint>

namespace pcapture::decode::ethernet {

// Phase 4: parse Ethernet II header. Returns ParseError::TooShort if too short.
ParseError parse(const std::uint8_t* data, std::size_t len, Ethernet& out, std::size_t& consumed);

} // namespace pcapture::decode::ethernet
