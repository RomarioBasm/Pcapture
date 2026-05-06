#pragma once

#include "model/protocol_model.hpp"

#include <cstddef>
#include <cstdint>

namespace pcapture::decode::vlan {

// Phase 4: parse one 802.1Q tag at offset 0; advances `consumed` by 4.
ParseError parse(const std::uint8_t* data, std::size_t len, VlanTag& out, std::size_t& consumed);

} // namespace pcapture::decode::vlan
