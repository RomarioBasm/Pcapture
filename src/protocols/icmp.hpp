#pragma once

#include "model/protocol_model.hpp"

#include <cstddef>
#include <cstdint>

namespace pcapture::decode::icmp {

ParseError parse(const std::uint8_t* data, std::size_t len, Icmp& out, std::size_t& consumed, bool v6);

} // namespace pcapture::decode::icmp
