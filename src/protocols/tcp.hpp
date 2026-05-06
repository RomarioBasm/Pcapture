#pragma once

#include "model/protocol_model.hpp"

#include <cstddef>
#include <cstdint>

namespace pcapture::decode::tcp {

ParseError parse(const std::uint8_t* data, std::size_t len, Tcp& out, std::size_t& consumed);

} // namespace pcapture::decode::tcp
