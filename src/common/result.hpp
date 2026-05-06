#pragma once

// A small Result<T, E> type. The architecture mandates that every public
// boundary returns "a Result<T, Error> (or expected<T,E>) at its public
// boundary" — so layers above never see exceptions thrown from libpcap or
// the OS, only typed errors.
//
// We can't use std::expected (C++23) on a C++17 codebase, and dragging in a
// dependency for this single shape is not worth it. The implementation
// below is deliberately minimal: it stores either a value or an error, and
// nothing else. No monadic combinators, no implicit conversions — those
// would just be load-bearing in subtle ways and we'd rather keep the
// surface area small.

#include <cassert>
#include <type_traits>
#include <utility>
#include <variant>

namespace pcapture::common {

template <typename T, typename E>
class Result {
public:
    static_assert(!std::is_same_v<T, E>,
                  "Result<T,E> requires distinct T and E to disambiguate construction");

    // Tag types so callers can construct unambiguously even when T and E are
    // implicitly convertible to each other (rare but real with strings).
    struct OkTag {};
    struct ErrTag {};

    static Result ok(T value)  { return Result(OkTag{},  std::move(value)); }
    static Result err(E error) { return Result(ErrTag{}, std::move(error)); }

    // Convenience constructors for the common case (distinct types).
    Result(T value)  : data_(std::move(value)) {}
    Result(E error)  : data_(std::move(error)) {}

    bool is_ok()  const noexcept { return data_.index() == 0; }
    bool is_err() const noexcept { return data_.index() == 1; }
    explicit operator bool() const noexcept { return is_ok(); }

    T&       value()       { assert(is_ok());  return std::get<0>(data_); }
    const T& value() const { assert(is_ok());  return std::get<0>(data_); }
    E&       error()       { assert(is_err()); return std::get<1>(data_); }
    const E& error() const { assert(is_err()); return std::get<1>(data_); }

private:
    Result(OkTag,  T value) : data_(std::in_place_index<0>, std::move(value)) {}
    Result(ErrTag, E error) : data_(std::in_place_index<1>, std::move(error)) {}

    std::variant<T, E> data_;
};

} // namespace pcapture::common
