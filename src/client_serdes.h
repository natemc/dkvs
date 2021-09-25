#pragma once

#include <iosfwd>
#include <span>
#include <string_view>

struct ClientSerdes {
    using SV = std::string_view;
    virtual ~ClientSerdes() = default;
    virtual std::ostream& deserialize_response(std::ostream& os, SV message) = 0;
    // Returns # of bytes written to dest or -1 if an error occurred
    virtual int32_t serialize_request(std::span<char> dest, SV src) = 0;
    // Returns # of bytes of message or -1 if message is incomplete
    virtual int32_t whole_message(SV data) = 0;
};
