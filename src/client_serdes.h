#pragma once

#include <iosfwd>
#include <span>
#include <string_view>

struct ClientSerdes {
    virtual ~ClientSerdes() {}
    virtual std::ostream& deserialize_response(
        std::ostream& os, std::string_view message) = 0;
    // Returns # of bytes written to dest or -1 if an error occurred
    virtual int32_t serialize_request(
        std::span<char> dest, std::string_view src) = 0;
};
