#pragma once

#include <client_serdes.h>
#include <kv.h>
#include <span>
#include <string_view>

struct PbClientSerdes: ClientSerdes {
    std::ostream& deserialize_response(
        std::ostream& os, std::string_view message) override;
    int32_t serialize_request(
        std::span<char> dest, std::string_view src) override;
};

// Returns the total bytes written to dest.
int32_t pb_process_request(std::span<char> dest, std::string_view message, KV& kv);
