#pragma once

// Protobuf serialization and deserialization
// We prefix each protobuf encoded message with a 4-bytes message length
// and a 1-byte message type:
//     | length | type | protobuf-encoded message |
// The length includes the bytes for the length and the type.

#include <client_serdes.h>
#include <server_serdes.h>
#include <span>
#include <string_view>

struct PbClientSerdes: ClientSerdes {
    std::ostream& deserialize_response(std::ostream& os, SV message) override;
    int32_t serialize_request(std::span<char> dest, SV src) override;
    int32_t whole_message(SV data) override;
};

struct PbServerSerdes: ServerSerdes {
    Command request_type(SV message) override;
    int32_t follow(SV message, const FollowHandler& handler) override;
    int32_t get(std::span<char> out, SV message, const GetHandler& handler) override;
    int32_t set(std::span<char> out, SV message, const SetHandler& handler) override;
    int32_t whole_message(SV data) override;
};
