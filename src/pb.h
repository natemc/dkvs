#pragma once

// Protobuf serialization and deserialization
// We prefix each protobuf encoded message with a 4-bytes message length
// and a 1-byte message type:
//     | length | type | protobuf-encoded message |
// The length includes the bytes for the length and the type.

#include <client_serdes.h>
#include <follower_serdes.h>
#include <server_serdes.h>

struct PbClientSerdes: ClientSerdes {
    std::ostream& deserialize_response(std::ostream& os, SV message) override;
    int32_t serialize_request(std::span<char> dest, SV src) override;
    int32_t whole_message(SV data) override;
};

struct PbFollowerSerdes: FollowerSerdes {
    Message message_type(SV message) override;
    int32_t serialize_follow(std::span<char> dest, uint64_t seq) override;
    int32_t recap(SV message, const RecapHandler& handler) override;
    int32_t set(std::span<char> out, SV message, const SetHandler& handler) override;
    int32_t whole_message(SV data) override;
};

struct PbServerSerdes: ServerSerdes {
    Message request_type(SV message) override;
    int32_t follow(SV message, const FollowHandler& handler) override;
    int32_t get(std::span<char> out, SV message, const GetHandler& handler) override;
    int32_t set(std::span<char> out, SV message, const SetHandler& handler) override;
    int32_t whole_message(SV data) override;

    std::string recap(uint64_t seq, const std::vector<PSV>& snapshot) override;
    int32_t serialize(std::span<char> dest, SV cmd) override;
};
