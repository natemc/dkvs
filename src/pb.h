#pragma once

#include <dkvs.pb.h>
#include <iosfwd>
#include <kv.h>
#include <span>
#include <string_view>

std::ostream& pb_deserialize_response(std::ostream& os, std::string_view message);
Response pb_process_request(std::string_view message, KV& kv);

// Returns the total bytes written to dest, including a 4-byte prefix
int32_t pb_serialize(std::span<char> dest, const google::protobuf::MessageLite& message);
int32_t pb_serialize_request(std::span<char> dest, std::string_view command);
