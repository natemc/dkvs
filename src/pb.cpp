#include <pb.h>
#include <cassert>
#include <command.h>
#include <cstring>
#include <doctest.h>
#include <iomanip>
#include <iostream>
#include <limits>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>

using namespace std::literals;

std::ostream& pb_deserialize_response(std::ostream& os, std::string_view message) {
    assert(message.size() <= std::numeric_limits<int>::max());

    Response r;
    if (!r.ParseFromArray(message.data(), static_cast<int>(message.size())))
        throw std::runtime_error("Bad message received");
    switch (r.Reply_case()) {
    case Response::ReplyCase::kGot : return os << r.got().value();
    case Response::ReplyCase::kSot : return os << "Done.";
    case Response::ReplyCase::kFail: return os << r.fail().message();
    default                        : throw std::runtime_error("Bad message");
    }
    return os;
}

Response pb_process_request(std::string_view message, KV& kv) {
    assert(message.size() <= std::numeric_limits<int>::max());

    Request in;
    if (!in.ParseFromArray(message.data(), static_cast<int>(message.size())))
        throw std::runtime_error("Bad message received");
    Response out;
    switch (in.Command_case()) {
    case Request::CommandCase::kGet:
        if (const auto it = kv.find(in.get().key()); it != kv.end()) {
            out.mutable_got()->set_value(it->second);
        } else {
            std::ostringstream os;
            os << in.get().key() << " is not bound.";
            out.mutable_fail()->set_message(std::move(os).str());
        }
        return out;
    case Request::CommandCase::kSet:
        kv[in.set().key()] = in.set().value();
        out.mutable_sot();
        return out;
    default                        :
        out.mutable_fail()->set_message("Unknown command");
        return out;
    }
}

int32_t pb_serialize(std::span<char> dest, const google::protobuf::MessageLite& message) {
    assert(dest.size() <= std::numeric_limits<int32_t>::max() - 4);

    const auto sz = message.ByteSizeLong();
    if (dest.size() - 4 < sz || std::numeric_limits<int32_t>::max() < sz + 4) {
        return -1;
        //throw std::runtime_error("Message too large");
    }

    uint8_t* const buf = reinterpret_cast<uint8_t*>(dest.data() + 4); // UB :-(
    uint8_t* const last = message.SerializeWithCachedSizesToArray(buf);
    assert(message.GetCachedSize() == last - buf);
    const int32_t len = static_cast<int32_t>(last - buf);
    memcpy(dest.data(), &len, sizeof len); // TODO handle endianness
    return len + 4;
}

TEST_CASE("pb_deserialize_response(pb_serialize(Response)) is identity") {
    const auto v = "who's there?"s;
    Response r;
    r.mutable_got()->set_value(v);
    char buf[4096];
    const auto len = pb_serialize(std::span(buf, buf + sizeof buf), r);
    CHECK(len > 0);
    std::ostringstream os;
    pb_deserialize_response(os, {buf + 4, static_cast<std::size_t>(len - 4)});
    CHECK(v == os.str());
}

// Returns # of bytes written to dest or -1 if an error occurred
int32_t pb_serialize_request(std::span<char> dest, std::string_view command) {
    Request r;
    if (const auto [cmd, args] = which_command(command); cmd == Command::get) {
        *r.mutable_get()->mutable_key() = args;
    } else if (cmd == Command::set) {
        if (const auto params = parse_set_args(args); !params) {
            //throw std::runtime_error("Invalid arguments to set command");
            return -1;
        } else {
            const auto& [key, value] = *params;
            *r.mutable_set()->mutable_key() = key;
            *r.mutable_set()->mutable_value() = value;
        }
    } else {
        return -1;
        //throw std::runtime_error("Invalid command");
    }

    return pb_serialize(dest, r);
}

TEST_CASE("pb_serialize_request does") {
    char buf[4096];
    const auto len = pb_serialize_request({buf, sizeof buf}, "get key"sv);
    CHECK(4 < len);
}
