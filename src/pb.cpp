#include <pb.h>
#include <cassert>
#include <command.h>
#include <cstring>
#include <dkvs.pb.h>
#include <doctest.h>
#include <iomanip>
#include <iostream>
#include <limits>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>

using google::protobuf::Arena;
using namespace std::literals;

namespace {
    std::ostream& pb_deserialize_response(
        std::ostream& os, std::string_view message)
    {
        assert(message.size() <= std::numeric_limits<int>::max());

        Arena arena;
        Response* const r = Arena::Create<Response>(&arena);
        if (!r->ParseFromArray(message.data(), static_cast<int>(message.size())))
            throw std::runtime_error("Bad message received");
        switch (r->Reply_case()) {
        case Response::ReplyCase::kGot : return os << r->got().value();
        case Response::ReplyCase::kSot : return os << "Done.";
        case Response::ReplyCase::kFail: return os << r->fail().message();
        default                        : throw std::runtime_error("Bad message");
        }
        return os;
    }

    int32_t pb_serialize(
        std::span<char> dest, const google::protobuf::MessageLite& message)
    {
        assert(dest.size() <= std::numeric_limits<int32_t>::max());

        const auto sz = message.ByteSizeLong();
        if (dest.size() < sz || std::numeric_limits<int32_t>::max() < sz) {
            return -1;
            //throw std::runtime_error("Message too large");
        }

        uint8_t* const buf = reinterpret_cast<uint8_t*>(dest.data()); // UB :-(
        uint8_t* const last = message.SerializeWithCachedSizesToArray(buf);
        assert(sz == last - buf);
        return static_cast<int32_t>(last - buf);
    }

    TEST_CASE("pb_deserialize_response(pb_serialize(Response)) is identity") {
        const auto v = "who's there?"s;
        Arena arena;
        Response* const r = Arena::Create<Response>(&arena);
        r->mutable_got()->set_value(v);
        char buf[4096];
        const auto len = pb_serialize(std::span(buf, buf + sizeof buf), *r);
        CHECK(len > 0);
        std::ostringstream os;
        pb_deserialize_response(os, {buf, static_cast<std::size_t>(len)});
        CHECK(v == os.str());
    }

    int32_t pb_serialize_request(std::span<char> dest, std::string_view command) {
        Arena arena;
        Request* const r = Arena::Create<Request>(&arena);
        if (const auto [cmd, args] = which_command(command); cmd == Command::get) {
            *r->mutable_get()->mutable_key() = args;
        } else if (cmd == Command::set) {
            // TODO Consider doing the parsing inline to be more efficient
            if (const auto params = parse_set_args(args); params.empty()) {
                //throw std::runtime_error("Invalid arguments to set command");
                return -1;
            } else {
                for (const auto& [key, value]: params) {
                    const auto m = r->mutable_set()->add_mapping();
                    *m->mutable_key() = key;
                    *m->mutable_value() = value;
                }
            }
        } else {
            return -1;
            //throw std::runtime_error("Invalid command");
        }

        return pb_serialize(dest, *r);
    }

    TEST_CASE("pb_serialize_request does") {
        char buf[4096];
        const auto len = pb_serialize_request({buf, sizeof buf}, "get key"sv);
        CHECK(0 < len);
    }
} // namespace

std::ostream& PbClientSerdes::deserialize_response(
    std::ostream& os, std::string_view message)
{
    return pb_deserialize_response(os, message);
}

int32_t PbClientSerdes::serialize_request(
    std::span<char> dest, std::string_view command)
{
    return pb_serialize_request(dest, command);
}

int32_t pb_process_request(std::span<char> dest, std::string_view message, KV& kv) {
    assert(message.size() <= std::numeric_limits<int>::max());

    Arena arena;
    Request* const in = Arena::Create<Request>(&arena);
    if (!in->ParseFromArray(message.data(), static_cast<int>(message.size())))
        throw std::runtime_error("Bad message received");
    Response* const out = Arena::Create<Response>(&arena);
    switch (in->Command_case()) {
    case Request::CommandCase::kGet:
        if (const auto it = kv.find(in->get().key()); it != kv.end()) {
            out->mutable_got()->set_value(it->second);
        } else {
            std::ostringstream os;
            os << in->get().key() << " is not bound.";
            out->mutable_fail()->set_message(std::move(os).str());
        }
        break;
    case Request::CommandCase::kSet: {
        const auto& s = in->set();
        const int n = s.mapping_size();
        for (int i = 0; i < n; ++i) {
            const auto& m = s.mapping(i);
            kv[m.key()] = m.value();
        }
        out->mutable_sot();
        break;
    }
    default                        :
        out->mutable_fail()->set_message("Unknown command");
        break;
    }

    return pb_serialize(dest, *out);
}
