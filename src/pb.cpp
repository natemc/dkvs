#include <pb.h>
#include <algorithm>
#include <arpa/inet.h>
#include <cassert>
#include <charconv>
#include <command.h>
#include <concise_lambda.h>
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

namespace {
    using google::protobuf::Arena;
    using google::protobuf::MessageLite;
    using SV = std::string_view;
    using namespace std::literals;

    static_assert(sizeof(Command) == sizeof(Reply));
    constexpr std::size_t META = sizeof(int32_t) + sizeof(Reply);

    Command pb_command(SV message) {
        assert(META < message.size());
        return static_cast<Command>(message[sizeof(int32_t)]);
    }

    Reply pb_reply(SV message) {
        assert(META < message.size());
        return static_cast<Reply>(message[sizeof(int32_t)]);
    }

    int32_t pb_whole_message(SV data) {
        uint32_t nbolen;
        if (data.size() < sizeof nbolen) return -1;
        memcpy(&nbolen, data.data(), sizeof nbolen);
        const uint32_t len = ntohl(nbolen);
        if (len < META || len > std::numeric_limits<int32_t>::max())
            throw std::runtime_error("bad message");
        return len < data.size()? -1 : static_cast<int32_t>(len);
    }

    template <class X> const X* parse(Arena& arena, SV message) {
        assert(message.size() <= std::numeric_limits<int>::max());
        assert(pb_whole_message(message) == message.size());

        const char* const buf = message.data() + META;
        const int len = static_cast<int>(message.size() - META);
        X* const x = Arena::Create<X>(&arena);
        if (!x->ParseFromArray(buf, len))
            throw std::runtime_error("Bad message received");
        return x;
    }

    std::ostream& pb_deserialize_response(std::ostream& os, SV message) {
        Arena arena;
        switch (pb_reply(message)) {
        case Reply::got : return os << parse<pb::Got>(arena, message)->value();
        case Reply::sot : return os << "Done.";
        case Reply::fail: return os << parse<pb::Fail>(arena, message)->message();
        default         : throw std::runtime_error("Bad message");
        }
        return os;
    }

    int32_t pb_serialize(
        uint8_t type, std::span<char> dest, const MessageLite& message)
    {
        assert(META < dest.size());
        const std::size_t pbsz = message.ByteSizeLong();
        if (dest.size() - META < pbsz ||
            std::numeric_limits<int32_t>::max() - META < pbsz)
        {
            return -1;
            //throw std::runtime_error("Message too large");
        }
        const uint32_t nbolen = htonl(static_cast<uint32_t>(pbsz + META));
        uint8_t* const buf = reinterpret_cast<uint8_t*>(dest.data()); // UB :-(
        memcpy(buf, &nbolen, sizeof nbolen);
        memcpy(buf + sizeof nbolen, &type, sizeof type);
        uint8_t* const last = message.SerializeWithCachedSizesToArray(buf + META);
        assert(pbsz + META == last - buf);
        return static_cast<int32_t>(last - buf);
    }

    int32_t pb_serialize(
        Command type, std::span<char> dest, const MessageLite& request)
    {
        return pb_serialize(static_cast<uint8_t>(type), dest, request);
    }

    int32_t pb_serialize(
        Reply type, std::span<char> dest, const MessageLite& response)
    {
        return pb_serialize(static_cast<uint8_t>(type), dest, response);
    }

    TEST_CASE("pb_deserialize_response(pb_serialize(Response)) is identity") {
        const auto v = "who's there?"s;
        Arena arena;
        auto got = Arena::Create<pb::Got>(&arena);
        got->set_value(v);
        char buf[4096];
        const auto len = pb_serialize(Reply::got, buf, *got);
        CHECK(len > 0);
        std::ostringstream os;
        pb_deserialize_response(os, {buf, static_cast<std::size_t>(len)});
        CHECK(v == os.str());
    }

    int32_t pb_serialize_request(std::span<char> dest, SV command) {
        assert(0 < dest.size());

        Arena arena;
        const auto [cmd, args] = which_command(command);
        if (cmd == Command::get) {
            pb::Get* const req = Arena::Create<pb::Get>(&arena);
            *req->mutable_key() = args;
            return pb_serialize(cmd, dest, *req);
        } else if (cmd == Command::set) {
            // TODO Consider doing the parsing inline to be more efficient
            // Issue: we might not detect a bad message until damage has been done
            if (const auto params = parse_set_args(args); params.empty()) {
                //throw std::runtime_error("Invalid arguments to set command");
                return -1;
            } else {
                pb::Set* const req = Arena::Create<pb::Set>(&arena);
                for (const auto& [key, value]: params) {
                    const auto m = req->add_mapping();
                    *m->mutable_key() = key;
                    *m->mutable_value() = value;
                }
                return pb_serialize(cmd, dest, *req);
            }
        } else if (cmd == Command::follow) {
            uint64_t seq;
            const auto [p, err] = std::from_chars(args.begin(), args.end(), seq);
            if (err != std::errc{}) return -1;
            pb::Follow* const req = Arena::Create<pb::Follow>(&arena);
            req->set_seq(seq);
            return pb_serialize(cmd, dest, *req);
        } else {
            return -1;
            //throw std::runtime_error("Invalid command");
        }
    }

    TEST_CASE("pb_serialize_request does") {
        char buf[4096] = {};
        const int32_t len = pb_serialize_request(buf, "get key"sv);
        CHECK(0 < len);
        CHECK(META < static_cast<std::size_t>(len));
        CHECK(std::all_of(buf + len, buf + sizeof buf, L1(x == '\0')));
        CHECK(pb_command(buf) == Command::get);

        Arena arena;
        pb::Get* const req = Arena::Create<pb::Get>(&arena);
        assert(len - META <= std::numeric_limits<int>::max());
        const bool parsed_ok = req->ParseFromArray(
            buf + META, static_cast<int>(static_cast<std::size_t>(len) - META));
        CHECK(parsed_ok);
        CHECK(req->key() == "key"s);
    }
} // namespace

std::ostream& PbClientSerdes::deserialize_response(std::ostream& os, SV message) {
    return pb_deserialize_response(os, message);
}

int32_t PbClientSerdes::serialize_request(std::span<char> dest, SV command) {
    return pb_serialize_request(dest, command);
}

int32_t PbClientSerdes::whole_message(SV message) {
    return pb_whole_message(message);
}

Command PbServerSerdes::request_type(SV message) {
    return pb_command(message);
}

int32_t PbServerSerdes::follow(SV message, const FollowHandler& handler) {
    assert(request_type(message) == Command::follow);

    Arena arena;
    handler(parse<pb::Follow>(arena, message)->seq());
    return 0;
}

int32_t PbServerSerdes::get(std::span<char> dest, SV message, const GetHandler& handler) {
    assert(request_type(message) == Command::get);

    Arena arena;
    const auto get = parse<pb::Get>(arena, message);
    if (const auto value = handler(get->key()); value) {
        pb::Got* const got = Arena::Create<pb::Got>(&arena);
        got->set_value(*value);
        return pb_serialize(Reply::got, dest, *got);
    } else {
        std::ostringstream os;
        os << get->key() << " is not bound.";
        pb::Fail* const fail = Arena::Create<pb::Fail>(&arena);
        fail->set_message(std::move(os).str());
        return pb_serialize(Reply::fail, dest, *fail);
    }
}

int32_t PbServerSerdes::set(std::span<char> dest, SV message, const SetHandler& handler) {
    assert(request_type(message) == Command::set);

    Arena arena;
    const pb::Set* const req = parse<pb::Set>(arena, message);
    std::vector<std::pair<SV, SV>> mappings;
    mappings.reserve(static_cast<std::size_t>(req->mapping_size()));
    for (int i = 0; i < req->mapping_size(); ++i) {
        const auto& m = req->mapping(i);
        mappings.emplace_back(m.key(), m.value());
        handler(mappings);
    }
    pb::Sot* const sot = Arena::Create<pb::Sot>(&arena);
    return pb_serialize(Reply::sot, dest, *sot);
}

int32_t PbServerSerdes::whole_message(SV data) {
    return pb_whole_message(data);
}
