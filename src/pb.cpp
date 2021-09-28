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

    constexpr std::size_t META = sizeof(int32_t) + sizeof(Message);

    Message pb_message_type(SV message) {
        assert(META < message.size());
        return static_cast<Message>(message[sizeof(int32_t)]);
    }

    int32_t pb_whole_message(SV data) {
        uint32_t nbolen;
        if (data.size() < sizeof nbolen) return -1;
        memcpy(&nbolen, data.data(), sizeof nbolen);
        const uint32_t len = ntohl(nbolen);
        if (len < META || len > std::numeric_limits<int32_t>::max())
            throw std::runtime_error("bad message");
        return data.size() < len? -1 : static_cast<int32_t>(len);
    }

    TEST_CASE("pb whole message returns neg1 when meta incomplete") {
        CHECK(-1 == pb_whole_message({}));
        CHECK(-1 == pb_whole_message(" "sv));
        CHECK(-1 == pb_whole_message("  "sv));
        CHECK(-1 == pb_whole_message("   "sv));
        CHECK(-1 == pb_whole_message("    "sv));
    }

    TEST_CASE("pb whole message returns neg1 when more data is needed") {
        char buf[META + 11] = {};
        const uint32_t len = static_cast<uint32_t>(sizeof buf + 1);
        const uint32_t nbolen = htonl(len);
        memcpy(buf, &nbolen, sizeof nbolen);
        CHECK(-1 == pb_whole_message(buf));
    }

    TEST_CASE("pb whole message returns msg len when the data len matches") {
        char buf[META + 11] = {};
        const uint32_t len = static_cast<uint32_t>(sizeof buf);
        const uint32_t nbolen = htonl(len);
        memcpy(buf, &nbolen, sizeof nbolen);
        CHECK(static_cast<int32_t>(len) == pb_whole_message({buf, sizeof buf}));
    }

    TEST_CASE("pb whole message returns msg len when the data oversized") {
        char buf[META + 11] = {};
        const uint32_t len = static_cast<uint32_t>(sizeof buf - 1);
        const uint32_t nbolen = htonl(len);
        memcpy(buf, &nbolen, sizeof nbolen);
        CHECK(static_cast<int32_t>(len) == pb_whole_message({buf, sizeof buf}));
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
        switch (pb_message_type(message)) {
        case Message::got : return os << parse<pb::Got>(arena, message)->value();
        case Message::sot : return os << "Done.";
        case Message::fail: return os << parse<pb::Fail>(arena, message)->message();
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
        Message type, std::span<char> dest, const MessageLite& request)
    {
        return pb_serialize(static_cast<uint8_t>(type), dest, request);
    }

    TEST_CASE("pb_deserialize_response(pb_serialize(Response)) is identity") {
        const auto v = "who's there?"s;
        Arena arena;
        auto got = Arena::Create<pb::Got>(&arena);
        got->set_value(v);
        char buf[4096];
        const auto len = pb_serialize(Message::got, buf, *got);
        CHECK(len > 0);
        std::ostringstream os;
        pb_deserialize_response(os, {buf, static_cast<std::size_t>(len)});
        CHECK(v == os.str());
    }

    int32_t pb_serialize_request(std::span<char> dest, SV command) {
        assert(0 < dest.size());

        Arena arena;
        const auto [cmd, args] = which_command(command);
        if (cmd == Message::get) {
            pb::Get* const req = Arena::Create<pb::Get>(&arena);
            *req->mutable_key() = args;
            return pb_serialize(cmd, dest, *req);
        } else if (cmd == Message::set) {
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
        CHECK(pb_message_type(buf) == Message::get);

        Arena arena;
        pb::Get* const req = Arena::Create<pb::Get>(&arena);
        assert(len - META <= std::numeric_limits<int>::max());
        const bool parsed_ok = req->ParseFromArray(
            buf + META, static_cast<int>(static_cast<std::size_t>(len) - META));
        CHECK(parsed_ok);
        CHECK(req->key() == "key"s);
    }

    // TODO put this somewhere that makes sense
    using SetHandler = std::function<void(const std::vector<std::pair<SV,SV>>&)>;

    int32_t pb_set(std::span<char> dest, SV message, const SetHandler& handler) {
        assert(pb_message_type(message) == Message::set);

        Arena arena;
        const pb::Set* const req = parse<pb::Set>(arena, message);
        std::vector<std::pair<SV, SV>> mappings;
        mappings.reserve(static_cast<std::size_t>(req->mapping_size()));
        for (int i = 0; i < req->mapping_size(); ++i) {
            const auto& m = req->mapping(i);
            mappings.emplace_back(m.key(), m.value());
        }
        // TODO handle errors/exceptions here or outside?
        handler(mappings);
        pb::Sot* const sot = Arena::Create<pb::Sot>(&arena);
        return pb_serialize(Message::sot, dest, *sot);
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

////////////////////////////////////////////////////////////////////////////////

Message PbFollowerSerdes::message_type(SV message) {
    return pb_message_type(message);
}

int32_t PbFollowerSerdes::serialize_follow(std::span<char> dest, uint64_t seq) {
    Arena arena;
    pb::Follow* const req = Arena::Create<pb::Follow>(&arena);
    req->set_seq(seq);
    return pb_serialize(Message::follow, dest, *req);
}

int32_t PbFollowerSerdes::recap(SV message, const RecapHandler& handler) {
    assert(pb_message_type(message) == Message::recap);

    Arena arena;
    const pb::Recap* const r = parse<pb::Recap>(arena, message);
    const auto& set = r->set();
    std::vector<std::pair<SV, SV>> mappings;
    mappings.reserve(static_cast<std::size_t>(set.mapping_size()));
    for (int i = 0; i < set.mapping_size(); ++i) {
        const auto& m = set.mapping(i);
        mappings.emplace_back(m.key(), m.value());
    }
    // TODO handle errors/exceptions here or outside?
    handler(r->seq(), mappings);
    return 0;
}

int32_t PbFollowerSerdes::set(
    std::span<char> out, SV message, const SetHandler& handler)
{
    return pb_set(out, message, handler);
}

int32_t PbFollowerSerdes::whole_message(SV data) {
    return pb_whole_message(data);
}

////////////////////////////////////////////////////////////////////////////////

Message PbServerSerdes::request_type(SV message) {
    return pb_message_type(message);
}

int32_t PbServerSerdes::follow(SV message, const FollowHandler& handler) {
    assert(request_type(message) == Message::follow);

    Arena arena;
    handler(parse<pb::Follow>(arena, message)->seq());
    return 0;
}

int32_t PbServerSerdes::get(std::span<char> dest, SV message, const GetHandler& handler) {
    assert(request_type(message) == Message::get);

    Arena arena;
    const auto get = parse<pb::Get>(arena, message);
    if (const auto value = handler(get->key()); value) {
        pb::Got* const got = Arena::Create<pb::Got>(&arena);
        got->set_value(*value);
        return pb_serialize(Message::got, dest, *got);
    } else {
        std::ostringstream os;
        os << get->key() << " is not bound.";
        pb::Fail* const fail = Arena::Create<pb::Fail>(&arena);
        fail->set_message(std::move(os).str());
        return pb_serialize(Message::fail, dest, *fail);
    }
}

std::string PbServerSerdes::recap(uint64_t seq, const std::vector<PSV>& snapshot) {
    Arena arena;
    pb::Recap* const recap = Arena::Create<pb::Recap>(&arena);
    recap->set_seq(seq);
    pb::Set* const set = recap->mutable_set();
    for (const auto& [key, value]: snapshot) {
        const auto m = set->add_mapping();
        *m->mutable_key() = key;
        *m->mutable_value() = value;
    }

    const std::size_t pbsz = recap->ByteSizeLong();
    if (std::numeric_limits<int32_t>::max() - META < pbsz) {
        throw std::runtime_error("Message too large");
    }

    std::string out(META, '\0');
    out.reserve(pbsz + META);
    const uint32_t nbolen = htonl(static_cast<uint32_t>(pbsz + META));
    uint8_t* const buf = reinterpret_cast<uint8_t*>(out.data()); // UB :-(
    memcpy(buf, &nbolen, sizeof nbolen);
    const Message type = Message::recap;
    memcpy(buf + sizeof nbolen, &type, sizeof type);
    recap->AppendToString(&out);
    return out;
}

int32_t PbServerSerdes::serialize(std::span<char> dest, SV command) {
    return pb_serialize_request(dest, command);
}

int32_t PbServerSerdes::set(std::span<char> dest, SV message, const SetHandler& handler) {
    return pb_set(dest, message, handler);
}

int32_t PbServerSerdes::whole_message(SV data) {
    return pb_whole_message(data);
}
