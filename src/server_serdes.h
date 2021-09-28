#pragma once

#include <command.h>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

struct ServerSerdes {
    using SV            = std::string_view;
    using PSV           = std::pair<SV, SV>;
    using FollowHandler = std::function<void(uint64_t)>;
    using GetHandler    = std::function<std::optional<std::string>(SV)>;
    using SetHandler    = std::function<void(const std::vector<PSV>&)>;

    virtual ~ServerSerdes() = default;

    virtual Message request_type(SV message) = 0;
    virtual int32_t follow(SV message, const FollowHandler& handler) = 0;
    virtual int32_t get(std::span<char> dest, SV message, const GetHandler& handler) = 0;
    virtual int32_t set(std::span<char> dest, SV message, const SetHandler& handler) = 0;
    // Returns # of bytes of message or -1 if message is incomplete
    virtual int32_t whole_message(SV data) = 0;

    virtual std::string recap(uint64_t seq, const std::vector<PSV>& snapshot) = 0;
    virtual int32_t serialize(std::span<char> dest, SV cmd) = 0;
};
