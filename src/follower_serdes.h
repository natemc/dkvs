#pragma once

#include <command.h>
#include <cstdint>
#include <functional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

struct FollowerSerdes {
    using SV           = std::string_view;
    using PSV          = std::pair<SV, SV>;
    using RecapHandler = std::function<void(uint64_t, const std::vector<PSV>&)>;
    using SetHandler   = std::function<void(const std::vector<PSV>&)>;

    virtual ~FollowerSerdes() = default;
    virtual Message message_type(SV message) = 0;
    virtual int32_t serialize_follow(std::span<char> dest, uint64_t seq) = 0;
    virtual int32_t recap(SV message, const RecapHandler& handler) = 0;
    virtual int32_t set(std::span<char> out, SV message, const SetHandler& handler) = 0;
    virtual int32_t whole_message(SV data) = 0;
};
