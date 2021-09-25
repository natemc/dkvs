#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct KV {
    using SV = std::string_view;

    KV() = default;
    virtual ~KV() = default;
    KV(const KV&) = delete;
    KV& operator=(const KV&) = delete;
    virtual std::optional<std::string> get(SV key) = 0;
    virtual void set(SV key, SV value) = 0;
};
