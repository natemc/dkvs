#pragma once

#include <optional>
#include <string>

struct KV {
    KV() = default;
    virtual ~KV() = default;
    KV(const KV&) = delete;
    KV& operator=(const KV&) = delete;
    virtual std::optional<std::string> get(const std::string& key) = 0;
    virtual void set(const std::string& key, const std::string& value) = 0;
};
