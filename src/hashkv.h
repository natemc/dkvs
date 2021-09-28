#pragma once

#include <kv.h>
#include <unordered_map>

struct HashKV: KV {
    explicit HashKV(const char* path);
    ~HashKV() override;
    // TODO Consider renaming/aliasing these to operator() for use with algos
    std::optional<std::string> get(SV key) override;
    void set(SV key, SV value) override;

private:
    const char*                                  p;
    std::unordered_map<std::string, std::string> m;
    int                                          fd;
};
