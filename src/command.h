#pragma once

#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

enum class Message: uint8_t { invalid, fail, follow, get, got, recap, set, sot };

std::pair<Message, std::string_view> which_command(std::string_view command);

std::vector<std::pair<std::string_view, std::string_view>>
parse_set_args(std::string_view args);
