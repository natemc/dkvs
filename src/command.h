#pragma once

#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

enum class Command: uint8_t { invalid, follow, get, set };
enum class Reply: uint8_t { invalid, fail, got, sot, recap };

std::pair<Command, std::string_view> which_command(std::string_view command);

std::vector<std::pair<std::string_view, std::string_view>>
parse_set_args(std::string_view args);
