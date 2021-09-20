#pragma once

#include <string_view>
#include <utility>
#include <vector>

enum class Command { invalid, get, set };

std::pair<Command, std::string_view> which_command(std::string_view command);

std::vector<std::pair<std::string_view, std::string_view>>
parse_set_args(std::string_view args);
