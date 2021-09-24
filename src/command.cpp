#include <command.h>
#include <doctest.h>
#include <iostream>

using namespace std::literals;

namespace {
    std::string_view trim(std::string_view s) {
        constexpr auto ws = "\b\n\r\t ";
        s.remove_prefix(std::min(s.find_first_not_of(ws), s.size()));
        const auto p = s.find_last_not_of(ws);
        s.remove_suffix(p == s.npos? s.size() : s.size() - (p + 1));
        return s;
    }

    TEST_CASE("trim does") {
        CHECK("foo"sv == trim("   foo   "sv));
    }
} // namespace

std::pair<Command, std::string_view> which_command(std::string_view command) {
#define NULLARY_COMMAND(X)                                  \
    if (command.starts_with(#X))                            \
        return {Command::X, command.substr(-1 + sizeof #X)}
#define COMMAND(X)                                          \
    if (command.starts_with(#X " "))                        \
        return {Command::X, command.substr(sizeof #X)}
    COMMAND(follow);
    COMMAND(get);
    COMMAND(set);
#undef COMMAND
    return {Command::invalid, command};
}

TEST_CASE("which_command recognizes get and set") {
    CHECK(Command::get == which_command("get frobozz").first);
    CHECK(Command::set == which_command("set xyzzy=47").first);
    CHECK(Command::invalid == which_command("oops").first);
}

std::vector<std::pair<std::string_view, std::string_view>>
parse_set_args(std::string_view args) {
    constexpr auto ws = "\b\n\r\t "sv;
    std::vector<std::pair<std::string_view, std::string_view>> r;
    std::string_view::size_type p = args.find_first_not_of(ws);
     while (p != args.npos) {
        const auto eq = args.find('=', p);
        if (eq == args.npos || eq == p) return {};
        const auto end = args.find_first_of(ws, eq + 1);
        const auto key = args.substr(p, eq - p);
        const auto value = args.substr(eq + 1, end == args.npos? args.npos : end - (eq + 1));
        r.emplace_back(trim(key), trim(value));
        p = end == args.npos? end : args.find_first_not_of(ws, end + 1);
    }
    return r;
}

TEST_CASE("parse_set_args splits on = and trims") {
    CHECK(std::pair("abc"sv, "def"sv) == parse_set_args("abc=def"sv)[0]);
    CHECK(std::pair("abc"sv, "def"sv) == parse_set_args("abc=def ghi=jkl"sv)[0]);
    CHECK(std::pair("ghi"sv, "jkl"sv) == parse_set_args("abc=def ghi=jkl"sv)[1]);
}
