#include <command.h>
#include <doctest.h>

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
    // TODO we may have nullary commands someday, and they won't be
    // followed by a space.
#define COMMAND(X)                                         \
    if (command.starts_with(#X " "))                       \
        return {Command::X, command.substr(sizeof #X)}
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

std::optional<std::pair<std::string_view, std::string_view>>
parse_set_args(std::string_view args) {
    if (const auto eq = args.find('='); eq == args.npos || eq == 0) {
        return {};
    } else {
        return {{trim(args.substr(0, eq)), trim(args.substr(eq + 1))}};
    }
}

TEST_CASE("parse_set_args splits on = and trims") {
    CHECK(std::pair("abc"sv, "def"sv) == *parse_set_args("abc=def"sv));
    CHECK(std::pair("abc"sv, "def"sv) == *parse_set_args("abc = def"sv));
}
