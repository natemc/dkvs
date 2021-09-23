#include <hashkv.h>
#include <cassert>
#include <cstring>
#include <doctest.h>
#include <fcntl.h>
#include <fdcloser.h>
#include <fstream>
#include <iostream>
#include <limits>
#include <span>
#include <sstream>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <system_error.h>
#include <unistd.h>
#include <vector>

using namespace std::literals;

namespace {
    using UMSS = std::unordered_map<std::string, std::string>;

    // All keys and values must be shorter than 128 bytes.
    void serialize_to(
        std::vector<char>& r, std::string_view key, std::string_view value)
    {
        assert(key.size() < 128);
        assert(value.size() < 128);
        const char klen = static_cast<char>(key.size());
        const char vlen = static_cast<char>(value.size());
        r.push_back(klen);
        std::copy(key.begin(), key.end(), std::back_inserter(r));
        r.push_back(vlen);
        std::copy(value.begin(), value.end(), std::back_inserter(r));
    }

    std::vector<char> serialize(std::string_view key, std::string_view value) {
        std::vector<char> r;
        serialize_to(r, key, value);
        return r;
    }

    UMSS deserialize(std::span<const char> s) {
        UMSS kv;
        for (auto it = s.begin(); it != s.end(); ) {
            const char klen = *it++;
            if (klen < 0) throw std::runtime_error("Corrupt log file");
            const std::string key(it, it + klen);
            it += klen;
            const char vlen = *it++;
            if (vlen < 0) throw std::runtime_error("Corrupt log file");
            kv[key] = std::string(it, it + vlen);
            it += vlen;
        }
        return kv;
    }

    TEST_CASE("deserialize of serialize is identity") {
        const UMSS kv{{"a"s, "A"s}, {"b"s, "B"s}, {"c"s, "C"s}};
        const auto serialize_map = [](const UMSS& kv) {
            std::vector<char> r;
            for (const auto& [k, v]: kv) serialize_to(r, k, v);
            return r;
        };
        CHECK(kv == deserialize(serialize_map(kv)));
    }

    void read_or_die(int fd, void* buf, std::size_t sz) {
        assert(sz <= std::numeric_limits<ssize_t>::max());
        ssize_t to_read = static_cast<ssize_t>(sz);
        char* p = static_cast<char*>(buf);
        while (to_read) {
            const ssize_t bytes_read = read(
                fd, p, static_cast<std::size_t>(to_read));
            if (bytes_read < 0) throw SYSTEM_ERROR(read);
            assert(bytes_read <= to_read);
            to_read -= bytes_read;
            p += bytes_read;
        }
    }

    void write_or_die(int fd, const void* buf, std::size_t sz) {
        assert(sz <= std::numeric_limits<ssize_t>::max());
        ssize_t to_write = static_cast<ssize_t>(sz);
        const char* p = static_cast<const char*>(buf);
        while (to_write) {
            const ssize_t bytes_written = write(
                fd, p, static_cast<std::size_t>(to_write));
            if (bytes_written < 0) throw SYSTEM_ERROR(write);
            assert(bytes_written <= to_write);
            to_write -= bytes_written;
            p += bytes_written;
        }
    }

    const char HEADER[] = {'D', 'K', 'V', 'S'};

    std::size_t file_size(int fd) {
        struct stat st;
        if (const int rc = fstat(fd, &st); rc < 0) throw SYSTEM_ERROR(fstat);
        assert(0 <= st.st_size);
        return static_cast<std::size_t>(st.st_size);
    }

    int init_log(int fd) {
        if (const std::size_t sz = file_size(fd); sz == 0) {
            write_or_die(fd, HEADER, sizeof HEADER);
        } else if (sz < sizeof HEADER) {
            return -1;
        } else {
            char buf[sizeof HEADER];
            read_or_die(fd, buf, sizeof buf);
            if (strncmp(buf, HEADER, sizeof buf)) return -1;
        }
        return 0;
    }

    UMSS load_snapshot(int fd) {
        assert(file_size(fd) >= sizeof HEADER);
        const std::size_t     sz             = file_size(fd) - sizeof HEADER;
        constexpr off_t       FROM_BEGINNING = 0;
        constexpr void* const wherever       = nullptr;
        void * const m = mmap(wherever, sz, PROT_READ,
            MAP_POPULATE|MAP_PRIVATE, fd, FROM_BEGINNING);
        if (!m) throw SYSTEM_ERROR(mmap);
        std::span data{static_cast<const char*>(m) + sizeof HEADER, sz};
        const auto r = deserialize(data);
        [[maybe_unused]] const int rc = munmap(m, sz);
        assert(rc == 0);
        return r;
    }
} // namespace

HashKV::HashKV(const char* path): p(path) {
    int f = open(path,
                 O_APPEND|O_CREAT|O_DSYNC|O_RDWR,
                 S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (f < 0) throw SYSTEM_ERROR(open);
    FdCloser closer(f);
    if (init_log(f) < 0) {
        std::ostringstream os;
        os << path << " is not a valid log file";
        throw std::runtime_error(os.str());
    }
    m = load_snapshot(f);
    fd = closer.release();
}

HashKV::~HashKV() {
    close(fd);
}

std::optional<std::string> HashKV::get(const std::string& key) {
    const auto it = m.find(key);
    if (it == m.end()) return {};
    else               return {it->second};
}

void HashKV::set(const std::string& key, const std::string& value) {
    const auto buf = serialize(key, value);
    write_or_die(fd, buf.data(), buf.size());
    m[key] = value;
}
