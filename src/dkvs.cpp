#include <dkvs.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <command.h>
#include <cstdio>
#include <cstring>
#include <doctest.h>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <liburing.h>
#include <limits>
#include <netdb.h>
#include <netinet/in.h>
#include <pb.h>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <tuple>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace std::literals;

namespace {
    // All keys and values must be shorter than 128 bytes.
    std::vector<char> serialize(const KV& kv) {
        std::vector<char> r;
        for (const auto& [k, v]: kv) {
            assert(k.size() < 128);
            assert(v.size() < 128);
            const char klen = static_cast<char>(k.size());
            const char vlen = static_cast<char>(v.size());
            r.push_back(klen);
            std::copy(k.begin(), k.end(), std::back_inserter(r));
            r.push_back(vlen);
            std::copy(v.begin(), v.end(), std::back_inserter(r));
        }
        return r;
    }

    KV deserialize(const std::vector<char>& s) {
        KV kv;
        for (auto it = s.begin(); it != s.end(); ) {
            const char klen = *it++;
            const std::string key(it, it + klen);
            it += klen;
            const char vlen = *it++;
            kv[key] = std::string(it, it + vlen);
            it += vlen;
        }
        return kv;
    }

    TEST_CASE("deserialize of serialize is identity") {
        const KV kv{{"a"s, "A"s}, {"b"s, "B"s}, {"c"s, "C"s}};
        CHECK(kv == deserialize(serialize(kv)));
    }

    std::ostream& process_command(
        std::ostream& os, std::string_view command, KV& kv)
    {
        if (const auto [cmd, args] = which_command(command); cmd == Command::get) {
            const std::string key(args);
            const auto it = kv.find(key);
            if (it != kv.end()) os << it->second;
            else                os << key << " is not bound.";
        } else if (cmd == Command::set) {
            if (const auto params = parse_set_args(args); !params) {
                os << "Invalid command: " << command;
            } else {
                const auto& [key, value] = *params;
                kv[std::string{key}] = std::string{value};
                os << "Done.";
            }
        } else {
            os << "Invalid command: " << command;
        }
        return os;
    }

    // Returns the length of the message or -1 if we need to wait for more data
    int32_t whole_message(std::span<const char> data) {
        if (data.size() < static_cast<std::size_t>(4)) return -1;
        int32_t len;
        memcpy(&len, data.data(), sizeof len); // TODO handle endianness
        if (len <= 0) throw std::runtime_error("bad message");
        return static_cast<std::size_t>(len) <= data.size()? len : -1;
    }

    struct Read {
        template <class U>
            requires std::is_trivially_copyable_v<U> && (sizeof(U) <= sizeof(__u64))
        Read(int fd_, void* buf_, unsigned int  sz_, U user_data_):
            fd(fd_), buf(buf_), sz(sz_), user_data(0)
        { memcpy(&user_data, &user_data_, sizeof user_data_); }

        int fd;
        void* buf;
        unsigned int sz;
        __u64 user_data;
    };

    struct Accept { int fd; sockaddr* addr; socklen_t* addrlen; __u64 user_data; };
    struct Close { int fd; __u64 user_data; };
    struct FSync { int fd; };
    struct Write { int fd; const void* buf; unsigned int sz; __u64 user_data; };
    template <class... O> using Link = std::tuple<O...>;

    struct IOURing {
        explicit IOURing(unsigned int entries);
        ~IOURing() { io_uring_queue_exit(&ring); }
        IOURing(IOURing&& o) = delete;
        IOURing& operator=(IOURing&& o) = delete;
        IOURing(const IOURing&) = delete;
        IOURing& operator=(const IOURing&) = delete;

        // Cannot fail at runtime; errors are communicated via the cqe
        // returned from wait.
        template <class... O> void submit(const O&... ops) {
            prep(ops...);
            submit();
        }
        template <class... O> void submit(const Link<O...>& ops) {
            prep(ops);
            submit();
        }

        io_uring_cqe* wait();
        void seen(io_uring_cqe* cqe);

    private:
        io_uring ring;

        template <class... O> void prep(const O&... ops) {
            (void)std::initializer_list<io_uring_sqe*>{prep(ops)...};
        }

        template <class... O> void prep(const Link<O...>& ops) {
            using SQEs = std::array<io_uring_sqe*, sizeof...(O)>;
            const auto f = [&](const auto&... op) { return SQEs{prep(op)...}; };
            const auto sqes = std::apply(f, ops);
            for (auto i = sqes.begin(); i != sqes.end() - 1; ++i)
                (*i)->flags |= IOSQE_IO_LINK;
        }

        io_uring_sqe* prep(const Accept&);
        io_uring_sqe* prep(const Close&);
        io_uring_sqe* prep(const FSync&);
        io_uring_sqe* prep(const Read&);
        io_uring_sqe* prep(const Write&);

        void submit();
    };

    inline std::system_error iouring_error(int code, const char* context) {
        return std::system_error(code, std::generic_category(), context);
    }

    std::system_error iouring_error(auto code, const char* context) {
        return std::system_error(int(code), std::generic_category(), context);
    }

#define IOURING_ERROR(code, context) iouring_error(-code, #context)

    IOURing::IOURing(unsigned int entries) {
        assert(entries <= 4096 && std::popcount(entries) == 1);
        const int rc = io_uring_queue_init(entries, &ring, 0);
        if (rc) throw IOURING_ERROR(rc, io_uring_queue_init);
    }

    io_uring_sqe* IOURing::prep(const Accept& op) {
        constexpr int NO_FLAGS = 0;
        io_uring_sqe* const sqe = io_uring_get_sqe(&ring);
        io_uring_prep_accept(sqe, op.fd, op.addr, op.addrlen, NO_FLAGS);
        sqe->user_data = __u64(op.user_data);
        return sqe;
    }

    io_uring_sqe* IOURing::prep(const Close& op) {
        io_uring_sqe* const sqe = io_uring_get_sqe(&ring);
        io_uring_prep_close(sqe, op.fd);
        sqe->user_data = __u64(op.user_data);
        return sqe;
    }

    io_uring_sqe* IOURing::prep(const FSync& op) {
        constexpr unsigned int flags = 0;
        io_uring_sqe* const sqe = io_uring_get_sqe(&ring);
        io_uring_prep_fsync(sqe, op.fd, flags);
        sqe->user_data = __u64(op.fd);
        return sqe;
    }

    io_uring_sqe* IOURing::prep(const Read& op) {
        constexpr std::uint64_t offset = 0;
        io_uring_sqe* const sqe = io_uring_get_sqe(&ring);
        io_uring_prep_read(sqe, op.fd, op.buf, op.sz, offset);
        sqe->user_data = op.user_data;
        return sqe;
    }

    io_uring_sqe* IOURing::prep(const Write& op) {
        constexpr std::uint64_t offset = 0;
        io_uring_sqe* const sqe = io_uring_get_sqe(&ring);
        io_uring_prep_write(sqe, op.fd, op.buf, op.sz, offset);
        sqe->user_data = __u64(op.user_data);
        return sqe;
    }

    void IOURing::seen(io_uring_cqe* cqe) {
        io_uring_cqe_seen(&ring, cqe);
    }

    void IOURing::submit() {
        const int rc = io_uring_submit(&ring);
        if (rc < 0) throw IOURING_ERROR(rc, io_uring_submit);
    }

    // Returns nullptr on SIGINT; throws on io uring errors.
    // Check the res member of the returned cqe for operation-related errors.
    io_uring_cqe* IOURing::wait() {
        io_uring_cqe *cqe;
        const int rc = io_uring_wait_cqe(&ring, &cqe);
        if      (-rc == EINTR) return nullptr;
        else if (rc)           throw IOURING_ERROR(rc, io_uring_wait_cqe);
        else                   return cqe;
    }

    struct Buffer {
        explicit Buffer(int fd_): p(data), fd(fd_) {}
        uint32_t space_left() const { return uint32_t(std::end(data) - p); }
        char data[4096];
        char* p;
        int fd;
    };

    // These values must not be legal pointers.
    constexpr __u64 CLOSE_COMPLETED     = 1;
    constexpr __u64 CONNECTION_ACCEPTED = 2;
    constexpr __u64 WRITE_COMPLETED     = 3;
} // namespace

FdCloser::~FdCloser() { if (0 <= fd) close(fd); }
int FdCloser::release() { return std::exchange(fd, -1); }

ProtobufGuard::ProtobufGuard() { GOOGLE_PROTOBUF_VERIFY_VERSION; }
ProtobufGuard::~ProtobufGuard() { google::protobuf::ShutdownProtobufLibrary(); }

int client_socket(const char* host, uint16_t port) {
    char service[6];
    const auto [p, ec] = std::to_chars(service, service + sizeof service, port);
    assert(ec == std::errc{});
    assert(p < service + sizeof service);
    *p = '\0';

    addrinfo hints = {};
    hints.ai_family   = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* infos;
    if (getaddrinfo(host, service, &hints, &infos) < 0) {
        throw SYSTEM_ERROR(getaddrinfo);
    } else {
        int fd = -1;
        for (addrinfo* info = infos; info && fd < 0; info = info->ai_next) {
            fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
            if (0 <= fd && connect(fd, info->ai_addr, info->ai_addrlen) < 0)
                fd = -1;
        }

        if (0 <= fd) {
            freeaddrinfo(infos);
            return fd;
        } else {
            const int err = errno;
            freeaddrinfo(infos);
            throw SYSTEM_ERROR_CODE(err, "connect");
        }
    }
}

int server_socket(uint16_t port, int queue_depth) {
    constexpr int DEFAULT_PROTOCOL = 0;
    const int fd = socket(AF_INET6, SOCK_STREAM, DEFAULT_PROTOCOL);
    if (fd < 0) {
        throw SYSTEM_ERROR(socket);
    } else {
        FdCloser closer(fd);

        const int OFF = 0;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &OFF, sizeof OFF) < 0) {
            throw SYSTEM_ERROR(setsockopt);
        } else {
            sockaddr_in6 addr = {};
            addr.sin6_family = AF_INET6;
            addr.sin6_addr   = in6addr_any;
            addr.sin6_port   = htons(port);
            if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
                if (errno == EADDRINUSE) return -1;
                else                     throw SYSTEM_ERROR(bind);
            } else if (listen(fd, queue_depth) < 0) {
                throw SYSTEM_ERROR(listen);
            } else {
                return closer.release();
            }
        }
    }
}

KV load_snapshot(const char* path) {
    KV kv;
    std::fstream f;
    f.open(path, f.binary | f.in | f.ate);
    if (!f.is_open()) {
        return kv;
    } else {
        static_assert(sizeof(std::streamsize) <= sizeof(std::size_t));
        std::vector<char> v(static_cast<std::size_t>(f.tellg()));
        assert(v.size() <= std::numeric_limits<std::streamsize>::max());
        const std::streamsize sz = static_cast<std::streamsize>(v.size());
        f.seekg(0, std::ios::beg);
        if (f.read(v.data(), sz)) return deserialize(v);
        else                      throw SYSTEM_ERROR_MSG(path);

    }
}

void save_snapshot(const char* path, const KV& kv) {
    const auto s = serialize(kv);
    std::fstream f;
    f.open(path, f.trunc | f.binary | f.out);
    if (!f.is_open()) {
        throw SYSTEM_ERROR("snapshot");
    } else {
        assert(s.size() <= std::numeric_limits<std::streamsize>::max());
        f.write(s.data(), static_cast<std::streamsize>(s.size()));
        f.flush();
        f.close();
    }
}

void client_repl(int signal_pipe, int sock) {
    Buffer pipe_buf(signal_pipe);
    Buffer sock_buf(sock);
    Buffer stdin_buf(fileno(stdin));

    constexpr int entries = 4;
    IOURing ring(entries);
    ring.submit(Read{stdin_buf.fd, stdin_buf.data, sizeof stdin_buf.data, &stdin_buf},
                Read{pipe_buf.fd, pipe_buf.data, sizeof pipe_buf.data, &pipe_buf});
    std::cout << "> " << std::flush;
    for (io_uring_cqe* cqe = ring.wait(); cqe; cqe = ring.wait()) {
        if (cqe->user_data == WRITE_COMPLETED) {
            // TODO Can we receive cqes for partial writes?
            ring.seen(cqe);
            continue;
        }
        Buffer* b;
        memcpy(&b, &cqe->user_data, sizeof b);
        if (b == &pipe_buf) { // SIGINT
            ring.seen(cqe);
            break;
        }
        const auto bytes_read = cqe->res;
        ring.seen(cqe);
        if (b == &sock_buf) {
            if (bytes_read < 0) throw IOURING_ERROR(bytes_read, server);
            sock_buf.p += bytes_read;
            const int32_t len = whole_message(std::span{sock_buf.data, sock_buf.p});
            if (len < 0) {
                ring.submit(Read{
                    sock_buf.fd, sock_buf.p, sock_buf.space_left(), &sock_buf});
            } else {
                // We don't expect multiple messages back at once
                assert(len == sock_buf.p - (sock_buf.data + 4));
                std::string_view data{sock_buf.data + 4, static_cast<std::size_t>(len)};
                pb_deserialize_response(std::cout, data) << '\n';
                sock_buf.p = sock_buf.data;
                ring.submit(Read{
                    stdin_buf.fd, stdin_buf.data, sizeof stdin_buf.data, &stdin_buf});
                std::cout << "> " << std::flush;
            }
        } else {
            assert(b == &stdin_buf);
            if (bytes_read < 0) throw IOURING_ERROR(bytes_read, stdin);
            char* const nl = std::find(stdin_buf.p, stdin_buf.p + bytes_read, '\n');
            stdin_buf.p += bytes_read;
            if (nl == stdin_buf.p) { // short read
                if (stdin_buf.p == std::end(stdin_buf.data)) {
                    std::cerr << "Message too large; dropping\n";
                    stdin_buf.p = stdin_buf.data;
                }
                ring.submit(Read{stdin_buf.fd, stdin_buf.p, stdin_buf.space_left(), &stdin_buf});
            } else {
                stdin_buf.p = stdin_buf.data;
                std::span<char> dest{sock_buf.data, sizeof sock_buf.data};
                std::string_view src{stdin_buf.data, nl};
                const auto len = pb_serialize_request(dest, src);
                if (len < 0) {
                    std::cerr << "Invalid command: " << src << "\n> ";
                    ring.submit(Read{stdin_buf.fd, stdin_buf.p, stdin_buf.space_left(), &stdin_buf});
                } else {
                    const auto sz = static_cast<unsigned int>(len);
                    ring.submit(Link{Write(sock_buf.fd, sock_buf.data, sz, WRITE_COMPLETED),
                                     Read(sock_buf.fd, sock_buf.data, sizeof sock_buf.data, &sock_buf)});
                }
            }
        }
    }
}

void server_repl(int signal_pipe, int server_fd, KV& kv) {
    // TODO check isatty and handle differently if not?
    // Would be handy for testing if nothing else.

    // TODO file and buffer registration; cf io_uring_register
    Buffer pipe_buf(signal_pipe);
    Buffer stdin_buf(fileno(stdin));
    sockaddr_in6 client_addr = {};
    sockaddr* const addr = reinterpret_cast<sockaddr*>(&client_addr);
    socklen_t addr_len;

    // TODO Going beyond 4096 connections => multiple rings
    //          => multiple threads or spinning
    constexpr int entries = 64;
    IOURing ring(entries);
    ring.submit(Read{stdin_buf.fd, stdin_buf.data, sizeof stdin_buf.data, &stdin_buf},
                Accept{server_fd, addr, &addr_len, CONNECTION_ACCEPTED},
                Read{pipe_buf.fd, pipe_buf.data, sizeof pipe_buf.data, &pipe_buf});
    std::cout << "> " << std::flush;
    for (io_uring_cqe* cqe = ring.wait(); cqe; cqe = ring.wait()) {
        if (cqe->user_data == CLOSE_COMPLETED) {
            ring.seen(cqe);
            continue;
        }
        if (cqe->user_data == CONNECTION_ACCEPTED) {
            const auto client_fd = cqe->res;
            ring.seen(cqe);
            if (client_fd < 0) throw IOURING_ERROR(client_fd, accept);
            // TODO refuse connections if memory is low
            Buffer* const b = new Buffer(client_fd);
            ring.submit(Read{b->fd, b->data, sizeof b->data, b});
            continue;
        }
        if (cqe->user_data == WRITE_COMPLETED) {
            ring.seen(cqe);
            continue;
        }
        Buffer* b;
        memcpy(&b, &cqe->user_data, sizeof b);
        if (b == &pipe_buf) { // SIGINT
            ring.seen(cqe);
            break;
        }
        const auto bytes_read = cqe->res;
        ring.seen(cqe);
        if (bytes_read < 0) {
            std::cerr << strerror(-bytes_read) << '\n';
            if (b != &stdin_buf) {
                ring.submit(Close(b->fd, CLOSE_COMPLETED));
                delete b;
            }
        } else if (b == &stdin_buf) {
            char* const nl = std::find(b->p, b->p + bytes_read, '\n');
            if (nl != b->p + bytes_read) {
                b->p = b->data;
                std::string_view command{b->data, nl};
                process_command(std::cout, command, kv);
                std::cout << "\n> " << std::flush;
            } else {
                b->p += bytes_read;
                if (b->p == std::end(b->data)) {
                    std::cerr << "Message too large; dropping\n";
                    b->p = b->data;
                }
            }
            ring.submit(Read{b->fd, b->p, b->space_left(), b});
        } else {
            b->p += bytes_read;
            if (b->p > std::end(b->data)) {
                std::cerr << "Request too large; disconnecting\n";
                // TODO send fail message
                ring.submit(Close(b->fd, CLOSE_COMPLETED));
                delete b;
            }
            const int32_t len = whole_message(std::span{b->data, b->p});
            if (len < 0) {
                ring.submit(Read{b->fd, b->p, b->space_left(), b});
            } else {
                std::string_view request{b->data + 4, static_cast<std::size_t>(len)};
                const Response r = pb_process_request(request, kv);
                std::span<char> dest{b->data, sizeof b->data};
                const auto sz = static_cast<unsigned int>(pb_serialize(dest, r));
                // TODO support multiple requests w/o round-trip on each
                b->p = b->data;
                ring.submit(Link{Write(b->fd, b->data, sz, WRITE_COMPLETED),
                                 Read(b->fd, b->data, sizeof b->data, b)});
            }
        }
    }
}
