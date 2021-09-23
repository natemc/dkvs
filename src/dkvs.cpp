#include <dkvs.h>
#include <algorithm>
#include <cassert>
#include <charconv>
#include <client_serdes.h>
#include <command.h>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fdcloser.h>
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <netdb.h>
#include <netinet/in.h>
#include <pb.h>
#include <iouring.h>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <system_error.h>
#include <tuple>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace std::literals;

namespace {
    std::ostream& process_command(
        std::ostream& os, std::string_view command, KV& kv)
    {
        if (const auto [cmd, args] = which_command(command); cmd == Command::get) {
            const std::string key(args);
            const auto v = kv.get(key);
            return v? os << *v : os << key << " is not bound.";
        } else if (cmd == Command::set) {
            if (const auto params = parse_set_args(args); params.empty()) {
                return os << "Invalid command: " << command;
            } else {
                for (const auto& [key, value]: params)
                    kv.set(std::string(key), std::string(value));
                return os << "Done.";                
            }
        }
        return os << "Invalid command: " << command;
    }

    // Returns the length of the message or -1 if we need to wait for more data
    int32_t whole_message(std::span<const char> data) {
        if (data.size() < static_cast<std::size_t>(4)) return -1;
        int32_t len;
        memcpy(&len, data.data(), sizeof len); // TODO handle endianness
        if (len <= 0) throw std::runtime_error("bad message");
        return static_cast<std::size_t>(len) + 4 < data.size()? -1 : len;
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

void client_repl(int signal_pipe, int sock, ClientSerdes& serdes) {
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
            const auto len = whole_message(std::span{sock_buf.data, sock_buf.p});
            if (len < 0) {
                ring.submit(Read{
                    sock_buf.fd, sock_buf.p, sock_buf.space_left(), &sock_buf});
            } else {
                // We don't expect multiple messages back at once
                assert(len == sock_buf.p - (sock_buf.data + sizeof len));
                std::string_view data{sock_buf.data + sizeof len, static_cast<std::size_t>(len)};
                serdes.deserialize_response(std::cout, data) << '\n';
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
                std::span<char> dest{sock_buf.data + sizeof(int32_t), sizeof sock_buf.data - 4};
                std::string_view src{stdin_buf.data, nl};
                const int32_t len = serdes.serialize_request(dest, src);
                if (len < 0) {
                    std::cerr << "Invalid command: " << src << "\n> ";
                    ring.submit(Read{stdin_buf.fd, stdin_buf.p, stdin_buf.space_left(), &stdin_buf});
                } else {
                    memcpy(sock_buf.data, &len, sizeof len); // TODO endianness
                    const auto SZ = static_cast<std::size_t>(len) + sizeof len;
                    assert(SZ < std::numeric_limits<unsigned int>::max());
                    const auto sz = static_cast<unsigned int>(SZ);
                    ring.submit(Link{Write(sock_buf.fd, sock_buf.data, sz, WRITE_COMPLETED),
                                     Read(sock_buf.fd, sock_buf.data, sizeof sock_buf.data, &sock_buf)});
                }
            }
        }
    }
}

void server_repl(
    int signal_pipe, int server_fd, KV& kv, process_request_t process_request)
{
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
                std::string_view request{b->data + sizeof len, static_cast<std::size_t>(len)};
                std::span<char> dest{b->data + sizeof len, sizeof b->data - sizeof len};
                const int32_t len = process_request(dest, request, kv);
                b->p = b->data;
                if (len < 0) {
                    std::cerr << "Bad message";
                } else {
                    memcpy(b->data, &len, sizeof len); // TODO endianness
                    const auto SZ = static_cast<std::size_t>(len) + sizeof len;
                    assert(SZ < std::numeric_limits<unsigned int>::max());
                    const auto sz = static_cast<unsigned int>(SZ);
                    // TODO support multiple requests w/o round-trip on each
                    ring.submit(Link{Write(b->fd, b->data, sz, WRITE_COMPLETED),
                                     Read(b->fd, b->data, sizeof b->data, b)});
                }
            }
        }
    }
}
