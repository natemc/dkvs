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
#include <iouring.h>
#include <iterator>
#include <limits>
#include <memory>
#include <netdb.h>
#include <netinet/in.h>
#include <pb.h>
#include <recap.h>
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
#include <unordered_set>
#include <utility>
#include <vector>

namespace {
    using SV = std::string_view;
    using namespace std::literals;

    struct Buffer {
        enum type_t { CLIENT, FOLLOWER, RECAP };
        explicit Buffer(int fd_): p(data), fd(fd_), type(CLIENT) {}
        Buffer(std::size_t num_followers, std::string_view data_):
            n(num_followers), type(FOLLOWER)
        {
            assert(data_.size() <= std::size(data));
            memcpy(data, data_.begin(), data_.size());
            p = data + data_.size();
        }
        explicit Buffer(std::string s_): s(std::move(s_)), type(RECAP) {}
        ~Buffer() { if (type == RECAP) s.~basic_string(); }

        uint32_t space_left() const { return uint32_t(std::end(data) - p); }
        uint32_t size() const { return static_cast<uint32_t>(p - data); }

        char data[4096];
        char* p;
        union { int fd; std::size_t n; std::string s; };
        type_t type;
    };

    std::ostream& operator<<(std::ostream& os, const Buffer& x) {
        os << std::hex << std::setfill('0');
        for (auto i = x.data; i != x.p; ++i)
            os << std::setw(2) << static_cast<int>(*i);
        return os << std::dec << std::setfill(' ');
    }

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
            const auto len = serdes.whole_message({sock_buf.data, sock_buf.p});
            if (len < 0) {
                ring.submit(Read{
                    sock_buf.fd, sock_buf.p, sock_buf.space_left(), &sock_buf});
            } else {
                // We don't expect multiple messages back at once
                assert(len == sock_buf.p - sock_buf.data);
                SV data{sock_buf.data, static_cast<std::size_t>(len)};
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
                std::span<char> dest{sock_buf.data};
                SV src{stdin_buf.data, nl};
                const int32_t len = serdes.serialize_request(dest, src);
                if (len < 0) {
                    std::cerr << "Invalid command: " << src << "\n> ";
                    ring.submit(Read{stdin_buf.fd, stdin_buf.p, stdin_buf.space_left(), &stdin_buf});
                } else {
                    assert(static_cast<std::size_t>(len) <=
                               std::numeric_limits<unsigned int>::max());
                    const auto sz = static_cast<unsigned int>(len);
                    ring.submit(Link{Write(sock_buf.fd, sock_buf.data, sz, WRITE_COMPLETED),
                                     Read(sock_buf.fd, sock_buf.data, sizeof sock_buf.data, &sock_buf)});
                }
            }
        }
    }
}

void follower_repl(int signal_pipe, int sock, KV& kv, FollowerSerdes& serdes) {
    Buffer pipe_buf(signal_pipe);
    Buffer stdin_buf(fileno(stdin));
    Buffer sock_buf(sock);

    constexpr int entries = 4;
    IOURing ring(entries);

    bool recapping = true;
    std::vector<std::pair<std::string, std::string>> pending_sets;
    std::span dest{sock_buf.data};
    const int32_t len = serdes.serialize_follow(dest, uint64_t(0));
    assert(0 < len);
    assert(static_cast<std::size_t>(len) <=
               std::numeric_limits<unsigned int>::max());
    const auto sz = static_cast<unsigned int>(len);
    ring.prep(Link{Write(sock_buf.fd, sock_buf.data, sz, WRITE_COMPLETED),
                   Read(sock_buf.fd, sock_buf.data, sizeof sock_buf.data, &sock_buf)});

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
            const auto reqlen = serdes.whole_message({sock_buf.data, sock_buf.p});
            if (reqlen < 0) {
                ring.submit(Read{
                    sock_buf.fd, sock_buf.p, sock_buf.space_left(), &sock_buf});
            } else {
                assert(reqlen == sock_buf.p - sock_buf.data);
                b->p = b->data;
                SV msg{b->data, static_cast<std::size_t>(reqlen)};
                std::span<char> dest{b->data};
                int len = -1;
                switch (serdes.message_type(msg)) {
                case Message::recap:
                    serdes.recap(msg,
                        [&](int seq, const std::vector<std::pair<SV,SV>>& mappings) {
                            for (auto& [key, value]: mappings) kv.set(key, value);
                        });
                    recapping = false;
                    len = 0;
                    for (auto& [key, value]: pending_sets) kv.set(key, value);
                    pending_sets.clear();
                    break;
                case Message::set:
                    len = serdes.set(dest, msg,
                        [&](const std::vector<std::pair<SV,SV>>& mappings) {
                            if (recapping) {
                                for (auto& [key, value]: mappings)
                                    pending_sets.emplace_back(key, value);
                            } else {
                                for (auto& [key, value]: mappings) kv.set(key, value);
                            }
                        });
                    break;
                default:
                    std::cerr << "Received unexpected message from leader\n";
                    break;
                }
                if (len <= 0) {
                    ring.submit(Read{sock_buf.fd, sock_buf.data, sizeof sock_buf.data, &sock_buf});
                } else {
                    ring.submit(Link{Write(sock_buf.fd, sock_buf.data, sz, WRITE_COMPLETED),
                                     Read(sock_buf.fd, sock_buf.data, sizeof sock_buf.data, &sock_buf)});
                }
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
                std::cout << "nyi\n> " << std::flush;
                b->p = b->data;
                ring.submit(Read{stdin_buf.fd, stdin_buf.p, stdin_buf.space_left(), &stdin_buf});
            }
        }
    }
}

void leader_repl(int signal_pipe, int server_fd, KV& kv, ServerSerdes& serdes) {
    // TODO check isatty and handle differently if not?
    // Would be handy for testing if nothing else.

    // TODO file and buffer registration; cf io_uring_register
    Buffer pipe_buf(signal_pipe);
    Buffer stdin_buf(fileno(stdin));
    sockaddr_in6 client_addr = {};
    sockaddr* const addr = reinterpret_cast<sockaddr*>(&client_addr);
    socklen_t addr_len;
    std::unordered_set<int> followers;

    // TODO Going beyond 4096 connections => multiple rings
    //          => multiple threads or spinning
    constexpr int entries = 64;
    IOURing ring(entries);
    ring.submit(Read{stdin_buf.fd, stdin_buf.data, sizeof stdin_buf.data, &stdin_buf},
                Accept{server_fd, addr, &addr_len, CONNECTION_ACCEPTED},
                Read{pipe_buf.fd, pipe_buf.data, sizeof pipe_buf.data, &pipe_buf});
    std::cout << "> " << std::flush;
    for (io_uring_cqe* cqe = ring.wait(); cqe; cqe = ring.wait()) {
        if (cqe->user_data == CLOSE_COMPLETED || cqe->user_data == WRITE_COMPLETED) {
            ring.seen(cqe);
            continue;
        }
        if (cqe->user_data == CONNECTION_ACCEPTED) {
            const auto client_fd = cqe->res;
            ring.seen(cqe);
            if (client_fd < 0) throw IOURING_ERROR(client_fd, accept);
            // TODO refuse connections if memory is low
            Buffer* const b = new Buffer(client_fd);
            ring.submit(Accept{server_fd, addr, &addr_len, CONNECTION_ACCEPTED},
                        Read{b->fd, b->data, sizeof b->data, b});
            continue;
        }
        Buffer* b;
        memcpy(&b, &cqe->user_data, sizeof b);
        if (b == &pipe_buf) { // SIGINT
            ring.seen(cqe);
            break;
        }
        if (b->type == Buffer::FOLLOWER) {
            ring.seen(cqe);
            if (!--b->n) delete b;
            continue;
        }
        if (b->type == Buffer::RECAP) {
            ring.seen(cqe);
            delete b;
            continue;
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
            if (nl == b->p + bytes_read) {
                b->p += bytes_read;
                if (b->p == std::end(b->data)) {
                    std::cerr << "Message too large; dropping\n";
                    b->p = b->data;
                }
            } else {
                b->p = b->data;
                SV command{b->data, nl};
                const auto [cmd, args] = which_command(command);
                if (cmd == Message::get) {
                    const std::string key(args);
                    const auto v = kv.get(key);
                    if (v) std::cout << *v;
                    else   std::cout << key << " is not bound.";
                } else if (cmd == Message::set) {
                    const auto params = parse_set_args(args);
                    if (params.empty()) {
                        std::cout << "Invalid command: " << command;
                    } else {
                        for (const auto& [key, value]: params)
                            kv.set(std::string(key), std::string(value));
                        char dest[4096];
                        const int32_t len = serdes.serialize(dest, command);
                        if (len < 0) {
                            std::cerr << "Serialization failed.\n";
                        } else {
                            assert(static_cast<std::size_t>(len) <=
                               std::numeric_limits<unsigned int>::max());
                            const auto sz = static_cast<unsigned int>(len);
                            Buffer* const buf = new Buffer(
                                followers.size(), {dest, sz});
                            for (int f: followers)
                                ring.prep(Write{f, buf->data, buf->size(), buf});
                            std::cout << "Done.";                
                        }
                    }
                } else {
                    std::cout << "Invalid command: " << command;
                }
                std::cout << "\n> " << std::flush;
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
            const int32_t reqlen = serdes.whole_message({b->data, b->p});
            if (reqlen < 0) {
                ring.submit(Read{b->fd, b->p, b->space_left(), b});
            } else {
                SV request{b->data, static_cast<std::size_t>(reqlen)};
                std::span<char> dest{b->data};
                int32_t len = -1;
                switch (serdes.request_type(request)) {
                case Message::get:
                    len = serdes.get(dest, request, [&](SV key) {
                        return kv.get(key);
                    });
                    break;
                case Message::set: {
                    // Need to copy data before serdes.set overwrites it
                    auto r = std::make_unique<Buffer>(
                        followers.size(), SV{b->data, b->size()});
                    len = serdes.set(dest, request,
                        [&](const std::vector<std::pair<SV,SV>>& mappings) {
                            for (auto& [key, value]: mappings) kv.set(key, value);
                        });
                    if (len < 0) break; // bad message
                    Buffer* const buf = r.release();
                    for (int f: followers) {
                        // This check is not needed if followers don't
                        // accept/forward writes
                        if (f != b->fd)
                            ring.prep(Write{f, buf->data, buf->size(), buf});
                    }
                    break;
                }
                case Message::sot:
                   len = 0;
                   // TODO if sot is from sync follower, ack client
                   break;
                case Message::follow:
                    len = serdes.follow(request, [&](uint64_t seq) {
                        // TODO farm out recap serialization to bg thread
                        auto ouch = new Buffer{serdes.recap(seq, {})};
                        const auto sz = static_cast<unsigned int>(ouch->s.size());
                        ring.prep(Write{b->fd, ouch->s.data(), sz, ouch});
                        followers.insert(b->fd);
                    });
                    break; // TODO send a reply? or not? does the recap suffice?
                default:
                    break;
                }
                b->p = b->data;
                if (len < 0) {
                    std::cerr << "Bad message";
                } else if (len == 0) { // no response
                    ring.submit(Read{b->fd, b->data, sizeof b->data, b});
                } else {
                    assert(static_cast<std::size_t>(len) <=
                               std::numeric_limits<unsigned int>::max());
                    const auto sz = static_cast<unsigned int>(len);
                    // TODO support multiple requests w/o round-trip on each
                    ring.submit(Link{Write(b->fd, b->data, sz, WRITE_COMPLETED),
                                     Read(b->fd, b->data, sizeof b->data, b)});
                }
            }
        }
    }
}
