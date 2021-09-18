#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <charconv>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dkvs.h>
#include <fcntl.h>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <limits>
#include <netdb.h>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#define SYSTEM_ERROR_CODE(code, msg) \
    std::system_error(code, std::generic_category(), msg)
#define SYSTEM_ERROR_MSG(msg) SYSTEM_ERROR_CODE(errno, msg)
#define SYSTEM_ERROR(context) SYSTEM_ERROR_MSG(#context)

struct FdCloser {
    ~FdCloser() { if (0 <= fd) close(fd); }
    int release() { return std::exchange(fd, -1); }
    int fd;
};

using KV = std::unordered_map<std::string, std::string>;

// Returns valid fd or throws
int client_socket(const char* host, uint16_t port) {
    char service[6];
    const auto [p, ec] = std::to_chars(service, service + sizeof service, port);
    assert(ec == std::errc{});
    assert(p < service + sizeof service);
    *p = '\0';

    addrinfo hints = {};
    hints.ai_family   = PF_UNSPEC;
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

// Returns -1 if port is already in use; throws on all other errors.
int server_socket(uint16_t port, int queue_depth=64) {
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
        f.write(s.data(), std::streamsize(s.size()));
        f.flush();
        f.close();
    }
}

// Requires *end == '\0'
std::ostream& process_command(
    std::ostream& os, const char* command, const char* end, KV& kv)
{
    assert(command <= end);
    assert(*end == '\0');

    if (const char* const sp = std::find(command, end, ' '); sp == end) {
        os << "Invalid command: " << command;
    } else if (std::equal(command, sp, "get")) {
        const char* const key = sp + 1;
        const auto it = kv.find(key);
        if (it != kv.end()) os << it->second;
        else                os << key << " is not bound.";
    } else if (std::equal(command, sp, "set")) {
        if (auto eq = std::find(sp + 1, end, '='); eq == end || eq == sp + 1) {
            os << "Invalid command: " << command;
        } else {
            const std::string key(sp + 1, eq);
            kv[key] = eq + 1;
        }
    } else {
        os << "Invalid command: " << command;
    }
    return os;
}

#ifdef __APPLE__

#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>

struct KQueue {
    template <class I>
    requires(std::is_same_v<int, std::decay_t<decltype(*std::declval<I>())>>)
    KQueue(I first, I last);
    KQueue(std::initializer_list<int> fds): KQueue(fds.begin(), fds.end()) {}
    ~KQueue() { if (0 <= kq) close(kq); }
    KQueue(KQueue&& o) noexcept: kq(o.kq) { o.kq = -1; }
    KQueue& operator=(KQueue&& o) noexcept;
    KQueue(const KQueue&) = delete;
    KQueue& operator=(const KQueue&) = delete;

    int operator()();
    const struct kevent& operator[](int i) { return events[std::size_t(i)]; }

private:
    std::vector<struct kevent> events;
    int                        kq;
};

template <class I>
requires(std::is_same_v<int, std::decay_t<decltype(*std::declval<I>())>>)
KQueue::KQueue(I first, I last): kq(kqueue()) {
    if (kq == -1) throw SYSTEM_ERROR(kqueue);
    const std::size_t n = std::size_t(std::distance(first, last));
    events.resize(n);
    for (std::size_t i = 0; first != last; ++first, ++i)
        EV_SET(&events[i], *first, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
    if (-1 == kevent(kq, events.data(), int(n), nullptr, 0, nullptr))
        throw SYSTEM_ERROR(kevent);
}

KQueue& KQueue::operator=(KQueue&& o) noexcept {
    KQueue x(std::move(o));
    using std::swap;
    swap(*this, x);
    return *this;
}

int KQueue::operator()() {
    assert(0 <= kq);
    const int num_triggered = kevent(kq, nullptr, 0,
        events.data(), int(events.size()), nullptr);
    if (num_triggered < 0 && errno != EINTR) throw SYSTEM_ERROR(kevent);
    else                                     return num_triggered;
}

void repl(int signal_pipe, KV& kv) {
    KQueue q{fileno(stdin), signal_pipe};
    char buf[4096];
    char* p = buf;
    const auto space_left = [&](){ return std::size_t(std::end(buf) - p); };
    std::cout << "> " << std::flush;
    for (bool done = false; !done; ) {
        if (const int nev = q(); nev < 0) {
            break;
        } else {
            for (int i = 0; i < nev; ++i) {
                if (q[i].flags & EV_ERROR)
                    throw std::runtime_error(strerror(int(q[i].data)));
                if (q[i].ident == uintptr_t(signal_pipe)) {
                    done = true;
                    break;
                }
                assert(q[i].ident == fileno(stdin));
                for (ssize_t remaining = q[i].data; 0 < remaining; ) {
                    const ssize_t bytes_read = read(
                        fileno(stdin), p, space_left());
                    if (bytes_read < 0) throw SYSTEM_ERROR(read);
                    char* const nl = std::find(p, p + bytes_read, '\n');
                    if (nl == p + bytes_read) {
                        p += bytes_read;
                        if (p == std::end(buf)) throw std::runtime_error("OOM");
                    } else {
                        *nl = '\0';
                        process_command(std::cout, buf, nl, kv);
                        std::copy(nl + 1, p + bytes_read, buf);
                        p = buf + (p + bytes_read - nl - 1);
                        std::cout << "> " << std::flush;
                    }
                    remaining -= bytes_read;
                }
            }
        }
    }
}

#else

#include <liburing.h>

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

// These values must not be legal pointers. An easy way to do that is to
// make them not divisble by 8.
constexpr __u64 CLOSE_COMPLETED = 1;
constexpr __u64 CONNECTION_ACCEPTED = 2;
constexpr __u64 WRITE_COMPLETED = 3;

void client_repl(int signal_pipe, int sock) {
    char pipe_buf[4096];
    char buf[4096];
    char* p = buf; // where to append data coming via stdin

    constexpr int entries = 4;
    IOURing ring(entries);
    ring.submit(Read{fileno(stdin), buf, sizeof buf, fileno(stdin)},
                Read{signal_pipe, pipe_buf, sizeof pipe_buf, signal_pipe});
    std::cout << "> " << std::flush;
    for (io_uring_cqe* cqe = ring.wait(); cqe; cqe = ring.wait()) {
        if (cqe->user_data == WRITE_COMPLETED) {
            ring.seen(cqe);
            continue;
        }
        const int fd = static_cast<int>(cqe->user_data);
        if (fd == signal_pipe) { // SIGINT
            ring.seen(cqe);
            break;
        }
        const auto bytes_read = cqe->res;
        ring.seen(cqe);
        if (fd == sock) {
            if (bytes_read < 0) throw IOURING_ERROR(bytes_read, server);
            std::cout.write(buf, cqe->res) << '\n';
            ring.submit(Read{fileno(stdin), buf, sizeof buf, fileno(stdin)});
            std::cout << "> " << std::flush;
        } else {
            assert(fd == fileno(stdin));
            if (bytes_read < 0) throw IOURING_ERROR(bytes_read, stdin);
            char* const nl = std::find(p, p + bytes_read, '\n');
            if (nl != p + bytes_read) {
                p = buf;
                const auto len = static_cast<unsigned int>(nl - buf + 1);
                ring.submit(Link{Write(sock, buf, len, WRITE_COMPLETED),
                                 Read(sock, buf, sizeof buf, sock)});
            } else {
                p += bytes_read;
                if (p == std::end(buf)) {
                    std::cerr << "Message too large; dropping\n";
                    p = buf;
                }
                static_assert(sizeof(buf) <= std::numeric_limits<uint32_t>::max());
                const auto space_left = static_cast<uint32_t>(std::end(buf) - p);
                ring.submit(Read{fileno(stdin), p, space_left, fileno(stdin)});
            }
        }
    }
}

void server_repl(int signal_pipe, int server_fd, KV& kv) {
    // TODO check isatty and handle differently if not?
    // Would be handy for testing if nothing else.

    Buffer pipe_buf(signal_pipe);
    Buffer stdin_buf(fileno(stdin));
    sockaddr_in6 client_addr = {};
    sockaddr* const addr = reinterpret_cast<sockaddr*>(&client_addr);
    socklen_t addr_len;

    constexpr int entries = 8;
    IOURing ring(entries);
    ring.submit(Read{stdin_buf.fd, stdin_buf.data, sizeof stdin_buf.data, &stdin_buf},
                Accept{server_fd, addr, &addr_len, CONNECTION_ACCEPTED},
                Read{pipe_buf.fd, pipe_buf.data, sizeof pipe_buf.data, &pipe_buf});
    std::cout << "> " << std::flush;
    for (io_uring_cqe* cqe = ring.wait(); cqe; cqe = ring.wait()) {
        if (cqe->user_data == CLOSE_COMPLETED) {
            ring.seen(cqe);
        } else if (cqe->user_data == CONNECTION_ACCEPTED) {
            const auto client_fd = cqe->res;
            ring.seen(cqe);
            if (client_fd < 0) throw IOURING_ERROR(client_fd, accept);
            // TODO refuse connections if memory is low
            Buffer* const b = new Buffer(client_fd);
            ring.submit(Read{b->fd, b->data, sizeof b->data, b});
        } else if (cqe->user_data == WRITE_COMPLETED) {
            ring.seen(cqe);
        } else {
            Buffer* b;
            memcpy(&b, &cqe->user_data, sizeof b);
            if (b == &pipe_buf) { // SIGINT
                ring.seen(cqe);
                break;
            } else {
                const auto bytes_read = cqe->res;
                ring.seen(cqe);
                if (bytes_read < 0) {
                    std::cerr << strerror(-bytes_read) << '\n';
                    if (b != &stdin_buf) {
                        ring.submit(Close(b->fd, CLOSE_COMPLETED));
                        delete b;
                    }
                } else {
                    char* const nl = std::find(b->p, b->p + bytes_read, '\n');
                    if (nl != b->p + bytes_read) {
                        *nl = '\0';
                        if (b == &stdin_buf) {
                            process_command(std::cout, b->p, nl, kv) << '\n';
                            std::copy(nl + 1, b->p + bytes_read, b->data);
                            b->p = b->data + (b->p + bytes_read - nl - 1);
                            ring.submit(Read{b->fd, b->p, b->space_left(), b});
                            std::cout << "> " << std::flush;
                        } else {
                            std::ostringstream os;
                            process_command(os, b->p, nl, kv);
                            const std::string s = std::move(os).str();
                            const auto sz = std::min(s.size(), sizeof b->data);
                            assert(sz <= std::numeric_limits<ssize_t>::max());
                            const auto end = s.begin() + static_cast<ssize_t>(sz);
                            std::copy(s.begin(), end, b->data);
                            b->p = b->data;
                            assert(sz <= std::numeric_limits<unsigned int>::max());
                            const auto len = static_cast<unsigned int>(sz);
                            ring.submit(Link{Write(b->fd, b->data, len, WRITE_COMPLETED),
                                             Read(b->fd, b->data, sizeof b->data, b)});
                        }
                    } else {
                        b->p += bytes_read;
                        if (b->p == std::end(b->data)) {
                            std::cerr << "Message too large; disconnecting client\n";
                            if (b != &stdin_buf) {
                                ring.submit(Close(b->fd, CLOSE_COMPLETED));
                                delete b;
                            }
                        }
                    }
                }
            }
        }
    }
}

#endif

namespace {
    // According to https://man7.org/linux/man-pages/man7/signal-safety.7.html
    // and https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/sigaction.2.html,
    // we can call write from within our signal handler, so we write to this
    // pipe to wake up io_uring or kqueue. Even though io_uring and kqueue both
    // return with errno set to EINTR in this situation, there is a race
    // condition due to the possibility of a signal being received outside of a
    // system call. Both io_uring and kqueue have a solution for that race
    // condition, but we do this all the time rather than having two different
    // ways. See https://www.sitepoint.com/the-self-pipe-trick-explained

    std::atomic<int> g_received_int_signal_notification_pipe = 0;
    void signal_handler(int) {
        const char buf = '\0';
        const int p = g_received_int_signal_notification_pipe;
        assert(p);
        [[maybe_unused]] const ssize_t written = write(p, &buf, sizeof buf);
    }
} // namespace

int main() {
    try {
        int signal_pipe[2];
        if (pipe(signal_pipe) == -1) throw SYSTEM_ERROR(pipe);
        [[maybe_unused]] const int fcntl_rc = fcntl(
            signal_pipe[1], F_SETFL, O_NONBLOCK);
        assert(!fcntl_rc);
        g_received_int_signal_notification_pipe = signal_pipe[1];
        const FdCloser pipe_fds[2] = { signal_pipe[0], signal_pipe[1] };

        struct sigaction sa = {};
        sa.sa_handler = signal_handler;
        if (sigaction(SIGINT, &sa, nullptr) < 0) {
            throw SYSTEM_ERROR(sigaction);
        } else {
            constexpr int PORT = 10010;
            if (const int ss = server_socket(PORT); ss == -1) {
                const int cs = client_socket("localhost", PORT);
                const FdCloser cs_closer(cs);
                client_repl(signal_pipe[0], cs);
            } else {
                const FdCloser ss_closer(ss);
                KV kv = load_snapshot("snapshot");
                server_repl(signal_pipe[0], ss, kv);
                save_snapshot("snapshot", kv);
            }

            std::cout << "bye!\n";
            return EXIT_SUCCESS;
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }
}
