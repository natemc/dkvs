#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
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
#include <netdb.h>
#include <netinet/in.h>
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

#define SYSTEM_ERROR_CODE(code, context) \
    std::system_error(code, std::generic_category(), #context)
#define SYSTEM_ERROR(context) SYSTEM_ERROR_CODE(errno, context)

struct FdCloser {
    ~FdCloser() { if (0 <= fd) close(fd); }
    int release() { return std::exchange(fd, -1); }
    int fd;
};

using KV = std::unordered_map<std::string, std::string>;

int client_socket(const char* host, uint16_t port) {
    char service[6];
    sprintf(service, "%d", port); // TODO use charconv
    addrinfo hints = {};
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo *infos;
    if (getaddrinfo(host, service, &hints, &infos) < 0)
        throw SYSTEM_ERROR(getaddrinfo);

    int fd = -1;
    for (addrinfo* info = infos; info && fd < 0; info = info->ai_next) {
        fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
        if (0 <= fd && connect(fd, info->ai_addr, info->ai_addrlen) < 0) {
            fd = -1;
        }
    }
    if (0 <= fd) {
        freeaddrinfo(infos);
        return fd;
    }

    const int err = errno;
    freeaddrinfo(infos);
    throw SYSTEM_ERROR_CODE(err, connect);
}

// Returns -1 if port is already in use; throws on all other errors.
int server_socket(uint16_t port, int queue_depth=64) {
    constexpr int DEFAULT_PROTOCOL = 0;
    const int fd = socket(AF_INET6, SOCK_STREAM, DEFAULT_PROTOCOL);
    if (fd < 0) throw SYSTEM_ERROR(socket);
    FdCloser closer(fd);

    const int OFF = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &OFF, sizeof OFF) < 0)
        throw SYSTEM_ERROR(setsockopt);

    sockaddr_in6 addr = {};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) < 0) {
        if (errno == EADDRINUSE) return -1;
        else                     throw SYSTEM_ERROR(bind);
    }

    if (listen(fd, queue_depth) < 0) throw SYSTEM_ERROR(listen);

    return closer.release();
}

std::vector<char> serialize(const KV& kv) {
    std::vector<char> r;
    for (const auto& [k, v]: kv) {
        assert(k.size() < 128);
        assert(v.size() < 128);
        r.push_back(char(k.size()));
        std::copy(k.begin(), k.end(), std::back_inserter(r));
        r.push_back(char(v.size()));
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
    if (!f.is_open()) throw SYSTEM_ERROR("snapshot");
    std::vector<char> v(std::size_t(f.tellg()));
    f.seekg(0, std::ios::beg);
    if (!f.read(v.data(), std::streamsize(v.size())))
        throw SYSTEM_ERROR("snapshot");
    return deserialize(v);
}

void save_snapshot(const char* path, const KV& kv) {
    const auto s = serialize(kv);
    std::fstream f;
    f.open(path, f.trunc | f.binary | f.out);
    if (!f.is_open()) throw SYSTEM_ERROR("snapshot");
    for (auto c: s) f << c;
    f.close();
}

#define BAIL(CAT, DATA) \
    do { std::cout << CAT << ": " << DATA << '\n'; return; } while (false);

void process_command(const char* command, KV& kv) {
    const char* const end = command + strlen(command);
    if (std::distance(command, end) < 5) {
        std::cout << "Invalid command: " << command << '\n';
    } else {
        const char* const sp = std::find(command, end, ' ');
        if (sp == end) {
            std::cout << "Invalid command: " << command << '\n';
        } else if (std::equal(command, sp, "get")) {
            const char* const key = sp + 1;
            const auto it = kv.find(key);
            if (it != kv.end()) {
                std::cout << it->second << '\n';
            } else {
                std::cout << key << " is not bound.\n";
            }
        } else if (std::equal(command, sp, "set")) {
            const char* const eq = std::find(sp + 1, end, '=');
            if (eq == end || eq == sp + 1) {
                std::cout << "Invalid command: " << command << '\n';
            } else {
                const std::string key(sp + 1, eq);
                kv[key] = eq + 1;
            }
        } else {
            std::cout << "Invalid command: " << command << '\n';
        }
    }
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
                        process_command(buf, kv);
                        std::copy_backward(nl + 1, p + bytes_read, buf);
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
    Read(int fd_, void* buf_, unsigned int sz_): Read(fd_, buf_, sz_, fd_) {}

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

struct Accept { int fd; sockaddr* addr; socklen_t* addrlen; };
struct Close { int fd; };
struct FSync { int fd; };
//struct Read { int fd; void* buf; unsigned int sz; };
struct Write { int fd; const void* buf; unsigned int sz; };
template <class... O> using Linked = std::tuple<O...>;

struct IOURing {
    explicit IOURing(unsigned int entries);
    ~IOURing() { io_uring_queue_exit(&ring); }
    IOURing(IOURing&& o) = delete;
    IOURing& operator=(IOURing&& o) = delete;
    IOURing(const IOURing&) = delete;
    IOURing& operator=(const IOURing&) = delete;

    template <class... O> void submit(const O&... ops) {
        prep(ops...);
        submit();
    }
    template <class... O> void submit(const Linked<O...>& ops) {
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

    template <class... O> void prep(const Linked<O...>& ops) {
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
    sqe->user_data = __u64(op.fd);
    return sqe;
}

io_uring_sqe* IOURing::prep(const Close& op) {
    io_uring_sqe* const sqe = io_uring_get_sqe(&ring);
    io_uring_prep_close(sqe, op.fd);
    sqe->user_data = __u64(op.fd);
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
    sqe->user_data = __u64(op.fd);
    return sqe;
}

void IOURing::seen(io_uring_cqe* cqe) {
    io_uring_cqe_seen(&ring, cqe);
}

void IOURing::submit() {
    const int rc = io_uring_submit(&ring);
    if (rc < 0) throw IOURING_ERROR(rc, io_uring_submit);
}

io_uring_cqe* IOURing::wait() {
    io_uring_cqe *cqe;
    const int rc = io_uring_wait_cqe(&ring, &cqe);
    if      (-rc == EINTR) return nullptr;
    else if (rc)           throw IOURING_ERROR(rc, io_uring_wait_cqe);
    else                   return cqe;
}

void client_repl(int signal_pipe, int sock) {
}

struct Buffer {
    explicit Buffer(int fd_): p(data), fd(fd_) {}
    uint32_t space_left() const { return uint32_t(std::end(data) - p); }
    char data[4096];
    char* p;
    int fd;
};

void server_repl(int signal_pipe, int server_fd, KV& kv) {
    // These values must not be legal pointers. An easy way to do that is to
    // make them not divisble by 8.
    constexpr int INTERRUPTED = 1;
    constexpr int CONNECTION_ACCEPTED = 2;

    char buf[4096], pipe_buf[4096];
    char* p = buf;
    const auto space_left = [&](){ return uint32_t(std::end(buf) - p); };
    sockaddr_in6 client_addr = {};
    sockaddr* const addr = reinterpret_cast<sockaddr*>(&client_addr);
    socklen_t addr_len;

    constexpr int entries = 8;
    IOURing ring(entries);
    ring.submit(Read{fileno(stdin), buf, sizeof buf},
                Accept{server_fd, addr, &addr_len},
                Read{signal_pipe, pipe_buf, sizeof pipe_buf});
    std::cout << "> " << std::flush;
    for (;;) {
        io_uring_cqe* const cqe = ring.wait();
        if (!cqe) break;
        const int fd = int(cqe->user_data);
        if (fd == signal_pipe) {
            ring.seen(cqe);
            break;
        } else if (fd == server_fd) {
            const int client_fd = cqe->res;
            ring.seen(cqe);
            if (client_fd < 0) throw IOURING_ERROR(client_fd, server);
            // TODO create a Buffer, put it in the sqe user data
//            Buffer* b = new Buffer(client_fd);
        } else {
            assert(fd == fileno(stdin));
            const ssize_t bytes_read = ssize_t(cqe->res);
            ring.seen(cqe);
            if (bytes_read < 0) throw IOURING_ERROR(bytes_read, stdin);
            char* const nl = std::find(p, p + bytes_read, '\n');
            if (nl == p + bytes_read) {
                p += bytes_read;
                if (p == std::end(buf)) throw std::runtime_error("OOM");
            } else {
                *nl = '\0';
                process_command(buf, kv);
                std::copy_backward(nl + 1, p + bytes_read, buf);
                p = buf + (p + bytes_read - nl - 1);
                ring.submit(Read{fileno(stdin), p, space_left()});
                std::cout << "> " << std::flush;
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
        if (sigaction(SIGINT, &sa, nullptr) < 0) throw SYSTEM_ERROR(sigaction);

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
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }
}
