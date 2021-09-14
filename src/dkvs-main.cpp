#include <algorithm>
#include <atomic>
#include <cassert>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <dkvs.h>
#include <fcntl.h>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#define SYSTEM_ERROR(context) \
    std::system_error(errno, std::generic_category(), #context)

using KV = std::unordered_map<std::string, std::string>;

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

struct IOURing {
    explicit IOURing(unsigned int entries);
    ~IOURing() { io_uring_queue_exit(&ring); }
    IOURing(IOURing&& o) = delete;
    IOURing& operator=(IOURing&& o) = delete;
    IOURing(const IOURing&) = delete;
    IOURing& operator=(const IOURing&) = delete;

    void prep_read(int fd, char* buf, unsigned int sz);
    void seen(io_uring_cqe* cqe);
    void submit();
    io_uring_cqe* wait();

private:
    io_uring ring;
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

void IOURing::prep_read(int fd, char* buf, unsigned int sz) {
    constexpr std::uint64_t offset = 0;
    io_uring_sqe* const sqe = io_uring_get_sqe(&ring);
    io_uring_prep_read(sqe, fd, buf, sz, offset);
    sqe->user_data = __u64(fd);
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
    if (-rc == EINTR) return nullptr;
    if (rc) throw IOURING_ERROR(rc, io_uring_wait_cqe);
    return cqe;
}

void repl(int signal_pipe, KV& kv) {
    char buf[4096], pipe_buf[4096];
    char* p = buf;
    const auto space_left = [&](){ return uint32_t(std::end(buf) - p); };

    constexpr int entries = 2;
    IOURing ring(entries);
    ring.prep_read(fileno(stdin), buf, sizeof buf);
    ring.prep_read(signal_pipe, pipe_buf, sizeof pipe_buf);
    ring.submit();

    std::cout << "> " << std::flush;
    for (;;) {
        io_uring_cqe* const cqe = ring.wait();
        if (!cqe) break;
        if (int(cqe->user_data) == signal_pipe) {
            ring.seen(cqe);
            break;
        } else {
            assert(int(cqe->user_data) == fileno(stdin));
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
                ring.prep_read(fileno(stdin), p, space_left());
                ring.submit();
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

    struct FdCloser {
        ~FdCloser() { close(fd); }
        int fd;
    };
} // namespace

int main() {
    try {
        int signal_pipe[2];
        const int pipe_rc = pipe(signal_pipe);
        if (pipe_rc == -1) throw SYSTEM_ERROR(pipe);
        [[maybe_unused]] const int fcntl_rc = fcntl(
            signal_pipe[1], F_SETFL, O_NONBLOCK);
        assert(!fcntl_rc);
        g_received_int_signal_notification_pipe = signal_pipe[1];
        const FdCloser pipe_fds[2] = { signal_pipe[0], signal_pipe[1] };

        const auto signal_rc = signal(SIGINT, signal_handler);
        if (signal_rc == SIG_ERR) throw SYSTEM_ERROR(signal);

        KV kv;
        repl(signal_pipe[0], kv);

        std::cout << "bye!\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }
}
