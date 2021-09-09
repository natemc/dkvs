#include <algorithm>
#include <atomic>
#include <cassert>
#include <csignal>
#include <cstdlib>
#include <dkvs.h>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <unistd.h>
#include <utility>
#include <vector>

#define SYSTEM_ERROR(context) std::system_error(errno, std::generic_category(), #context)

#ifdef __APPLE__
#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>

struct IOQueue {
    template <class I>
    requires(std::is_same_v<int, std::decay_t<decltype(*std::declval<I>())>>)
    IOQueue(I first, I last);
    IOQueue(std::initializer_list<int> fds): IOQueue(fds.begin(), fds.end()) {}
    ~IOQueue() { if (0 <= kq) close(kq); }
    IOQueue(IOQueue&& o) noexcept: kq(o.kq) { o.kq = -1; }
    IOQueue& operator=(IOQueue&& o) noexcept;
    IOQueue(const IOQueue&) = delete;
    IOQueue& operator=(const IOQueue&) = delete;

    int operator()();
    const struct kevent& operator[](int i) { return events[std::size_t(i)]; }

private:
    std::vector<struct kevent> events;
    int                        kq;
};

template <class I>
requires(std::is_same_v<int, std::decay_t<decltype(*std::declval<I>())>>)
IOQueue::IOQueue(I first, I last): kq(kqueue()) {
    if (kq == -1) throw SYSTEM_ERROR(kqueue);
    const std::size_t n = std::size_t(std::distance(first, last));
    events.resize(n);
    for (std::size_t i = 0; first != last; ++first, ++i)
        EV_SET(&events[i], *first, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
    if (-1 == kevent(kq, events.data(), int(n), nullptr, 0, nullptr))
        throw SYSTEM_ERROR(kevent);
}

IOQueue& IOQueue::operator=(IOQueue&& o) noexcept {
    IOQueue x(std::move(o));
    std::swap(*this, x);
    return *this;
}

int IOQueue::operator()() {
    assert(0 <= kq);
    const int num_triggered = kevent(kq, nullptr, 0,
        events.data(), int(events.size()), nullptr);
    if (num_triggered < 0 && errno != EINTR) throw SYSTEM_ERROR(kevent);
    else                                     return num_triggered;
}
#else
#error TODO write IOQueue for linux
#endif

namespace {
    // According to https://man7.org/linux/man-pages/man7/signal-safety.7.html
    // we can call write from within our signal handler, so the plan is to
    // create a pipe just to wake up select/epoll/kqueue whatever.
    // Update: with kqueue, that is not necessary, as kevent will return EINTR.
    // TODO: explore io_uring and determine whether we still need this pipe.
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
        g_received_int_signal_notification_pipe = signal_pipe[1];
        const FdCloser pipe_fds[2] = { signal_pipe[0], signal_pipe[1] };

        const auto signal_rc = signal(SIGINT, signal_handler);
        if (signal_rc == SIG_ERR) throw SYSTEM_ERROR(signal);

        IOQueue q{fileno(stdin), signal_pipe[0]};
        char buf[4096];
        char* p = buf;
        const auto space_left = [&](){ return std::size_t(std::end(buf) - p); };
        std::cout << "> " << std::flush;
        for (bool done = false; !done; ) {
            if (const int nev = q(); nev < 0) {
                done = true;
            } else {
                for (int i = 0; i < nev; ++i) {
                    if (q[i].flags & EV_ERROR)
                        throw std::runtime_error(strerror(int(q[i].data)));
                    if (q[i].ident == uintptr_t(signal_pipe[0])) {
                        done = true;
                        break;
                    }
                    assert(q[i].ident == fileno(stdin));
                    for (ssize_t remaining = q[i].data; 0 < remaining; ) {
                        const ssize_t seen = read(fileno(stdin), p, space_left());
                        if (seen < 0) throw SYSTEM_ERROR(read);
                        char* const nl = std::find(p, p + seen, '\n');
                        if (nl == p + seen) {
                            p += seen;
                            if (p == std::end(buf)) throw std::runtime_error("OOM");
                        } else {
                            *nl = '\0';
                            std::cout << buf << '\n';
                            std::copy_backward(nl + 1, p + seen, buf);
                            p = buf + (p + seen - nl - 1);
                            std::cout << "> " << std::flush;
                        }
                        remaining -= seen;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }
}
