#include <atomic>
#include <cassert>
#include <csignal>
#include <cstdlib>
#include <dkvs.h>
#include <fcntl.h>
#include <iostream>
#include <unistd.h>

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
        const ProtobufGuard pbguard;

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
