#pragma once

#include <cstring>
#include <liburing.h>
#include <system_error>
#include <tuple>
#include <type_traits>

struct Accept { int fd; sockaddr* addr; socklen_t* addrlen; __u64 user_data; };
struct Close { int fd; __u64 user_data; };
struct FSync { int fd; };

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

struct Write {
    template <class U>
        requires std::is_trivially_copyable_v<U> && (sizeof(U) <= sizeof(__u64))
    Write(int fd_, void* buf_, unsigned int  sz_, U user_data_):
        fd(fd_), buf(buf_), sz(sz_), user_data(0)
    { memcpy(&user_data, &user_data_, sizeof user_data_); }

    int fd;
    const void* buf;
    unsigned int sz;
    __u64 user_data;
};

template <class... O> using Link = std::tuple<O...>;

struct IOURing {
    explicit IOURing(unsigned int entries);
    ~IOURing() { io_uring_queue_exit(&ring); }
    IOURing(IOURing&& o) = delete;
    IOURing& operator=(IOURing&& o) = delete;
    IOURing(const IOURing&) = delete;
    IOURing& operator=(const IOURing&) = delete;

    io_uring_sqe* prep(const Accept&);
    io_uring_sqe* prep(const Close&);
    io_uring_sqe* prep(const FSync&);
    io_uring_sqe* prep(const Read&);
    io_uring_sqe* prep(const Write&);

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
    void submit();

    // Returns nullptr on SIGINT; throws on io uring errors.
    // Check the res member of the returned cqe for operation-related errors.
    io_uring_cqe* wait();
    void seen(io_uring_cqe* cqe);

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
