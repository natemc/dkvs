#include <iouring.h>
#include <bit>
#include <cassert>
#include <cstdint>

namespace { constexpr int NO_FLAGS = 0; }

IOURing::IOURing(unsigned int entries) {
    assert(entries <= 4096u && std::popcount(entries) == 1);
    const int rc = io_uring_queue_init(entries, &ring, NO_FLAGS);
    if (rc) throw IOURING_ERROR(rc, io_uring_queue_init);
}

io_uring_sqe* IOURing::prep(const Accept& op) {
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
    constexpr unsigned int no_flags = 0;
    io_uring_sqe* const sqe = io_uring_get_sqe(&ring);
    io_uring_prep_fsync(sqe, op.fd, no_flags);
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

io_uring_cqe* IOURing::wait() {
    io_uring_cqe *cqe;
    const int rc = io_uring_wait_cqe(&ring, &cqe);
    if      (-rc == EINTR) return nullptr;
    else if (rc)           throw IOURING_ERROR(rc, io_uring_wait_cqe);
    else                   return cqe;
}
