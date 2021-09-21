#include <fdcloser.h>
#include <unistd.h>
#include <utility>

FdCloser::~FdCloser() { if (0 <= fd) close(fd); }
int FdCloser::release() { return std::exchange(fd, -1); }
