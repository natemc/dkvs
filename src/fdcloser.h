#pragma once

struct FdCloser {
    ~FdCloser();
    int release();
    int fd;
};

