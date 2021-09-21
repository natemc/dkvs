# dkvs
Exercises for the Bradfield Distributed Systems Course.

## Build

Requires a recent Linux kernel (>= 5.6), liburing, Protobuf (3), cmake >= 3.18, doctest, and C++20 (I've been using g++ and haven't tried clang).

```
$ cmake -S . -B build
$ cmake --build build
```

## Run

```
$ build/dkvs snapshot-file
> get foo
foo is not bound.
> set foo=bar
Done.
> get foo
bar
> set a=1 b=2 c=3
Done.
> get b
2
>
```

The current version is client-server. You can run more instances of dkvs, and each one will connect to the first:

```
$ build/dkvs
> get c
3
>
```

You exit via Ctrl-C.

## Notes

The IPC uses [io_uring](https://kernel.dk/io_uring.pdf) (see [iouring.h](https://github.com/natemc/dkvs/blob/main/src/iouring.h) for my wrapper interface and [dkvs.cpp:300-307](https://github.com/natemc/dkvs/blob/80bb0ef68ac43f50042a34ab1a70c0e045c957a7/src/dkvs.cpp#L300) and [dkvs.cpp:376-377](https://github.com/natemc/dkvs/blob/80bb0ef68ac43f50042a34ab1a70c0e045c957a7/src/dkvs.cpp#L376) for how it’s used). Using io_uring ties my project to recent versions of Linux. Eventually I’d like to support kqueue on BSD, too, since most of my home computers are Macs, and it'd be fun to run the service on multiple computers here.

Meanwhile, the IPC encoding is [Protobuf](https://developers.google.com/protocol-buffers) (see [dkvs.proto](https://github.com/natemc/dkvs/blob/main/src/dkvs.proto) for the schema and [pb.cpp](https://github.com/natemc/dkvs/blob/main/src/pb.cpp) for the marshalling code).

The on-disk format is length-prefixed strings mashed end-to-end (and keys and values are both limited to 127 bytes currently). At the moment, I use [open+mmap for reading](https://github.com/natemc/dkvs/blob/80bb0ef68ac43f50042a34ab1a70c0e045c957a7/src/dkvs.cpp#L178) and the C++ standard library [fstream](https://github.com/natemc/dkvs/blob/80bb0ef68ac43f50042a34ab1a70c0e045c957a7/src/dkvs.cpp#L197) for writing. I expect the latter to change this week as we start working on replication.
