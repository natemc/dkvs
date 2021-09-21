# dkvs
Exercises for the Bradfield Distributed Systems Course.

## Build

Requires a recent Linux kernel (>= 5.6), Protobuf (3), cmake >= 3.18, and C++20.

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

The current version is client-server: you can run more instances of build/dkvs, and each one will connect to the first:

```
$ build/dkvs
> get c
3
>
```

You exit via Ctrl-C.
