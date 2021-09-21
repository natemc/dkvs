#pragma once

#include <client_serdes.h>
#include <cstdint>
#include <kv.h>
#include <system_error>

#define SYSTEM_ERROR_CODE(code, msg) \
    std::system_error(code, std::generic_category(), msg)
#define SYSTEM_ERROR_MSG(msg) SYSTEM_ERROR_CODE(errno, msg)
#define SYSTEM_ERROR(context) SYSTEM_ERROR_MSG(#context)

// Returns valid fd or throws
int client_socket(const char* host, uint16_t port);

// Returns -1 if port is already in use; throws on all other errors.
int server_socket(uint16_t port, int queue_depth=64);

void client_repl(int signal_pipe, int sock, ClientSerdes& serdes);
using process_request_t = int32_t(*)(std::span<char>, std::string_view, KV&);
void server_repl(int signal_pipe, int sock, KV& kv, process_request_t);

KV load_snapshot(const char* path);
void save_snapshot(const char* path, const KV& kv);
