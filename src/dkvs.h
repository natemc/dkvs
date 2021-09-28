#pragma once

#include <client_serdes.h>
#include <cstdint>
#include <follower_serdes.h>
#include <kv.h>
#include <server_serdes.h>

// Returns valid fd or throws
int client_socket(const char* host, uint16_t port);

// Returns -1 if port is already in use; throws on all other errors.
int server_socket(uint16_t port, int queue_depth=64);

void client_repl(int signal_pipe, int sock, ClientSerdes& serdes);
void follower_repl(int signal_pipe, int sock, KV& kv, FollowerSerdes& serdes);
void leader_repl(int signal_pipe, int sock, KV& kv, ServerSerdes& serdes);
