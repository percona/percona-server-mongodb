

#include <iostream>
#include <cstring>
#include "kmippp.h"

int main(int argc, char** argv) {

  if(argc < 8) {
    std::cerr << "Usage: demo_create <host> <port> <client_cert> <client_key> <server_cert> <key_name> <key>" << std::endl;
    return -1;
  }

  kmippp::context ctx(argv[1], argv[2], argv[3], argv[4], argv[5]);

  kmippp::context::key_t key(strlen(argv[7]));
  memcpy(key.data(), argv[7], key.size());

  std::string key_id = ctx.op_register(argv[6], "TestGroup", key);
  std::cout << "New key: " << key_id << std::endl;

  std::cout << "end!" << std::endl;

  return 0;
}
