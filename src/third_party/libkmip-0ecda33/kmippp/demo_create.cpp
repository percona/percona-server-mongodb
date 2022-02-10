

#include <iostream>
#include "kmippp.h"

int main(int argc, char** argv) {

  if(argc < 7) {
    std::cerr << "Usage: demo_create <host> <port> <client_cert> <client_key> <server_cert> <key_name>" << std::endl;
    return -1;
  }

  kmippp::context ctx(argv[1], argv[2], argv[3], argv[4], argv[5]);

  std::string key_id = ctx.op_create(argv[6], "TestGroup");
  std::cout << "New key: " << key_id << std::endl;

  std::cout << "end!" << std::endl;

  return 0;
}
