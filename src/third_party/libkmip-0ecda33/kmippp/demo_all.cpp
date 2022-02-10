

#include <iostream>
#include "kmippp.h"

int main(int argc, char** argv) {

  if(argc < 6) {
    std::cerr << "Usage: demo_locate <host> <port> <client_cert> <client_key> <server_cert>" << std::endl;
    return -1;
  }

  kmippp::context ctx(argv[1], argv[2], argv[3], argv[4], argv[5]);

  //auto keys = ctx.op_all();
  auto keys = ctx.op_locate_by_group("TestGroup");
  for (auto id : keys) {
    std::cout << "Key: " << id << " ";
    auto key = ctx.op_get(id);
    auto key_name = ctx.op_get_name_attr(id);
    std::cout << key_name << " 0x";
    for (auto const& c : key) {
      std::cout << std::hex << ((int)c);
    }
    std::cout << std::endl;
  }
  return 0;
}
