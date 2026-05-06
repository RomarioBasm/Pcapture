#include "output/formatter.hpp"

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
#endif

#include <cstdio>
#include <string>

namespace pcapture::format {

std::string format_mac(const decode::Mac& mac) {
    char buf[18];
    std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

std::string format_ipv4(std::uint32_t addr_host_order) {
    in_addr a;
    a.s_addr = htonl(addr_host_order);
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &a, buf, sizeof buf);
    return buf;
}

std::string format_ipv6(const std::array<std::uint8_t, 16>& addr) {
    char buf[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, addr.data(), buf, sizeof buf);
    return buf;
}

} // namespace pcapture::format
