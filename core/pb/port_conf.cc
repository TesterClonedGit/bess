/*
 * Copyright 2022 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>
#include <sstream>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc.h>
#include <netlink/socket.h>

#include "port_conf.h"

std::regex PortConf::mac_regex_("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");

PortConf::PortConf()
    : if_name_(""), if_index_(0), mac_address_(""), mac_dst_address_("") {}

PortConf::PortConf(const std::string name) : if_name_(name) {
  int ifindex;

  ifindex = if_nametoindex(name.c_str());
  if (!ifindex) {
    throw std::runtime_error("Uname to retrieve ifindex for port " + name);
  }

  if_index_ = ifindex;

  // Now it is also time to get the hardware address of the port
  mac_address_ = getMacAddress(name);
}

std::string PortConf::getMacAddress(const std::string &iface) {
  unsigned char mac[32];
  struct ifreq ifr;
  int fd, rv;

  strcpy(ifr.ifr_name, iface.c_str());
  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (fd < 0) {
    throw std::runtime_error(
        std::string("get_iface_mac error opening socket: ") +
        std::strerror(errno));
  }
  rv = ioctl(fd, SIOCGIFHWADDR, &ifr);
  if (rv >= 0)
    memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
  else {
    close(fd);
    if (errno == NLE_NOADDR || errno == NLE_NODEV) {
      // Device has been deleted
      return std::string("");
    }

    throw std::runtime_error(
        std::string("get_iface_mac error determining the MAC address: ") +
        std::strerror(errno));
  }
  close(fd);

  uint64_t mac_;
  memcpy(&mac_, mac, sizeof(mac_));
  return nbo_uint_to_mac_string(mac_);
}

std::string PortConf::nbo_uint_to_mac_string(uint64_t mac) {
  uint8_t a[6];
  for (int i = 0; i < 6; i++) {
    a[i] = (mac >> i * 8) & 0xFF;
  }

  char str[19];
  std::sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3],
               a[4], a[5]);
  return std::string(str);
}

std::string PortConf::getMacAddress() {
  return mac_address_;
}

int PortConf::getIfIndex() {
  return if_index_;
}

std::string PortConf::getIfName() {
  return if_name_;
}

std::string PortConf::getDstMacAddress() {
  return mac_dst_address_;
}

void PortConf::setIfIndex(int ifindex) {
  if_index_ = ifindex;
}

void PortConf::setIfName(const std::string &ifname) {
  if_name_ = ifname;
}

void PortConf::setDstMacAddress(const std::string &dstMacAddress) {
  if (!std::regex_match(dstMacAddress, mac_regex_)) {
    throw std::runtime_error(dstMacAddress +
                             std::string(" is an invalid MAC address"));
  }
  mac_dst_address_ = dstMacAddress;
}

void PortConf::macStrtoByteArray(std::vector<uint8_t> &out,
                                 std::string const &in) {
  unsigned int bytes[6];
  if (std::sscanf(in.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x", &bytes[0],
                  &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) != 6) {
    throw std::runtime_error(in + std::string(" is an invalid MAC address"));
  }
  out.assign(&bytes[0], &bytes[6]);
}