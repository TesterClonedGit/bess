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

#pragma once

#include <string>
#include <vector>
#include <regex>

class PortConf {
public:
  PortConf();
  PortConf(const std::string name);

  int getIfIndex();
  std::string getIfName();
  std::string getMacAddress();
  std::string getDstMacAddress();

  void setIfIndex(int ifindex);
  void setIfName(const std::string &ifname);
  void setDstMacAddress(const std::string &dstMacAddress);

  static void macStrtoByteArray(std::vector<uint8_t> &out,
                                std::string const &in);

private:
  std::string getMacAddress(const std::string &name);
  std::string nbo_uint_to_mac_string(uint64_t mac);

  static std::regex mac_regex_;

private:
  std::string if_name_;
  int if_index_;

  std::string mac_address_;
  std::string mac_dst_address_;
};
