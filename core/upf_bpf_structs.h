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

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace upf_ebpf {

struct pdr_key_s {
  uint8_t src_iface;
  uint32_t tunnel_ip4_dst;
  uint32_t tunnel_teid;
  uint32_t ue_ip_src_addr;
  uint32_t inet_ip_dst_addr;
  uint16_t ue_src_port;
  uint16_t inet_src_port;
  uint8_t proto_id;
} __attribute__((packed));

struct pdr_value_s {
  uint64_t pdr_id;
  uint32_t fse_id;
  uint32_t ctr_id;
  uint32_t qer_id;
  uint32_t far_id;
};

struct far_key_s {
  uint32_t far_id;
  uint32_t fse_id;
} __attribute__((packed));

struct far_value_s {
  uint64_t action;
  uint32_t tunnel_type;
  uint32_t tunnel_ip4_src;
  uint32_t tunnel_ip4_dst;
  uint32_t tunnel_teid;
  uint32_t tunnel_port;
};

enum far_actions_e {
  FAR_FORWARD_DOWNLINK_ACTION = 0,
  FAR_FORWARD_UPLINK_ACTION = 1,
  FAR_DROP_ACTION = 2,
  FAR_BUFFER_ACTION = 3,
  FAR_NOTIFY_CP_ACTION = 4,
};

struct token_bucket_s {
  uint64_t tokens;
  uint64_t refill_rate; // tokens/ms
  uint64_t capacity;
  uint64_t last_refill; // Timestamp of the last time the bucket was refilled
                        // in ms
};

struct app_qer_key_s {
  uint8_t src_iface;
  uint32_t qer_id;
  uint32_t fse_id;
} __attribute__((packed));

struct app_qer_value_s {
  struct token_bucket_s cir_bucket;
  struct token_bucket_s pir_bucket;
  uint32_t qfi_id;
  struct bpf_spin_lock lock;
};

struct session_qer_key_s {
  uint8_t src_iface;
  uint32_t fse_id;
} __attribute__((packed));

struct session_qer_value_s {
  struct token_bucket_s cir_bucket;
  struct token_bucket_s pir_bucket;
  struct bpf_spin_lock lock;
};

enum color_markers_e {
  QER_GREEN_MARKER = 0,
  QER_YELLOW_MARKER = 1,
  QER_RED_MARKER = 2,
};

} // namespace upf_ebpf