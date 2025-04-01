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

#include <memory>

#include "module.h"
#include "utils/endian.h"

// #include <bpf/bpf.h>
// #include <bpf/btf.h>
// #include <bpf/libbpf.h>
#include <xdp/prog_dispatcher.h>
#include <xdp/libxdp.h>

#include "pb/upf_ebpf_msg.pb.h"

#include "upf_bpf_main.skel.h"

#include "port_conf.h"

#define IF_INDEX_ACCESS 1
#define IF_INDEX_CORE 2

static const size_t kMaxVariable = 16;

static int libbpf_print_fn([[maybe_unused]] enum libbpf_print_level level,
                           const char *format, va_list args) {
  return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void) {
  struct rlimit rlim_new = {
      .rlim_cur = RLIM_INFINITY,
      .rlim_max = RLIM_INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
    exit(1);
  }
}

struct xdp_program {
  /* one of prog or prog_fd should be set */
  struct bpf_program *bpf_prog;
  struct bpf_object *bpf_obj;
  struct btf *btf;
  int prog_fd;
  int link_fd;
  char *prog_name;
  char *attach_name;
  __u8 prog_tag[BPF_TAG_SIZE];
  __u32 prog_id;
  __u64 load_time;
  bool from_external_obj;
  unsigned int run_prio;
  unsigned int chain_call_actions; // bitmap

  /* for building list of attached programs to multiprog */
  struct xdp_program *next;
};

class UPFeBPF final : public Module {
public:
  static const Commands cmds;

  UPFeBPF()
      : Module(), skel_access_(nullptr), xdp_prog_access_(nullptr),
        skel_core_(nullptr), xdp_prog_core_(nullptr) {}

  void DeInit() override;

  CommandResponse Init(const upf_ebpf::pb::UPFeBPFArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse
  CommandAddPDR(const upf_ebpf::pb::UPFeBPFCommandAddPDRArg &arg);
  CommandResponse
  CommandDeletePDR(const upf_ebpf::pb::UPFeBPFCommandDeletePDRArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

  CommandResponse
  CommandAddFAR(const upf_ebpf::pb::UPFeBPFCommandAddFARArg &arg);
  CommandResponse
  CommandDeleteFAR(const upf_ebpf::pb::UPFeBPFCommandDeleteFARArg &arg);

  CommandResponse
  CommandAddAppQoS(const upf_ebpf::pb::UPFeBPFCommandAddAppQoSArg &arg);
  CommandResponse
  CommandDeleteAppQoS(const upf_ebpf::pb::UPFeBPFCommandDelAppQoSArg &arg);

  CommandResponse
  CommandAddSessionQoS(const upf_ebpf::pb::UPFeBPFCommandAddSessionQoSArg &arg);
  CommandResponse CommandDeleteSessionQoS(
      const upf_ebpf::pb::UPFeBPFCommandDelSessionQoSArg &arg);

  CommandResponse CommandGetBPFProgsInfo(
      const upf_ebpf::pb::UPFeBPFCommandGetBPFProgsInfoArg &arg);

private:
  int initPorts(const upf_ebpf::pb::UPFeBPFArg &arg);
  int openAndLoadAccess(const upf_ebpf::pb::UPFeBPFArg_Conf &conf);
  int openAndLoadCore(const upf_ebpf::pb::UPFeBPFArg_Conf &conf);
  int setValuesRedirectMap();

  uint8_t
  pbLogLevelToEbpf(const upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel &log_level);

  uint8_t
  pbRunningModeToEbpf(const upf_ebpf::pb::UPFeBPFArg_Conf_Mode &running_mode);

private:
  size_t num_vars_;
  struct upf_bpf_main_bpf *skel_access_;
  struct xdp_program *xdp_prog_access_;

  struct upf_bpf_main_bpf *skel_core_;
  struct xdp_program *xdp_prog_core_;

  int pdr_map_fd_;
  int far_map_fd_;
  int app_qer_map_fd_;
  int session_qer_map_fd_;
  int access_redirect_map_fd_;
  int core_redirect_map_fd_;

  upf_ebpf::pb::UPFeBPFArg_Conf_Mode running_mode_;

  std::unique_ptr<PortConf> access_port_;
  std::unique_ptr<PortConf> core_port_;
};
