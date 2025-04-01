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

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

#include "upf_bpf_main.h"
#include "upf_bpf_structs.h"

using bess::utils::be32_t;

const Commands UPFeBPF::cmds = {
    {"add_pdr", "UPFeBPFCommandAddPDRArg",
     MODULE_CMD_FUNC(&UPFeBPF::CommandAddPDR), Command::THREAD_UNSAFE},
    {"delete_pdr", "UPFeBPFCommandDeletePDRArg",
     MODULE_CMD_FUNC(&UPFeBPF::CommandDeletePDR), Command::THREAD_UNSAFE},
    {"add_far", "UPFeBPFCommandAddFARArg",
     MODULE_CMD_FUNC(&UPFeBPF::CommandAddFAR), Command::THREAD_UNSAFE},
    {"delete_far", "UPFeBPFCommandDeleteFARArg",
     MODULE_CMD_FUNC(&UPFeBPF::CommandDeleteFAR), Command::THREAD_UNSAFE},
    {"add_app_qos", "UPFeBPFCommandAddAppQoSArg",
     MODULE_CMD_FUNC(&UPFeBPF::CommandAddAppQoS), Command::THREAD_UNSAFE},
    {"delete_app_qos", "UPFeBPFCommandDelAppQoSArg",
     MODULE_CMD_FUNC(&UPFeBPF::CommandDeleteAppQoS), Command::THREAD_UNSAFE},
    {"add_session_qos", "UPFeBPFCommandAddSessionQoSArg",
     MODULE_CMD_FUNC(&UPFeBPF::CommandAddSessionQoS), Command::THREAD_UNSAFE},
    {"delete_session_qos", "UPFeBPFCommandDelSessionQoSArg",
     MODULE_CMD_FUNC(&UPFeBPF::CommandDeleteSessionQoS),
     Command::THREAD_UNSAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&UPFeBPF::CommandClear),
     Command::THREAD_UNSAFE},
    {"get_bpf_progs_info", "UPFeBPFCommandGetBPFProgsInfoArg",
     MODULE_CMD_FUNC(&UPFeBPF::CommandGetBPFProgsInfo), Command::THREAD_SAFE},
};

void UPFeBPF::DeInit() {
  std::cout << "Deinit UPF-eBPF" << std::endl;
  bess::pb::EmptyArg empty;
  CommandClear(empty);
}

int UPFeBPF::initPorts(const upf_ebpf::pb::UPFeBPFArg &arg) {
  access_port_ =
      std::unique_ptr<PortConf>(new PortConf(arg.conf().access_port()));
  core_port_ = std::unique_ptr<PortConf>(new PortConf(arg.conf().core_port()));

  access_port_->setDstMacAddress(arg.port_mac_conf().access_dst_mac());
  core_port_->setDstMacAddress(arg.port_mac_conf().core_dst_mac());

  return 0;
}

int UPFeBPF::openAndLoadAccess(const upf_ebpf::pb::UPFeBPFArg_Conf &conf) {
  int err = 0;

  /* Open BPF application */
  skel_access_ = upf_bpf_main_bpf__open();
  if (!skel_access_) {
    fprintf(stderr, "Failed to open BPF access skeleton");
    return -1;
  }

  skel_access_->rodata->upf_cfg.log_level = pbLogLevelToEbpf(conf.log_level());
  skel_access_->rodata->upf_cfg.if_id = IF_INDEX_ACCESS;
  skel_access_->rodata->upf_cfg.if_index_access = access_port_->getIfIndex();
  skel_access_->rodata->upf_cfg.if_index_core = core_port_->getIfIndex();
  skel_access_->rodata->upf_cfg.running_mode =
      pbRunningModeToEbpf(conf.running_mode());

  std::vector<uint8_t> access_src_mac;
  PortConf::macStrtoByteArray(access_src_mac, access_port_->getMacAddress());
  std::copy(access_src_mac.begin(), access_src_mac.end(),
            skel_access_->rodata->upf_mac_cfg.access_src_mac);

  std::vector<uint8_t> access_dst_mac;
  PortConf::macStrtoByteArray(access_dst_mac, access_port_->getDstMacAddress());
  std::copy(access_dst_mac.begin(), access_dst_mac.end(),
            skel_access_->rodata->upf_mac_cfg.access_dst_mac);

  std::vector<uint8_t> core_src_mac;
  PortConf::macStrtoByteArray(core_src_mac, core_port_->getMacAddress());
  std::copy(core_src_mac.begin(), core_src_mac.end(),
            skel_access_->rodata->upf_mac_cfg.core_src_mac);

  std::vector<uint8_t> core_dst_mac;
  PortConf::macStrtoByteArray(core_dst_mac, core_port_->getDstMacAddress());
  std::copy(core_dst_mac.begin(), core_dst_mac.end(),
            skel_access_->rodata->upf_mac_cfg.core_dst_mac);

  xdp_prog_access_ = xdp_program__from_bpf_obj(skel_access_->obj, "upf_main");

  if (running_mode_ == upf_ebpf::pb::UPFeBPFArg_Conf_Mode_XDP) {
    // Attach program to access port
    err = xdp_program__attach(xdp_prog_access_, access_port_->getIfIndex(),
                              XDP_MODE_NATIVE, 0);
    if (err) {
      fprintf(stderr, "Failed to attach XDP program to access port");
      return -1;
    }
  } else {
    bpf_program__set_type(xdp_prog_access_->bpf_prog, BPF_PROG_TYPE_XDP);
    err = xdp_program__load_prog(xdp_prog_access_);

    if (err) {
      fprintf(stderr, "Failed to load XDP program to access port");
      return -1;
    }
  }

  return 0;
}

int UPFeBPF::openAndLoadCore(const upf_ebpf::pb::UPFeBPFArg_Conf &conf) {
  int err = 0;

  /* Open BPF application */
  skel_core_ = upf_bpf_main_bpf__open();
  if (!skel_core_) {
    fprintf(stderr, "Failed to open BPF core skeleton");
    return -1;
  }

  skel_core_->rodata->upf_cfg.log_level = pbLogLevelToEbpf(conf.log_level());
  skel_core_->rodata->upf_cfg.if_id = IF_INDEX_CORE;
  skel_core_->rodata->upf_cfg.if_index_access = access_port_->getIfIndex();
  skel_core_->rodata->upf_cfg.if_index_core = core_port_->getIfIndex();
  skel_access_->rodata->upf_cfg.running_mode =
      pbRunningModeToEbpf(conf.running_mode());

  std::vector<uint8_t> access_src_mac;
  PortConf::macStrtoByteArray(access_src_mac, access_port_->getMacAddress());
  std::copy(access_src_mac.begin(), access_src_mac.end(),
            skel_core_->rodata->upf_mac_cfg.access_src_mac);

  std::vector<uint8_t> access_dst_mac;
  PortConf::macStrtoByteArray(access_dst_mac, access_port_->getDstMacAddress());
  std::copy(access_dst_mac.begin(), access_dst_mac.end(),
            skel_core_->rodata->upf_mac_cfg.access_dst_mac);

  std::vector<uint8_t> core_src_mac;
  PortConf::macStrtoByteArray(core_src_mac, core_port_->getMacAddress());
  std::copy(core_src_mac.begin(), core_src_mac.end(),
            skel_core_->rodata->upf_mac_cfg.core_src_mac);

  std::vector<uint8_t> core_dst_mac;
  PortConf::macStrtoByteArray(core_dst_mac, core_port_->getDstMacAddress());
  std::copy(core_dst_mac.begin(), core_dst_mac.end(),
            skel_core_->rodata->upf_mac_cfg.core_dst_mac);

  xdp_prog_core_ = xdp_program__from_bpf_obj(skel_core_->obj, "upf_main");

  if (running_mode_ == upf_ebpf::pb::UPFeBPFArg_Conf_Mode_XDP) {
    // Attach program to core port
    err = xdp_program__attach(xdp_prog_core_, core_port_->getIfIndex(),
                              XDP_MODE_NATIVE, 0);
    if (err) {
      fprintf(stderr, "Failed to attach XDP program to access port");
      return -1;
    }
  } else {
    bpf_program__set_type(xdp_prog_core_->bpf_prog, BPF_PROG_TYPE_XDP);
    err = xdp_program__load_prog(xdp_prog_core_);

    if (err) {
      fprintf(stderr, "Failed to load XDP program to access port");
      return -1;
    }
  }

  return 0;
}

int UPFeBPF::setValuesRedirectMap() {
  int key, value, ret;

  // Set values for the ACCESS port
  key = IF_INDEX_ACCESS - 1;
  value = access_port_->getIfIndex();
  ret = bpf_map_update_elem(access_redirect_map_fd_, &key, &value, BPF_ANY);
  if (ret != 0) {
    fprintf(stderr,
            "bpf_map_update_elem inside setValuesRedirectMap failed (access)");
    return -1;
  }

  key = IF_INDEX_ACCESS - 1;
  value = access_port_->getIfIndex();
  ret = bpf_map_update_elem(core_redirect_map_fd_, &key, &value, BPF_ANY);
  if (ret != 0) {
    fprintf(stderr,
            "bpf_map_update_elem inside setValuesRedirectMap failed (access)");
    return -1;
  }

  // Set values for the CORE port
  key = IF_INDEX_CORE - 1;
  value = core_port_->getIfIndex();
  ret = bpf_map_update_elem(access_redirect_map_fd_, &key, &value, BPF_ANY);
  if (ret != 0) {
    fprintf(stderr,
            "bpf_map_update_elem inside setValuesRedirectMap failed (core)");
    return -1;
  }

  key = IF_INDEX_CORE - 1;
  value = core_port_->getIfIndex();
  ret = bpf_map_update_elem(core_redirect_map_fd_, &key, &value, BPF_ANY);
  if (ret != 0) {
    fprintf(stderr,
            "bpf_map_update_elem inside setValuesRedirectMap failed (core)");
    return -1;
  }

  return 0;
}

CommandResponse UPFeBPF::Init(const upf_ebpf::pb::UPFeBPFArg &arg) {
  int err;

  /* Set up libbpf errors and debug info callback */
  libbpf_set_print(libbpf_print_fn);

  /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
  bump_memlock_rlimit();

  err = initPorts(arg);
  if (err) {
    return CommandFailure(-1, "Error while initializing ports");
  }

  running_mode_ = arg.conf().running_mode();

  err = openAndLoadAccess(arg.conf());
  if (err) {
    return CommandFailure(-1, "Failed to attach BPF ACCESS program");
  }

  err = openAndLoadCore(arg.conf());
  if (err) {
    return CommandFailure(-1, "Failed to attach BPF CORE program");
  }

  pdr_map_fd_ = bpf_map__fd(skel_access_->maps.pdr_list_m);
  if (pdr_map_fd_ <= 0) {
    return CommandFailure(-1,
                          "Unable to get file descriptor for map pdr_list_m");
  }

  far_map_fd_ = bpf_map__fd(skel_access_->maps.far_list_m);
  if (far_map_fd_ <= 0) {
    return CommandFailure(-1,
                          "Unable to get file descriptor for map far_list_m");
  }

  app_qer_map_fd_ = bpf_map__fd(skel_access_->maps.app_qer_list_m);
  if (app_qer_map_fd_ <= 0) {
    return CommandFailure(
        -1, "Unable to get file descriptor for map app_qer_list_m");
  }

  session_qer_map_fd_ = bpf_map__fd(skel_access_->maps.session_qer_list_m);
  if (session_qer_map_fd_ <= 0) {
    return CommandFailure(
        -1, "Unable to get file descriptor for map session_qer_map_fd_");
  }

  access_redirect_map_fd_ = bpf_map__fd(skel_access_->maps.redir_map_m);
  if (access_redirect_map_fd_ <= 0) {
    return CommandFailure(
        -1, "Unable to get file descriptor for access map redirect_map_fd_");
  }

  core_redirect_map_fd_ = bpf_map__fd(skel_core_->maps.redir_map_m);
  if (core_redirect_map_fd_ <= 0) {
    return CommandFailure(
        -1, "Unable to get file descriptor for core map redirect_map_fd_");
  }

  err = setValuesRedirectMap();
  if (err) {
    return CommandFailure(-1, "Failed to set values on the redirect map");
  }

  return CommandSuccess();
}

CommandResponse
UPFeBPF::CommandAddPDR(const upf_ebpf::pb::UPFeBPFCommandAddPDRArg &arg) {
  struct upf_ebpf::pdr_key_s key;
  key.src_iface = arg.keys().srciface();
  key.tunnel_ip4_dst = arg.keys().tunnelip4dst();
  key.tunnel_teid = arg.keys().tunnelteid();
  key.ue_ip_src_addr = arg.keys().ueipsrcaddr();
  key.inet_ip_dst_addr = arg.keys().inetipdstaddr();
  key.ue_src_port = arg.keys().uesrcport();
  key.inet_src_port = arg.keys().inetsrcport();
  key.proto_id = arg.keys().protoid();

  struct upf_ebpf::pdr_value_s value;
  value.pdr_id = arg.values().pdrid();
  value.fse_id = arg.values().fseid();
  value.ctr_id = arg.values().ctrid();
  value.qer_id = arg.values().qerid();
  value.far_id = arg.values().farid();

  // Now it is time to insert the entry in the map
  int ret = bpf_map_update_elem(pdr_map_fd_, &key, &value, BPF_ANY);
  if (ret != 0) {
    return CommandFailure(-1, "bpf_map_update_elem inside addPDR failed");
  }

  return CommandSuccess();
}

CommandResponse
UPFeBPF::CommandDeletePDR(const upf_ebpf::pb::UPFeBPFCommandDeletePDRArg &arg) {
  struct upf_ebpf::pdr_key_s key;
  key.src_iface = arg.keys().srciface();
  key.tunnel_ip4_dst = arg.keys().tunnelip4dst();
  key.tunnel_teid = arg.keys().tunnelteid();
  key.ue_ip_src_addr = arg.keys().ueipsrcaddr();
  key.inet_ip_dst_addr = arg.keys().inetipdstaddr();
  key.ue_src_port = arg.keys().uesrcport();
  key.inet_src_port = arg.keys().inetsrcport();
  key.proto_id = arg.keys().protoid();

  // Now it is time to delete the entry in the map
  int ret = bpf_map_delete_elem(pdr_map_fd_, &key);
  if (ret != 0) {
    return CommandFailure(-1, "bpf_map_delete_elem inside delPDR failed");
  }

  return CommandSuccess();
}

CommandResponse
UPFeBPF::CommandAddFAR(const upf_ebpf::pb::UPFeBPFCommandAddFARArg &arg) {
  struct upf_ebpf::far_key_s key;
  key.far_id = arg.keys().farid();
  key.fse_id = arg.keys().fseid();

  struct upf_ebpf::far_value_s value;
  value.action = arg.values().action();
  value.tunnel_type = arg.values().tunneltype();
  value.tunnel_ip4_src = arg.values().tunnelip4src();
  value.tunnel_ip4_dst = arg.values().tunnelip4dst();
  value.tunnel_teid = arg.values().tunnelteid();
  value.tunnel_port = arg.values().tunnelport();

  // Now it is time to insert the entry in the map
  int ret = bpf_map_update_elem(far_map_fd_, &key, &value, BPF_ANY);
  if (ret != 0) {
    return CommandFailure(-1, "bpf_map_update_elem inside addPDR failed");
  }

  return CommandSuccess();
}

CommandResponse
UPFeBPF::CommandDeleteFAR(const upf_ebpf::pb::UPFeBPFCommandDeleteFARArg &arg) {
  struct upf_ebpf::far_key_s key;
  key.far_id = arg.keys().farid();
  key.fse_id = arg.keys().fseid();

  // Now it is time to delete the entry in the map
  int ret = bpf_map_delete_elem(far_map_fd_, &key);
  if (ret != 0) {
    return CommandFailure(-1, "bpf_map_delete_elem inside delPDR failed");
  }

  return CommandSuccess();
}

CommandResponse UPFeBPF::CommandClear(const bess::pb::EmptyArg &) {
  if (xdp_prog_access_ != nullptr) {
    bpf_object__unpin_maps(skel_access_->obj, NULL);
    if (running_mode_ == upf_ebpf::pb::UPFeBPFArg_Conf_Mode_XDP) {
      xdp_program__detach(xdp_prog_access_, access_port_->getIfIndex(),
                          XDP_MODE_NATIVE, 0);
    }
    xdp_program__close(xdp_prog_access_);
    upf_bpf_main_bpf__destroy(skel_access_);
  }

  if (xdp_prog_core_ != nullptr) {
    bpf_object__unpin_maps(skel_core_->obj, NULL);
    if (running_mode_ == upf_ebpf::pb::UPFeBPFArg_Conf_Mode_XDP) {
      xdp_program__detach(xdp_prog_core_, core_port_->getIfIndex(),
                          XDP_MODE_NATIVE, 0);
    }
    xdp_program__close(xdp_prog_core_);
    upf_bpf_main_bpf__destroy(skel_core_);
  }

  return CommandSuccess();
}

CommandResponse
UPFeBPF::CommandAddAppQoS(const upf_ebpf::pb::UPFeBPFCommandAddAppQoSArg &arg) {
  // std::cout << "Add App QoS: " << std::endl;
  // std::cout << "CIR: " + arg.qos_val().cir() << std::endl;
  // std::cout << "PIR: " + arg.qos_val().pir() << std::endl;
  // std::cout << "CBS: " + arg.qos_val().cbs() << std::endl;
  // std::cout << "PBS: " + arg.qos_val().pbs() << std::endl;
  // std::cout << "EBS: " + arg.qos_val().ebs() << std::endl;
  // std::cout << "Keys: " << std::endl;
  // std::cout << "SrcIface: " + arg.keys().srciface() << std::endl;
  // std::cout << "QER_ID: " + arg.keys().qerid() << std::endl;
  // std::cout << "FSE_ID: " + arg.keys().fseid() << std::endl;
  // std::cout << "Value: " << std::endl;
  // std::cout << "QFI_ID: " + arg.values().qfiid() << std::endl;

  /* First of all, let's perform some checks to understand if the parameters
   * that receive are correct */

  /* Committed information rate (CIR)
   *  This is the bandwidth limit for guaranteed traffic
   *  Measured in bytes of IP packets per second
   */
  uint64_t cir = arg.qos_val().cir();

  /* Peak information rate (CIR)
   *  This is the bandwidth limit for peak traffic
   *  Measured in bytes of IP packets per second
   */
  uint64_t pir = arg.qos_val().pir();

  /* Committed burst size (CBS)
   *  This is the maximum packet size for burst of data in the CIR
   *  This basically indicates the capacity of the CIR bucket (in bytes)
   */
  uint64_t cbs = arg.qos_val().cbs();

  /* Peak burst size (PBS)
   *  This is the maximum packet size for burst of data in the PIR
   *  This basically indicates the capacity of the PIR bucket (in bytes)
   */
  uint64_t pbs = arg.qos_val().pbs();

  if (cir <= 0 || pir <= 0 || cir > pir) {
    return CommandFailure(-1, "The value of CIR or PIR is zero or CIR > PIR");
  }

  if (cbs <= 0 || pbs <= 0) {
    return CommandFailure(-1, "The value of CBS or PBS is zero");
  }

  struct upf_ebpf::app_qer_key_s key;
  key.src_iface = arg.keys().srciface();
  key.qer_id = arg.keys().qerid();
  key.fse_id = arg.keys().fseid();

  struct upf_ebpf::app_qer_value_s value;
  value.qfi_id = arg.values().qfiid();

  /* Now it is time to fill the tocken bucket with the correct values */
  /* Let's start from the CIR bucket */
  value.cir_bucket.capacity = cbs;
  value.cir_bucket.tokens = cbs;
  value.cir_bucket.last_refill = 0;
  value.cir_bucket.refill_rate = cir;

  /* Now it is time to fill the tocken bucket with the correct values */
  /* Let's start from the PIR bucket */
  value.pir_bucket.capacity = pbs;
  value.pir_bucket.tokens = pbs;
  value.pir_bucket.last_refill = 0;
  value.pir_bucket.refill_rate = pir;

  // Now it is time to insert the entry in the map
  int ret = bpf_map_update_elem(app_qer_map_fd_, &key, &value, BPF_ANY);
  if (ret != 0) {
    return CommandFailure(-1, "bpf_map_update_elem inside addAppQoS failed");
  }

  return CommandSuccess();
}

CommandResponse UPFeBPF::CommandDeleteAppQoS(
    const upf_ebpf::pb::UPFeBPFCommandDelAppQoSArg &arg) {
  struct upf_ebpf::app_qer_key_s key;
  key.src_iface = arg.keys().srciface();
  key.qer_id = arg.keys().qerid();
  key.fse_id = arg.keys().fseid();

  // Now it is time to delete the entry in the map
  int ret = bpf_map_delete_elem(app_qer_map_fd_, &key);
  if (ret != 0) {
    return CommandFailure(-1, "bpf_map_delete_elem inside delAppQoS failed");
  }

  return CommandSuccess();
}

CommandResponse UPFeBPF::CommandAddSessionQoS(
    const upf_ebpf::pb::UPFeBPFCommandAddSessionQoSArg &arg) {
  // std::cout << "Add App QoS: " << std::endl;
  // std::cout << "CIR: " + arg.qos_val().cir() << std::endl;
  // std::cout << "PIR: " + arg.qos_val().pir() << std::endl;
  // std::cout << "CBS: " + arg.qos_val().cbs() << std::endl;
  // std::cout << "PBS: " + arg.qos_val().pbs() << std::endl;
  // std::cout << "EBS: " + arg.qos_val().ebs() << std::endl;
  // std::cout << "Keys: " << std::endl;
  // std::cout << "SrcIface: " + arg.keys().srciface() << std::endl;
  // std::cout << "FSE_ID: " + arg.keys().fseid() << std::endl;

  /* First of all, let's perform some checks to understand if the parameters
   * that receive are correct */

  /* Committed information rate (CIR)
   *  This is the bandwidth limit for guaranteed traffic
   *  Measured in bytes of IP packets per second
   */
  uint64_t cir = arg.qos_val().cir();

  /* Peak information rate (CIR)
   *  This is the bandwidth limit for peak traffic
   *  Measured in bytes of IP packets per second
   */
  uint64_t pir = arg.qos_val().pir();

  /* Committed burst size (CBS)
   *  This is the maximum packet size for burst of data in the CIR
   *  This basically indicates the capacity of the CIR bucket (in bytes)
   */
  uint64_t cbs = arg.qos_val().cbs();

  /* Peak burst size (PBS)
   *  This is the maximum packet size for burst of data in the PIR
   *  This basically indicates the capacity of the PIR bucket (in bytes)
   */
  uint64_t pbs = arg.qos_val().pbs();

  if (cir <= 0 || pir <= 0 || cir > pir) {
    return CommandFailure(-1, "The value of CIR or PIR is zero or CIR > PIR");
  }

  if (cbs <= 0 || pbs <= 0) {
    return CommandFailure(-1, "The value of CBS or PBS is zero");
  }

  struct upf_ebpf::session_qer_key_s key;
  key.src_iface = arg.keys().srciface();
  key.fse_id = arg.keys().fseid();

  struct upf_ebpf::session_qer_value_s value;

  /* Now it is time to fill the tocken bucket with the correct values */
  /* Let's start from the CIR bucket */
  value.cir_bucket.capacity = cbs;
  value.cir_bucket.tokens = cbs;
  value.cir_bucket.last_refill = 0;
  value.cir_bucket.refill_rate = cir;

  /* Now it is time to fill the tocken bucket with the correct values */
  /* Let's start from the PIR bucket */
  value.pir_bucket.capacity = pbs;
  value.pir_bucket.tokens = pbs;
  value.pir_bucket.last_refill = 0;
  value.pir_bucket.refill_rate = pir;

  // Now it is time to insert the entry in the map
  int ret = bpf_map_update_elem(session_qer_map_fd_, &key, &value, BPF_ANY);
  if (ret != 0) {
    return CommandFailure(-1,
                          "bpf_map_update_elem inside addSessionQoS failed");
  }

  return CommandSuccess();
}

CommandResponse UPFeBPF::CommandDeleteSessionQoS(
    const upf_ebpf::pb::UPFeBPFCommandDelSessionQoSArg &arg) {
  struct upf_ebpf::session_qer_key_s key;
  key.src_iface = arg.keys().srciface();
  key.fse_id = arg.keys().fseid();

  // Now it is time to delete the entry in the map
  int ret = bpf_map_delete_elem(session_qer_map_fd_, &key);
  if (ret != 0) {
    return CommandFailure(-1,
                          "bpf_map_delete_elem inside delSessionQoS failed");
  }

  return CommandSuccess();
}

CommandResponse UPFeBPF::CommandGetBPFProgsInfo(__attribute__((
    unused)) const upf_ebpf::pb::UPFeBPFCommandGetBPFProgsInfoArg &arg) {
  int accessID, coreID;
  upf_ebpf::pb::UPFeBPFCommandGetBPFProgsInfoResponse r;

  accessID = xdp_program__id(xdp_prog_access_);
  coreID = xdp_program__id(xdp_prog_core_);

  r.set_accessid(accessID);
  r.set_coreid(coreID);

  return CommandSuccess(r);
}

uint8_t UPFeBPF::pbLogLevelToEbpf(
    const upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel &log_level) {
  switch (log_level) {
  case upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel_ERR:
    return 1;
  case upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel_WARNING:
    return 2;
  case upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel_NOTICE:
    return 3;
  case upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel_INFO:
    return 4;
  case upf_ebpf::pb::UPFeBPFArg_Conf_LogLevel_DEBUG:
    return 5;
  default:
    return 0;
  }
  return 0;
}

uint8_t UPFeBPF::pbRunningModeToEbpf(
    const upf_ebpf::pb::UPFeBPFArg_Conf_Mode &running_mode) {
  switch (running_mode) {
  case upf_ebpf::pb::UPFeBPFArg_Conf_Mode_XDP:
    return 0;
  case upf_ebpf::pb::UPFeBPFArg_Conf_Mode_COMBINED:
    return 1;
  default:
    return 0;
  }
  return 0;
}

void UPFeBPF::ProcessBatch(__attribute__((unused)) Context *ctx,
                           __attribute__((unused)) bess::PacketBatch *batch) {}

ADD_MODULE(UPFeBPF, "upf-ebpf", "5G UPF built with eBPF/XDP")