#pragma once
#include <optional>
#include <string>
#include "docktrace/model/container.hpp"

namespace docktrace::container {

// Query containerd via its gRPC/ttrpc socket (simplified JSON-over-socket approach)
std::optional<ContainerInfo> resolve_containerd(const std::string& name_or_id,
                                                const std::string& ns = "default");

// Read an OCI bundle directory (config.json + state.json)
std::optional<ContainerInfo> resolve_oci_bundle(const std::string& bundle_path);

// Generic resolver: tries Docker first, then containerd, then OCI bundle
std::optional<ContainerInfo> resolve_any(const std::string& name_or_id);

// Read cgroup_id for a PID from cgroupfs v2
uint64_t read_cgroup_id_v2(uint32_t pid);

// Read PID namespace inode
uint64_t read_pid_ns_inode(uint32_t pid);

// Enumerate all PIDs that share a PID namespace inode
std::vector<uint32_t> pids_in_namespace(uint64_t ns_inode);

} // namespace docktrace::container
