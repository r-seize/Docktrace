#pragma once
#include <optional>
#include <string>
#include "docktrace/model/container.hpp"

namespace docktrace::container {

// Resolves a container name/id to ContainerInfo by querying the Docker socket.
std::optional<ContainerInfo> resolve_docker(const std::string& name_or_id);

// Low-level: read container PID from /run/docker/netns or via /proc traversal.
std::optional<uint32_t> find_container_root_pid(const std::string& container_id);

} // namespace docktrace::container
