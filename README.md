# Docktrace

![License](https://img.shields.io/badge/license-BSD%203--Clause-blue)
![Version](https://img.shields.io/badge/version-0.1.0-informational)
![C++](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus)
![Platform](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)
![CMake](https://img.shields.io/badge/build-CMake-064F8C?logo=cmake)
![eBPF](https://img.shields.io/badge/eBPF-optional-orange)

Observe a running container, understand what it actually does, and generate a minimal security profile from real behavior.

Docktrace watches a container for a period of time (which processes run, which files are touched, which network connections are made) then turns that observation into a Seccomp/capabilities profile you can enforce.


## Install

### Option A - Install from .deb (simplest)

Download the `.deb` from the [releases page](https://github.com/r-seize/docktrace/releases) and install it:

```bash
sudo dpkg -i docktrace-0.1.0-Linux.deb
docktrace --version
```

No build tools needed. Works on Ubuntu, Debian, and derivatives.

### Option B - Build from source (Ubuntu / Debian)

```bash
# 1. Get the source
git clone https://github.com/r-seize/docktrace.git
cd docktrace

# 2. Install build dependencies
sudo apt install -y cmake g++ \
    libcli11-dev nlohmann-json3-dev \
    libfmt-dev libspdlog-dev libyaml-cpp-dev

# 3. Build and install
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DDOCKTRACE_ENABLE_TESTS=OFF
cmake --build build --parallel
sudo cmake --install build
```

Or generate a `.deb` yourself:

```bash
cd build && cpack
sudo dpkg -i docktrace-0.1.0-Linux.deb
```

> **Without sudo:** `cmake --install build --prefix ~/.local` works if `~/.local/bin` is in your `PATH`.

### Full build - any distro (with tests + eBPF support)

Requires [vcpkg](https://github.com/microsoft/vcpkg):

```bash
git clone https://github.com/microsoft/vcpkg.git ~/vcpkg
~/vcpkg/bootstrap-vcpkg.sh -disableMetrics

./bootstrap.sh           # standard build
./bootstrap.sh --ebpf    # with eBPF support (needs clang + libbpf-dev)
./bootstrap.sh --release # optimized binary

sudo cmake --install build   # or: cmake --install build --prefix ~/.local
```

Optional, for eBPF collection (more accurate, requires root):

```bash
sudo apt install clang libbpf-dev libelf-dev linux-headers-$(uname -r)
```


## Usage

### Check your environment

```bash
docktrace doctor
```

Shows whether eBPF, Docker socket, /proc, and other prerequisites are available.


### Inspect a container

```bash
docktrace inspect --container <name>
```

Displays the container's PID, cgroup ID, configured capabilities, volumes, seccomp profile, and UID/GID.


### Observe a container

```bash
docktrace observe --container <name> --duration 60s -o report.json
```

Watches the container for the given duration and saves a report. Duration format: `30s`, `2m`, `1h`.

You can also observe by PID directly:

```bash
docktrace observe --pid 1234 --duration 30s -o report.json
```

Filter which event types to collect (default: process, file, network):

```bash
docktrace observe --container <name> --duration 60s --events process,network
```


### View a report

```bash
docktrace report --input report.json
docktrace report --input report.json --format json
docktrace report --input report.json --format markdown
docktrace report --input report.json --format html -o report.html
```


### Generate a security profile

```bash
docktrace profile --input report.json --format yaml
docktrace profile --input report.json --format oci-seccomp -o seccomp.json
```

The `yaml` format gives a human-readable suggested profile (capabilities to drop, syscalls observed, read-only root recommendation). The `oci-seccomp` format produces a JSON file you can pass directly to Docker:

```bash
docker run --security-opt seccomp=seccomp.json ...
```


### Validate a profile

```bash
docktrace validate --input seccomp.json     # OCI Seccomp JSON
docktrace validate --input profile.yaml     # Docktrace YAML profile
```

Exits 0 if valid, 1 with an error message if not.


### Compare two reports

```bash
docktrace diff --baseline baseline.json --current current.json
```

Highlights what is new in the current report compared to the baseline (new processes, network destinations, file writes, syscalls). Exits 1 if any deviation is found, useful in CI.


### Baseline workflow

Capture a reference observation, then compare future runs against it:

```bash
# Step 1 - record baseline behavior
docktrace baseline create --container <name> --duration 60s -o baseline.json

# Step 2 - re-run later and compare
docktrace baseline check --container <name> --duration 60s --baseline baseline.json
```

`baseline check` exits 1 if behavior has changed. Run it in your CI pipeline to detect unexpected changes between releases.

View the contents of a baseline file:

```bash
docktrace baseline list --input baseline.json
```


## Example: full workflow with a web container

```bash
# Observe for 2 minutes while the container handles real traffic
docktrace observe --container myapp --duration 2m -o myapp-report.json

# Generate a seccomp profile
docktrace profile --input myapp-report.json --format oci-seccomp -o myapp-seccomp.json

# Validate it
docktrace validate --input myapp-seccomp.json

# Apply it
docker run --security-opt seccomp=myapp-seccomp.json myimage
```


## Without Docker

You can use Docktrace on any process, not just containers:

```bash
docktrace observe --pid $(pgrep nginx) --duration 30s -o report.json
```


## eBPF vs /proc collection

Without `--ebpf`, Docktrace reads from `/proc` (no root required). This captures processes and open file descriptors but misses short-lived activity.

With eBPF (`./bootstrap.sh --ebpf`), Docktrace attaches to kernel tracepoints and sees every `execve`, `openat`, and `connect` call in real time. This requires root and a kernel with BTF enabled (`/sys/kernel/btf/vmlinux`).

Docktrace automatically picks eBPF when available and falls back to `/proc` otherwise.


## License

BSD 3-Clause License

Copyright (c) 2026, r-seize

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
