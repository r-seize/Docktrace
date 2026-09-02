cmake_minimum_required(VERSION 3.20)
project(docktrace VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(DOCKTRACE_ENABLE_EBPF  "Enable eBPF collection (requires clang, libbpf-dev)" OFF)
option(DOCKTRACE_ENABLE_TESTS "Build unit tests" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ─── C++ dependencies ────────────────────────────────────────────────────────
find_package(CLI11        CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(fmt          CONFIG REQUIRED)
find_package(spdlog       CONFIG REQUIRED)
find_package(yaml-cpp     CONFIG REQUIRED)

# ─── eBPF dependencies ───────────────────────────────────────────────────────
if(DOCKTRACE_ENABLE_EBPF)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBBPF REQUIRED libbpf)

    set(EBPF_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ebpf")
    set(EBPF_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/ebpf")
    file(MAKE_DIRECTORY "${EBPF_OUT_DIR}")

    # Compile each .bpf.c -> .bpf.o -> skeleton header
    foreach(BPF_SRC process filesystem network)
        set(SRC  "${EBPF_SRC_DIR}/${BPF_SRC}.bpf.c")
        set(OBJ  "${EBPF_OUT_DIR}/${BPF_SRC}.bpf.o")
        set(SKEL "${EBPF_OUT_DIR}/${BPF_SRC}.skel.h")

        add_custom_command(OUTPUT "${OBJ}"
            COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_x86
                    -I "${EBPF_SRC_DIR}"
                    -I "${LIBBPF_INCLUDE_DIRS}"
                    -c "${SRC}" -o "${OBJ}"
            DEPENDS "${SRC}" "${EBPF_SRC_DIR}/common.h"
            COMMENT "Compiling eBPF: ${BPF_SRC}.bpf.c"
            VERBATIM
        )
        add_custom_command(OUTPUT "${SKEL}"
            COMMAND bpftool gen skeleton "${OBJ}" > "${SKEL}"
            DEPENDS "${OBJ}"
            COMMENT "Generating skeleton: ${BPF_SRC}.skel.h"
            VERBATIM
        )
        list(APPEND EBPF_SKELETONS "${SKEL}")
    endforeach()

    add_custom_target(ebpf_skeletons DEPENDS ${EBPF_SKELETONS})
endif()

# ─── Main library ────────────────────────────────────────────────────────────
file(GLOB_RECURSE DOCKTRACE_SOURCES
    "src/cli/*.cpp"
    "src/model/*.cpp"
    "src/container/*.cpp"
    "src/collector/*.cpp"
    "src/policy/*.cpp"
    "src/output/*.cpp"
)

add_library(docktrace_lib STATIC ${DOCKTRACE_SOURCES})
target_include_directories(docktrace_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(docktrace_lib PUBLIC
    CLI11::CLI11
    nlohmann_json::nlohmann_json
    fmt::fmt
    spdlog::spdlog
    yaml-cpp::yaml-cpp
)

if(DOCKTRACE_ENABLE_EBPF)
    add_dependencies(docktrace_lib ebpf_skeletons)
    target_compile_definitions(docktrace_lib PUBLIC DOCKTRACE_EBPF_ENABLED)
    target_include_directories(docktrace_lib PUBLIC
        ${LIBBPF_INCLUDE_DIRS}
        ${EBPF_OUT_DIR}          # for generated .skel.h files
    )
    target_link_libraries(docktrace_lib PUBLIC ${LIBBPF_LIBRARIES} elf z)
endif()

# ─── Executable ──────────────────────────────────────────────────────────────
add_executable(docktrace src/main.cpp)
target_link_libraries(docktrace PRIVATE docktrace_lib)
install(TARGETS docktrace RUNTIME DESTINATION bin)

# ─── Tests ───────────────────────────────────────────────────────────────────
if(DOCKTRACE_ENABLE_TESTS)
    enable_testing()
    find_package(Catch2 CONFIG REQUIRED)
    add_subdirectory(tests)
endif()

# ─── Packaging (.deb / .rpm) ─────────────────────────────────────────────────
set(CPACK_PACKAGE_NAME                "docktrace")
set(CPACK_PACKAGE_VERSION             "${PROJECT_VERSION}")
set(CPACK_PACKAGE_CONTACT             "r-seize")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Observe containers and generate minimal security profiles")
set(CPACK_PACKAGE_DESCRIPTION
    "Docktrace watches a running container via /proc or eBPF and turns the observed behavior into a minimal Seccomp/capabilities profile.")
set(CPACK_DEBIAN_PACKAGE_SECTION      "utils")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS    ON)   # auto-detect runtime .so deps
set(CPACK_GENERATOR                   "DEB")
include(CPack)
