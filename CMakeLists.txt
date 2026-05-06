cmake_minimum_required(VERSION 3.15)
project(pcapture LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(ENABLE_SANITIZERS "Enable AddressSanitizer + UBSan" OFF)
option(BUILD_TESTING "Build unit tests" ON)

if(MSVC)
  add_compile_options(/W4 /permissive-)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

if(ENABLE_SANITIZERS)
  if(MSVC)
    message(WARNING "ENABLE_SANITIZERS requested but not supported with MSVC; ignoring")
  else()
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
  endif()
endif()

# --- libpcap / Npcap ---------------------------------------------------------
# On Linux/macOS: pkg-config locates libpcap.
# On Windows: point PCAP_ROOT (or NPCAP_SDK_DIR) at the Npcap SDK.
if(WIN32)
  set(PCAP_ROOT "" CACHE PATH "Path to Npcap SDK (contains Include/ and Lib/)")
  if(NOT PCAP_ROOT)
    if(DEFINED ENV{NPCAP_SDK_DIR})
      set(PCAP_ROOT "$ENV{NPCAP_SDK_DIR}")
    endif()
  endif()
  if(NOT PCAP_ROOT)
    message(FATAL_ERROR
      "Npcap SDK not found. Install Npcap SDK and pass -DPCAP_ROOT=<path> "
      "or set NPCAP_SDK_DIR.")
  endif()
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_pcap_libdir "${PCAP_ROOT}/Lib/x64")
  else()
    set(_pcap_libdir "${PCAP_ROOT}/Lib")
  endif()
  add_library(pcap::pcap INTERFACE IMPORTED)
  target_include_directories(pcap::pcap INTERFACE "${PCAP_ROOT}/Include")
  target_link_directories(pcap::pcap INTERFACE "${_pcap_libdir}")
  target_link_libraries(pcap::pcap INTERFACE wpcap Packet ws2_32 iphlpapi)
  target_compile_definitions(pcap::pcap INTERFACE PCAPTURE_WINDOWS=1 WIN32_LEAN_AND_MEAN NOMINMAX)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
  add_library(pcap::pcap ALIAS PkgConfig::PCAP)
endif()

# --- third-party: cxxopts ----------------------------------------------------
include(FetchContent)
FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG v3.2.0
)
set(CXXOPTS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CXXOPTS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CXXOPTS_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(cxxopts)

# --- core library ------------------------------------------------------------
add_library(pcapture_core
  src/cli/config.cpp
  src/capture/pcap_capture.cpp
  src/capture/pcap_handle.cpp
  src/capture/platform/signals.cpp
  src/model/protocol_model.cpp
  src/parser/parser.cpp
  src/parser/decoder_registry.cpp
  src/protocols/ethernet.cpp
  src/protocols/vlan.cpp
  src/protocols/ipv4.cpp
  src/protocols/ipv6.cpp
  src/protocols/arp.cpp
  src/protocols/tcp.cpp
  src/protocols/udp.cpp
  src/protocols/icmp.cpp
  src/common/checksum.cpp
  src/filter/filter.cpp
  src/output/format_helpers.cpp
  src/output/text_formatter.cpp
  src/output/compact_formatter.cpp
  src/output/json_formatter.cpp
  src/output/sink.cpp
  src/output/hex_formatter.cpp
  src/app/packet_queue.cpp
  src/app/application.cpp
)
target_include_directories(pcapture_core PUBLIC src)
target_link_libraries(pcapture_core
  PUBLIC pcap::pcap Threads::Threads
  PRIVATE cxxopts::cxxopts)

# --- main executable ---------------------------------------------------------
add_executable(pcapture src/main.cpp)
target_link_libraries(pcapture PRIVATE pcapture_core)

# --- tests -------------------------------------------------------------------
if(BUILD_TESTING)
  enable_testing()
  include(FetchContent)
  FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
  )
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  add_executable(pcapture_tests
    tests/test_smoke.cpp
    tests/test_config_parser.cpp
    tests/test_decoders.cpp
    tests/test_formatters.cpp
    tests/test_bounded_queue.cpp
    tests/test_filter.cpp
    tests/test_hexdump.cpp
    tests/test_replay_pipeline.cpp
  )
  target_link_libraries(pcapture_tests PRIVATE pcapture_core pcap::pcap GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(pcapture_tests)
endif()
