#pragma once

#include <atomic>

struct pcap;
using pcap_t = pcap;

namespace pcapture::util {

// Process-wide stop flag set by signal handlers.
std::atomic<bool>& stop_flag();

// Install SIGINT/SIGTERM (POSIX) or Ctrl-C handler (Windows). The handler
// flips stop_flag() and calls pcap_breakloop() on the registered handle.
void install_signal_handlers();

// Tell the signal subsystem which pcap handle to break out of. Pass nullptr
// to clear before the handle is closed.
void set_active_pcap(pcap_t* handle);

} // namespace pcapture::util
