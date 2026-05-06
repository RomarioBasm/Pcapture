#include "capture/platform/signals.hpp"

#include <pcap.h>

#ifdef _WIN32
  #include <windows.h>
#else
  #include <csignal>
#endif

#include <atomic>

namespace pcapture::util {
namespace {

std::atomic<pcap_t*> g_active_pcap{nullptr};

void on_stop() {
    stop_flag().store(true, std::memory_order_release);
    if (auto* p = g_active_pcap.load(std::memory_order_acquire); p != nullptr) {
        pcap_breakloop(p);
    }
}

#ifdef _WIN32
BOOL WINAPI windows_handler(DWORD type) {
    switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        on_stop();
        return TRUE;
    default:
        return FALSE;
    }
}
#else
extern "C" void posix_handler(int /*sig*/) {
    on_stop();
}
#endif

} // namespace

std::atomic<bool>& stop_flag() {
    static std::atomic<bool> flag{false};
    return flag;
}

void set_active_pcap(pcap_t* handle) {
    g_active_pcap.store(handle, std::memory_order_release);
}

void install_signal_handlers() {
#ifdef _WIN32
    SetConsoleCtrlHandler(windows_handler, TRUE);
#else
    struct sigaction sa{};
    sa.sa_handler = posix_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // intentionally not SA_RESTART so blocking syscalls return EINTR
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
#endif
}

} // namespace pcapture::util
