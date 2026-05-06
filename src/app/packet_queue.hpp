#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>
#include <utility>

namespace pcapture::pipeline {

enum class PushResult {
    Ok,
    Dropped,  // queue full, drop policy applied
    Closed,
};

enum class DropPolicy {
    DropNewest,
    DropOldest,
    Block,
};

// Phase 6: bounded MPMC-friendly queue used between capture and decode threads.
template <typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(std::size_t capacity, DropPolicy policy = DropPolicy::DropNewest)
        : capacity_(capacity), policy_(policy) {}

    PushResult push(T value) {
        std::unique_lock lk(mtx_);
        if (closed_) return PushResult::Closed;
        if (q_.size() >= capacity_) {
            switch (policy_) {
            case DropPolicy::DropNewest:
                dropped_.fetch_add(1, std::memory_order_relaxed);
                return PushResult::Dropped;
            case DropPolicy::DropOldest:
                q_.pop_front();
                dropped_.fetch_add(1, std::memory_order_relaxed);
                break;
            case DropPolicy::Block:
                not_full_.wait(lk, [&] { return closed_ || q_.size() < capacity_; });
                if (closed_) return PushResult::Closed;
                break;
            }
        }
        q_.push_back(std::move(value));
        not_empty_.notify_one();
        return PushResult::Ok;
    }

    std::optional<T> pop() {
        std::unique_lock lk(mtx_);
        not_empty_.wait(lk, [&] { return closed_ || !q_.empty(); });
        if (q_.empty()) return std::nullopt;
        T v = std::move(q_.front());
        q_.pop_front();
        not_full_.notify_one();
        return v;
    }

    void close() {
        {
            std::lock_guard lk(mtx_);
            closed_ = true;
        }
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    std::size_t dropped() const noexcept { return dropped_.load(std::memory_order_relaxed); }
    std::size_t size() const { std::lock_guard lk(mtx_); return q_.size(); }

private:
    mutable std::mutex mtx_;
    std::condition_variable not_full_;
    std::condition_variable not_empty_;
    std::deque<T> q_;
    std::size_t capacity_;
    DropPolicy policy_;
    std::atomic<std::size_t> dropped_{0};
    bool closed_ = false;
};

} // namespace pcapture::pipeline
