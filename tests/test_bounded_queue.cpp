#include "app/packet_queue.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using namespace pcapture::pipeline;

TEST(BoundedQueue, FifoOrder) {
    BoundedQueue<int> q(8);
    for (int i = 0; i < 5; ++i) EXPECT_EQ(q.push(i), PushResult::Ok);
    for (int i = 0; i < 5; ++i) {
        auto v = q.pop();
        ASSERT_TRUE(v.has_value());
        EXPECT_EQ(*v, i);
    }
}

TEST(BoundedQueue, DropNewestWhenFull) {
    BoundedQueue<int> q(2, DropPolicy::DropNewest);
    EXPECT_EQ(q.push(1), PushResult::Ok);
    EXPECT_EQ(q.push(2), PushResult::Ok);
    EXPECT_EQ(q.push(3), PushResult::Dropped);
    EXPECT_EQ(q.dropped(), 1u);

    EXPECT_EQ(*q.pop(), 1);
    EXPECT_EQ(*q.pop(), 2);
}

TEST(BoundedQueue, DropOldestWhenFull) {
    BoundedQueue<int> q(2, DropPolicy::DropOldest);
    q.push(1); q.push(2); q.push(3);
    EXPECT_EQ(q.dropped(), 1u);
    EXPECT_EQ(*q.pop(), 2);
    EXPECT_EQ(*q.pop(), 3);
}

TEST(BoundedQueue, BlockUntilSpaceAvailable) {
    BoundedQueue<int> q(1, DropPolicy::Block);
    q.push(1);

    std::atomic<bool> producer_returned{false};
    std::thread producer([&] {
        q.push(2);
        producer_returned = true;
    });

    // Producer must still be blocked.
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_FALSE(producer_returned.load());

    EXPECT_EQ(*q.pop(), 1);
    producer.join();
    EXPECT_TRUE(producer_returned.load());
    EXPECT_EQ(*q.pop(), 2);
}

TEST(BoundedQueue, CloseDrainsThenReturnsNullopt) {
    BoundedQueue<int> q(4);
    q.push(1); q.push(2);
    q.close();
    EXPECT_EQ(*q.pop(), 1);
    EXPECT_EQ(*q.pop(), 2);
    EXPECT_FALSE(q.pop().has_value());
}

TEST(BoundedQueue, CloseUnblocksConsumer) {
    BoundedQueue<int> q(4);
    std::atomic<bool> consumer_returned{false};
    std::thread consumer([&] {
        auto v = q.pop();
        EXPECT_FALSE(v.has_value());
        consumer_returned = true;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_FALSE(consumer_returned.load());
    q.close();
    consumer.join();
    EXPECT_TRUE(consumer_returned.load());
}

TEST(BoundedQueue, ConcurrentProducerConsumer) {
    BoundedQueue<int> q(16);
    constexpr int N = 5000;

    std::thread producer([&] {
        for (int i = 0; i < N; ++i) {
            while (q.push(i) != PushResult::Ok) {
                std::this_thread::yield();
            }
        }
        q.close();
    });

    std::vector<int> received;
    received.reserve(N);
    while (auto v = q.pop()) received.push_back(*v);

    producer.join();
    ASSERT_EQ(received.size(), static_cast<std::size_t>(N));
    for (int i = 0; i < N; ++i) EXPECT_EQ(received[i], i);
}
