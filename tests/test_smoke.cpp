#include <gtest/gtest.h>

#include "app/packet_queue.hpp"

// Phase 1 baseline test. Real per-protocol tests land in tests/decode/* in Phase 4.

TEST(Smoke, Truthy) {
    EXPECT_TRUE(true);
}

TEST(BoundedQueueSmoke, PushPopOne) {
    pcapture::pipeline::BoundedQueue<int> q(4);
    EXPECT_EQ(q.push(42), pcapture::pipeline::PushResult::Ok);
    auto v = q.pop();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 42);
}
