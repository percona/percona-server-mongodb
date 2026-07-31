// Copyright (c) MongoDB, Inc.
// SPDX-License-Identifier: SSPL-1.0

#include "mongo/otel/traces/span/span_telemetry_context_impl.h"

#include "mongo/platform/random.h"
#include "mongo/stdx/thread.h"
#include "mongo/unittest/unittest.h"

#include <memory>
#include <span>
#include <thread>

#include <opentelemetry/trace/noop.h>
#include <opentelemetry/trace/span_context.h>

namespace mongo {
namespace otel {
namespace traces {
namespace {

class SpanTelemetryContextImplTest : public unittest::Test {
public:
    OtelContext getSpanContext() {
        return OtelContext();
    }

    ScopedSpan makeValidSpan() {
        constexpr uint8_t kTraceIdBytes[16] = {1};
        constexpr uint8_t kSpanIdBytes[8] = {1};
        auto ctx = std::unique_ptr<opentelemetry::trace::SpanContext>(
            new opentelemetry::trace::SpanContext(
                opentelemetry::trace::TraceId(std::span<const uint8_t, 16>(kTraceIdBytes)),
                opentelemetry::trace::SpanId(std::span<const uint8_t, 8>(kSpanIdBytes)),
                opentelemetry::trace::TraceFlags{},
                false));
        auto tracer = std::make_shared<opentelemetry::trace::NoopTracer>();
        return std::shared_ptr<opentelemetry::trace::Span>(
            new opentelemetry::trace::NoopSpan(tracer, std::move(ctx)));
    }
};

TEST_F(SpanTelemetryContextImplTest, SamplingRollIsInUnitInterval) {
    PseudoRandom prng(int64_t{1});
    SpanTelemetryContextImpl impl(getSpanContext(), &prng);
    double roll = impl.getSamplingValue();
    ASSERT_GTE(roll, 0.0);
    ASSERT_LT(roll, 1.0);
}

TEST_F(SpanTelemetryContextImplTest, SamplingRollIsStable) {
    PseudoRandom prng(int64_t{1});
    SpanTelemetryContextImpl impl(getSpanContext(), &prng);
    double first = impl.getSamplingValue();

    // Repeated calls must return the constructor-drawn value. This is the "one roll per
    // telemetry context" invariant.
    double second = impl.getSamplingValue();
    ASSERT_EQ(first, second);
}

TEST_F(SpanTelemetryContextImplTest, HasActiveTraceReturnsFalseWhenNoSpanIsSet) {
    SpanTelemetryContextImpl impl(getSpanContext());
    ASSERT_FALSE(impl.hasActiveTrace());
}

TEST_F(SpanTelemetryContextImplTest, HasActiveTraceReturnsTrueWhenSpanIsSet) {
    SpanTelemetryContextImpl impl(getSpanContext());
    impl.setSpan(makeValidSpan());
    ASSERT_TRUE(impl.hasActiveTrace());
}

// TSAN regression for concurrent setSpan writes vs getSpan/hasActiveTrace reads of _ctx.
// No ASSERT/EXPECT by design: correctness is enforced by ThreadSanitizer detecting a data race.
//
// The writer is bounded to a fixed iteration count rather than looping until a stop flag. Each
// setSpan prepends a node to the underlying OpenTelemetry Context's persistent list (it is never
// pruned), so an unbounded writer accumulates a chain whose recursive destruction at teardown
// overflows the stack -- a non-deterministic crash whose likelihood scales with how many
// iterations the writer wins. A fixed, modest count keeps the chain small enough to tear down
// safely while still exercising concurrent access; both loops yield each iteration so the writes
// and reads interleave rather than one loop draining before the other starts.
TEST_F(SpanTelemetryContextImplTest, ConcurrentSetSpanAndGetSpan) {
    constexpr int kIterations = 10000;
    SpanTelemetryContextImpl impl(getSpanContext());

    stdx::thread writer([&] {
<<<<<<< HEAD
        for (int i = 0; i < kIterations; ++i) {
||||||| bb7a39b05fe
        while (!stop.load()) {
=======
        // Internally, our span's DataList maintains a shared ptr to the next node.
        // Cap the writes so that we don't stack overflow on recursive DataList destruction.
        constexpr int kWriteIterations = 50;
        for (int i = 0; i < kWriteIterations; ++i) {
>>>>>>> 8c9f0d06cee875c13c1ff04a941df790e25650f4
            impl.setSpan(makeValidSpan());
            std::this_thread::yield();
        }
    });

    for (int i = 0; i < kIterations; ++i) {
        (void)impl.getSpan();
        (void)impl.hasActiveTrace();
        std::this_thread::yield();
    }

    writer.join();
}

}  // namespace
}  // namespace traces
}  // namespace otel
}  // namespace mongo
