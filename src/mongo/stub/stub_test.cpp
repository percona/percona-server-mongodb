#include "mongo/stub/stub.h"
#include "mongo/unittest/assert.h"

namespace stub {
namespace {
TEST(StubTest, TestAlpha) {
    ASSERT_EQ(square(2), 4);
}
}  // namespace
}  // namespace stub
