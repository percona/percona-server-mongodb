/**
 *    Copyright (C) 2025-present MongoDB, Inc.
 *
 *    This program is free software: you can redistribute it and/or modify
 *    it under the terms of the Server Side Public License, version 1,
 *    as published by MongoDB, Inc.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    Server Side Public License for more details.
 *
 *    You should have received a copy of the Server Side Public License
 *    along with this program. If not, see
 *    <http://www.mongodb.com/licensing/server-side-public-license>.
 *
 *    As a special exception, the copyright holders give permission to link the
 *    code of portions of this program with the OpenSSL library under certain
 *    conditions as described in each individual source file and distribute
 *    linked combinations including the program with the OpenSSL library. You
 *    must comply with the Server Side Public License in all respects for
 *    all of the code used other than as permitted herein. If you modify file(s)
 *    with this exception, you may extend this exception to your version of the
 *    file(s), but you are not obligated to do so. If you do not wish to do so,
 *    delete this exception statement from your version. If you delete this
 *    exception statement from all source files in the program, then also delete
 *    it in the license file.
 */

#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/exec/sbe/vm/vm.h"
#include "mongo/db/query/stage_builder/sbe/gen_helpers.h"

#include <benchmark/benchmark.h>

namespace mongo::sbe {

/**
 * Benchmark fixture with a generic, policy-based driver.
 *
 * Axes:
 *  - ShapePolicy: document shape / number of fields / target position
 *  - ValuePolicy: value type and size for the target field
 *  - FieldNamePolicy: field-name spelling / length (key size)
 *  - PresencePolicy: which field name is queried each iteration (hit/miss ratio)
 */
class GetFieldBenchmark : public benchmark::Fixture {
public:
    template <class ShapePolicy, class ValuePolicy, class FieldNamePolicy, class PresencePolicy>
    void runPolicyBm(benchmark::State& state) {
        BSONObj obj = ShapePolicy::template makeDoc<ValuePolicy, FieldNamePolicy>();

        auto [type, val] = stage_builder::makeValue(obj);
        vm::ByteCode byteCode;

        size_t i = 0;
        for (auto _ : state) {
            StringData fieldName = PresencePolicy::template selectField<FieldNamePolicy>(i++);
            benchmark::DoNotOptimize(byteCode.getField_test(type, val, fieldName));
        }
    }
};

/**
 * Field-name policies (key size / spelling).
 */
struct ShortFieldName {
    static StringData hit() {
        static const char* k = "z";  // 1-char key
        return StringData(k);
    }
    static StringData miss() {
        static const char* k = "q";
        return StringData(k);
    }
    static std::string pad(int i) {
        return "pad" + std::to_string(i);
    }
};

struct MediumFieldName {
    static StringData hit() {
        static const char* k = "veryLongFieldName";
        return StringData(k);
    }
    static StringData miss() {
        static const char* k = "anotherLongFieldName";
        return StringData(k);
    }
    static std::string pad(int i) {
        return "pad_medium_" + std::to_string(i);
    }
};

struct LongFieldName {
    static const std::string& hitStorage() {
        static const std::string s(64, 'a');  // 64-char key
        return s;
    }
    static const std::string& missStorage() {
        static const std::string s(64, 'b');
        return s;
    }
    static StringData hit() {
        return StringData(hitStorage());
    }
    static StringData miss() {
        return StringData(missStorage());
    }
    static std::string pad(int i) {
        return "pad_long_field_name_" + std::to_string(i);
    }
};

/**
 * Shape policies (document layout / target position).
 */

// Single-field document: just the target key.
struct OneFieldShape {
    template <class ValuePolicy, class FieldNamePolicy>
    static BSONObj makeDoc() {
        BSONObjBuilder bob;
        ValuePolicy::append(bob, FieldNamePolicy::hit());
        return bob.obj();
    }
};

// Many fields, target first.
struct ManyFieldsTargetFirst {
    static constexpr int kNumPad = 100;

    template <class ValuePolicy, class FieldNamePolicy>
    static BSONObj makeDoc() {
        BSONObjBuilder bob;
        // Target first.
        ValuePolicy::append(bob, FieldNamePolicy::hit());
        // Pads use the same value and field-name policies.
        for (int i = 0; i < kNumPad; ++i) {
            const std::string name = FieldNamePolicy::pad(i);
            ValuePolicy::append(bob, name);
        }
        return bob.obj();
    }
};

// Many fields, target last.
struct ManyFieldsTargetLast {
    static constexpr int kNumPad = 100;

    template <class ValuePolicy, class FieldNamePolicy>
    static BSONObj makeDoc() {
        BSONObjBuilder bob;
        // Pads first, using the same value + field-name policies.
        for (int i = 0; i < kNumPad; ++i) {
            const std::string name = FieldNamePolicy::pad(i);
            ValuePolicy::append(bob, name);
        }
        // Target last.
        ValuePolicy::append(bob, FieldNamePolicy::hit());
        return bob.obj();
    }
};

/**
 * Value policies (value type / size for the target field).
 */

struct Int32Small {
    static void append(BSONObjBuilder& bob, StringData fieldName) {
        bob.append(fieldName, 42);
    }
};

struct String1KB {
    static void append(BSONObjBuilder& bob, StringData fieldName) {
        static const std::string kBuf(1024, 'x');  // 1 KB
        bob.append(fieldName, kBuf);
    }
};

/**
 * Presence policies (hit/miss / mix of field names).
 */

struct AlwaysHit {
    template <class FieldNamePolicy>
    static StringData selectField(size_t /*i*/) {
        return FieldNamePolicy::hit();
    }
};

struct AlwaysMiss {
    template <class FieldNamePolicy>
    static StringData selectField(size_t /*i*/) {
        return FieldNamePolicy::miss();
    }
};

struct Hit90Miss10 {
    template <class FieldNamePolicy>
    static StringData selectField(size_t i) {
        // Every 10th lookup is a miss.
        return (i % 10 == 0) ? FieldNamePolicy::miss() : FieldNamePolicy::hit();
    }
};

/**
 * Helper macro to define a benchmark for a given combination of policies.
 */
#define DEFINE_GETFIELD_BM(shape, value, fname, presence)                  \
    BENCHMARK_F(GetFieldBenchmark, shape##_##value##_##fname##_##presence) \
    (benchmark::State & state) {                                           \
        runPolicyBm<shape, value, fname, presence>(state);                 \
    }

#define FOR_EACH_PRESENCE(M, shape, value, fname) \
    M(shape, value, fname, AlwaysHit)             \
    M(shape, value, fname, AlwaysMiss)            \
    M(shape, value, fname, Hit90Miss10)

#define FOR_EACH_FNAME(M, shape, value)                 \
    FOR_EACH_PRESENCE(M, shape, value, ShortFieldName)  \
    FOR_EACH_PRESENCE(M, shape, value, MediumFieldName) \
    FOR_EACH_PRESENCE(M, shape, value, LongFieldName)

#define FOR_EACH_VALUE(M, shape)         \
    FOR_EACH_FNAME(M, shape, Int32Small) \
    FOR_EACH_FNAME(M, shape, String1KB)

#define FOR_EACH_SHAPE(M)                    \
    FOR_EACH_VALUE(M, OneFieldShape)         \
    FOR_EACH_VALUE(M, ManyFieldsTargetFirst) \
    FOR_EACH_VALUE(M, ManyFieldsTargetLast)

#define GEN_GETFIELD_BM(shape, value, fname, presence) \
    DEFINE_GETFIELD_BM(shape, value, fname, presence)

// Generate the full matrix.
FOR_EACH_SHAPE(GEN_GETFIELD_BM);

#undef GEN_GETFIELD_BM
#undef FOR_EACH_SHAPE
#undef FOR_EACH_VALUE
#undef FOR_EACH_FNAME
#undef FOR_EACH_PRESENCE
}  // namespace mongo::sbe
