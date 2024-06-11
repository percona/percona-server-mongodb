/**
 *    Copyright (C) 2021-present MongoDB, Inc.
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

#pragma once

#include <algorithm>
#include <set>

#include "mongo/bson/bsonobj.h"
#include "mongo/db/exec/document_value/document.h"
#include "mongo/db/timeseries/timeseries_constants.h"

namespace mongo {
/**
 * Carries parameters for unpacking a bucket. The order of operations applied to determine which
 * fields are in the final document are:
 * If we are in include mode:
 *   1. Unpack all fields from the bucket.
 *   2. Remove any fields not in _fieldSet, since we are in include mode.
 *   3. Add fields from _computedMetaProjFields.
 * If we are in exclude mode:
 *   1. Unpack all fields from the bucket.
 *   2. Add fields from _computedMetaProjFields.
 *   3. Remove any fields in _fieldSet, since we are in exclude mode.
 */
struct BucketSpec {
    // The user-supplied timestamp field name specified during time-series collection creation.
    std::string timeField;

    // An optional user-supplied metadata field name specified during time-series collection
    // creation. This field name is used during materialization of metadata fields of a measurement
    // after unpacking.
    boost::optional<std::string> metaField;

    void setUsesExtendedRange(bool usesExtendedRange) {
        _usesExtendedRange = usesExtendedRange;
    }

    bool usesExtendedRange() const {
        return _usesExtendedRange;
    }

    // Returns whether 'field' depends on a pushed down $addFields or computed $project.
    bool fieldIsComputed(StringData field) const;

    // The set of field names in the data region that should be included or excluded.
    std::set<std::string> fieldSet;

    // Vector of computed meta field projection names. Added at the end of materialized
    // measurements.
    std::set<std::string> computedMetaProjFields;

    // Remove fields that the predicate function evaluates to true for.
    void eraseIfPredTrueFromComputedMetaProjFields(const std::function<bool(std::string)> pred) {
        auto it = computedMetaProjFields.begin();
        while (it != computedMetaProjFields.end()) {
            if (pred(*it)) {
                it = computedMetaProjFields.erase(it);
            } else {
                ++it;
            }
        }
    }

    bool includeMinTimeAsMetadata = false;
    bool includeMaxTimeAsMetadata = false;

    bool _usesExtendedRange = false;
};

/**
 * BucketUnpacker will unpack bucket fields for metadata and the provided fields.
 */
class BucketUnpacker {
public:
    // When BucketUnpacker is created with kInclude it must produce measurements that contain the
    // set of fields. Otherwise, if the kExclude option is used, the measurements will include the
    // set difference between all fields in the bucket and the provided fields.
    enum class Behavior { kInclude, kExclude };
    /**
     * Returns the number of measurements in the bucket in O(1) time.
     */
    static int computeMeasurementCount(const BSONObj& bucket, StringData timeField);

    // Set of field names reserved for time-series buckets.
    static const std::set<StringData> reservedBucketFieldNames;

    BucketUnpacker();
    BucketUnpacker(BucketSpec spec, Behavior unpackerBehavior);
    BucketUnpacker(const BucketUnpacker& other) = delete;
    BucketUnpacker(BucketUnpacker&& other);
    ~BucketUnpacker();
    BucketUnpacker& operator=(const BucketUnpacker& rhs) = delete;
    BucketUnpacker& operator=(BucketUnpacker&& rhs);

    /**
     * This method will continue to materialize Documents until the bucket is exhausted. A
     * precondition of this method is that 'hasNext()' must be true.
     */
    Document getNext();

    /**
     * This method will extract the j-th measurement from the bucket. A precondition of this method
     * is that j >= 0 && j <= the number of measurements within the underlying bucket.
     */
    Document extractSingleMeasurement(int j);

    /**
     * Returns true if there is more data to fetch, is the precondition for 'getNext'.
     */
    bool hasNext() const {
        return _hasNext;
    }

    /**
     * Makes a copy of this BucketUnpacker that is detached from current bucket. The new copy needs
     * to be reset to a new bucket object to perform unpacking.
     */
    BucketUnpacker copy() const;

    /**
     * This resets the unpacker to prepare to unpack a new bucket described by the given document.
     */
    void reset(BSONObj&& bucket);

    Behavior behavior() const {
        return _unpackerBehavior;
    }

    const BucketSpec& bucketSpec() const {
        return _spec;
    }

    const BSONObj& bucket() const {
        return _bucket;
    }

    bool includeMetaField() const {
        return _includeMetaField;
    }

    bool includeTimeField() const {
        return _includeTimeField;
    }

    int32_t numberOfMeasurements() const {
        return _numberOfMeasurements;
    }

    bool includeMinTimeAsMetadata() const {
        return _includeMinTimeAsMetadata;
    }

    bool includeMaxTimeAsMetadata() const {
        return _includeMaxTimeAsMetadata;
    }

    const std::string& getTimeField() const {
        return _spec.timeField;
    }

    const boost::optional<std::string>& getMetaField() const {
        return _spec.metaField;
    }

    std::string getMinField(StringData field) const {
        return std::string{timeseries::kControlMinFieldNamePrefix} + field;
    }

    std::string getMaxField(StringData field) const {
        return std::string{timeseries::kControlMaxFieldNamePrefix} + field;
    }

    void setBucketSpecAndBehavior(BucketSpec&& bucketSpec, Behavior behavior);
    void setIncludeMinTimeAsMetadata();
    void setIncludeMaxTimeAsMetadata();

    // Add computed meta projection names to the bucket specification.
    void addComputedMetaProjFields(const std::vector<StringData>& computedFieldNames);

    // Fill _spec.unpackFieldsToIncludeExclude with final list of fields to include/exclude during
    // unpacking. Only calculates the list the first time it is called.
    const std::set<std::string>& fieldsToIncludeExcludeDuringUnpack();

    class UnpackingImpl;

private:
    // Determines if timestamp values should be included in the materialized measurements.
    void determineIncludeTimeField();

    // Removes metaField from the field set and determines whether metaField should be
    // included in the materialized measurements.
    void eraseMetaFromFieldSetAndDetermineIncludeMeta();

    // Erase computed meta projection fields if they are present in the exclusion field set or if
    // they are not present in the inclusion set.
    void eraseUnneededComputedMetaProjFields();

    BucketSpec _spec;
    Behavior _unpackerBehavior;

    std::unique_ptr<UnpackingImpl> _unpackingImpl;

    bool _hasNext = false;

    // A flag used to mark that the timestamp value should be materialized in measurements.
    bool _includeTimeField;

    // A flag used to mark that a bucket's metadata value should be materialized in measurements.
    bool _includeMetaField;

    // A flag used to mark that a bucket's min time should be materialized as metadata.
    bool _includeMinTimeAsMetadata{false};

    // A flag used to mark that a bucket's max time should be materialized as metadata.
    bool _includeMaxTimeAsMetadata{false};

    // The bucket being unpacked.
    BSONObj _bucket;

    // Since the metadata value is the same across all materialized measurements we can cache the
    // metadata BSONElement in the reset phase and use it to materialize the metadata in each
    // measurement.
    BSONElement _metaValue;


    // Since the bucket min time is the same across all materialized measurements, we can cache the
    // value in the reset phase and use it to materialize as a metadata field in each measurement
    // if required by the pipeline.
    boost::optional<Date_t> _minTime;

    // Since the bucket max time is the same across all materialized measurements, we can cache the
    // value in the reset phase and use it to materialize as a metadata field in each measurement
    // if required by the pipeline.
    boost::optional<Date_t> _maxTime;

    // Map <name, BSONElement> for the computed meta field projections. Updated for
    // every bucket upon reset().
    stdx::unordered_map<std::string, BSONElement> _computedMetaProjections;

    // The number of measurements in the bucket.
    int32_t _numberOfMeasurements = 0;

    // Final list of fields to include/exclude during unpacking. This is computed once during the
    // first doGetNext call so we don't have to recalculate every time we reach a new bucket.
    boost::optional<std::set<std::string>> _unpackFieldsToIncludeExclude = boost::none;
};

/**
 * Determines if an arbitrary field should be included in the materialized measurements.
 */
inline bool determineIncludeField(StringData fieldName,
                                  BucketUnpacker::Behavior unpackerBehavior,
                                  const std::set<std::string>& unpackFieldsToIncludeExclude) {
    const bool isInclude = unpackerBehavior == BucketUnpacker::Behavior::kInclude;
    const bool unpackFieldsContains = unpackFieldsToIncludeExclude.find(fieldName.toString()) !=
        unpackFieldsToIncludeExclude.cend();
    return isInclude == unpackFieldsContains;
}
}  // namespace mongo
