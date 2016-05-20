#pragma once

#include <deque>

#include "mongo/bson/bsonobj.h"

namespace mongo {

struct PartitionMetaData {
    typedef std::deque<PartitionMetaData> deque;

    PartitionMetaData(const BSONElement& pmd)
        : obj(pmd.Obj().getOwned()), id(obj["_id"].numberLong()) {}

    PartitionMetaData(const BSONObj& pmd)
        : obj(pmd.getOwned()), id(obj["_id"].numberLong()) {}

    BSONObj obj;
    int64_t id; // parsed value of partition id
};

}
