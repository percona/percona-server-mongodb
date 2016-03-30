/* -*- mode: C++; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// vim: ft=cpp:expandtab:ts=8:sw=4:softtabstop=4:
/*======
This file is part of Percona Server for MongoDB.

Copyright (c) 2006, 2015, Percona and/or its affiliates. All rights reserved.

    Percona Server for MongoDB is free software: you can redistribute
    it and/or modify it under the terms of the GNU Affero General
    Public License, version 3, as published by the Free Software
    Foundation.

    Percona Server for MongoDB is distributed in the hope that it will
    be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public
    License along with Percona Server for MongoDB.  If not, see
    <http://www.gnu.org/licenses/>.
======= */

#pragma once

#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjiterator.h"
#include "mongo/bson/bsonobjbuilder.h"

namespace mongo {

inline void cloneBSONWithFieldChanged(BSONObjBuilder &b, const BSONObj &orig, const BSONElement &newElement, bool appendIfMissing = true) {
    StringData fieldName = newElement.fieldName();
    bool replaced = false;
    for (BSONObjIterator it(orig); it.more(); it.next()) {
        BSONElement e = *it;
        if (fieldName == e.fieldName()) {
            b.append(newElement);
            replaced = true;
        } else {
            b.append(e);
        }
    }
    if (!replaced && appendIfMissing) {
        b.append(newElement);
    }
}

inline BSONObj cloneBSONWithFieldChanged(const BSONObj &orig, const BSONElement &newElement, bool appendIfMissing = true) {
    BSONObjBuilder b(orig.objsize());
    cloneBSONWithFieldChanged(b, orig, newElement, appendIfMissing);
    return b.obj();
}

template<typename T>
void cloneBSONWithFieldChanged(BSONObjBuilder &b, const BSONObj &orig, const StringData &fieldName, const T &newValue, bool appendIfMissing = true) {
    bool replaced = false;
    for (BSONObjIterator it(orig); it.more(); it.next()) {
        BSONElement e = *it;
        if (fieldName == e.fieldName()) {
            b.append(fieldName, newValue);
            replaced = true;
        } else {
            b.append(e);
        }
    }
    if (!replaced && appendIfMissing) {
        b.append(fieldName, newValue);
    }
}

template<typename T>
BSONObj cloneBSONWithFieldChanged(const BSONObj &orig, const StringData &fieldName, const T &newValue, bool appendIfMissing = true) {
    BSONObjBuilder b(orig.objsize());
    cloneBSONWithFieldChanged(b, orig, fieldName, newValue, appendIfMissing);
    return b.obj();
}

}
