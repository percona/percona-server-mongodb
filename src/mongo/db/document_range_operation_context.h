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

#include "mongo/db/document_locking_context.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/storage/kv/slice.h"

namespace mongo {

/**
 *  This class implements all the methods needed to help storage
 *  engines optimize document level locking.
 */
class DocumentRangeOperationContext : public OperationContext {
public:
    DocumentRangeOperationContext() : _leftKeyIsSet(false), _rightKeyIsSet(false) {}
    virtual ~DocumentRangeOperationContext() {}

    virtual bool HasBounds() const {
        return _leftKeyIsSet && _rightKeyIsSet;
    }

    virtual BSONObj *GetLeftBounds() {
        return &_left;
    }

    virtual BSONObj *GetRightBounds() {
        return &_right;
    }

    virtual void SetLeftBounds(BSONObj *left) {
        _left = *left;
        _leftKeyIsSet = true;
    }

    virtual void SetRightBounds(BSONObj *right) {
        _right = *right;
        _rightKeyIsSet = true;
    }

    virtual const Ordering *GetCursorOrdering() const {
        return _ordering;
    }

    virtual void SetCursorOrdering(const Ordering *order) {
        _ordering = order;
    }

private:
    BSONObj _left;
    BSONObj _right;
    bool _leftKeyIsSet;
    bool _rightKeyIsSet;
    const Ordering *_ordering;
};

}  // namespace mongo
