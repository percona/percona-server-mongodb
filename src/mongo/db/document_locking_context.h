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

#include "mongo/base/disallow_copying.h"

namespace mongo {

    class BSONObj;
    class Ordering;

/**
 * This class/interface provides an API to set and probe the logical
 * lock state for a set of documents and the operations on those
 * documents.
 */
class DocumentLockingContext {
    MONGO_DISALLOW_COPYING(DocumentLockingContext);

public:
    virtual ~DocumentLockingContext() {}

    /**
     * This method is used by storage engines to determine if the left
     * and right bounds of a query or scan have been cached and can be
     * used to create a ranged cursor.  
     *
     * NOTE: Derived classes should return true if the left and right
     * BSON bounds have been set.
    */
    virtual bool HasBounds() const { return false; }

    /**
     * These two methods return pointers to cached left and right BSON
     * keys, respectively.  Derived classes should return NULL if no
     * key has been set.
    */
    virtual BSONObj *GetLeftBounds() { return NULL; }
    virtual BSONObj *GetRightBounds() { return NULL; }

    /**
     * These two methods cache the given (i.e. not owned by THIS
     * class) BSON key pointers for potential use by a storage engine
     * cursor.
    */
    virtual void SetLeftBounds(BSONObj *left) {};
    virtual void SetRightBounds(BSONObj *right) {};

    /**
     * Caches the cursor scan ordering, which may be needed by a
     * storage engine at the time of cursor creation.
    */
    virtual const Ordering *GetCursorOrdering() const { return NULL; }
    virtual void SetCursorOrdering(const Ordering *order) {};

protected:
    DocumentLockingContext() {}
};

}  // namespace mongo
