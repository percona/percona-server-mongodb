/*======
This file is part of Percona Server for MongoDB.

Copyright (c) 2006, 2017, Percona and/or its affiliates. All rights reserved.

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

#include <string>

#include "mongo/base/status.h"

namespace percona {

/**
 * The interface which provides the ability to get subclass
 * via base class pointer.
 */
struct EngineGetter {
    virtual ~EngineGetter() {}

    virtual EngineGetter* getEngineForCast() const {
        // must be overridden
        invariant(false);
        return nullptr;
    }

    template <class T> T *getEngineAs() const {
        T *subclass = dynamic_cast<T *>(getEngineForCast());
        invariant(subclass != nullptr);
        return subclass;
    }

};

}  // end of percona namespace.
