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

#include "mongo/db/commands.h"
#include "mongo/db/storage_options.h"

namespace mongo {
    extern StorageGlobalParams storageGlobalParams;
    namespace partcoll {
        class PartitionCommandBase : public Command {
        public:
            PartitionCommandBase(const char *name) : Command(name) {}
            virtual bool slaveOk() const override { return true; }
            bool currentEngineSupportsPartitionedCollections() const {
                return storageGlobalParams.engine == "PerconaFT";
            }
            void printEngineSupportFailure(std::string &errmsg) const {
                errmsg = "Parttioned collections are not supported by the current storage engine.";
            }
        };
    }
}
