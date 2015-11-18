// kv_heap_dictionary.h

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

#include <map>

#include "mongo/base/status.h"
#include "mongo/db/storage/kv/dictionary/kv_dictionary.h"
#include "mongo/db/storage/kv/slice.h"

namespace mongo {

    class KVHeapDictionary : public KVDictionary {
    public:
        class SliceCmp {
            KVDictionary::Encoding _enc;

        public:
            SliceCmp(const KVDictionary::Encoding &enc)
                : _enc(enc)
            {}

            int cmp(const Slice &a, const Slice &b) const {
                return _enc.cmp(a, b);
            }

            bool operator()(const Slice &a, const Slice &b) const {
                const int c = cmp(a, b);
                return c < 0;
            }
        };

    private:
        SliceCmp _cmp;

        typedef std::map<Slice, Slice, SliceCmp> SliceMap;
        SliceMap _map;

        Stats _stats;

        class Cursor : public KVDictionary::Cursor {
            const SliceMap &_map;
            const SliceCmp &_cmp;
            const int _direction;

            SliceMap::const_iterator _it;
            SliceMap::const_reverse_iterator _rit;

            bool _forward() const { return _direction > 0; }

        public:
            Cursor(const SliceMap &map, const SliceCmp &cmp, const Slice &key, const int direction);

            Cursor(const SliceMap &map, const SliceCmp &cmp, const int direction);

            bool ok() const;

            void seek(OperationContext *opCtx, const Slice &key);

            void advance(OperationContext *opCtx);

            Slice currKey() const;

            Slice currVal() const;
        };

        void _insertPair(const Slice &key, const Slice &value);

        void _deleteKey(const Slice &key);

    public:
        KVHeapDictionary(const KVDictionary::Encoding &cmp = KVDictionary::Encoding());

        Status get(OperationContext *opCtx, const Slice &key, Slice &value, bool skipPessimisticLocking=false) const;

        Status insert(OperationContext *opCtx, const Slice &key, const Slice &value, bool skipPessimisticLocking);

        void rollbackInsertByDeleting(const Slice &key);

        void rollbackInsertToOldValue(const Slice &key, const Slice &value);

        Status remove(OperationContext *opCtx, const Slice &key);

        void rollbackDelete(const Slice &key, const Slice &value);

        // --------

        const char *name() const { return "KVHeapDictionary"; }

        Stats getStats() const { return _stats; }

        bool appendCustomStats(OperationContext *opCtx, BSONObjBuilder* result, double scale ) const {
            return false;
        }

        virtual bool compactSupported() const { return false; }

        KVDictionary::Cursor *getCursor(OperationContext *opCtx, const Slice &key, const int direction = 1) const;

        KVDictionary::Cursor *getRangedCursor(OperationContext *opCtx, const Slice &key, const int direction = 1) const;

        KVDictionary::Cursor *getRangedCursor(OperationContext *opCtx, const int direction = 1) const;
    };

} // namespace mongo
