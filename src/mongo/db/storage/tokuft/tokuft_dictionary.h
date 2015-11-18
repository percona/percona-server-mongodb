// tokuft_dictionary.h

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

#include <algorithm>

#include "mongo/base/status.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/mutable/damage_vector.h"
#include "mongo/db/storage/kv/dictionary/kv_dictionary.h"
#include "mongo/db/storage/kv/dictionary/kv_dictionary_update.h"
#include "mongo/db/storage/kv/slice.h"
#include "mongo/db/storage/record_data.h"
#include "mongo/db/storage/tokuft/tokuft_capped_delete_range_optimizer.h"
#include "mongo/db/storage/tokuft/tokuft_dictionary_options.h"

#include <ftcxx/cursor.hpp>
#include <ftcxx/db.hpp>
#include <ftcxx/db_env.hpp>
#include <ftcxx/db_txn.hpp>
#include <ftcxx/slice.hpp>

namespace mongo {

    class BSONElement;
    class BSONObjBuilder;
    class RecordId;
    class IndexDescriptor;
    class OperationContext;
    class TokuFTDictionaryOptions;

    inline Slice ftslice2slice(const ftcxx::Slice &in) {
        return Slice(in.data(), in.size());
    }

    inline ftcxx::Slice slice2ftslice(const Slice &in) {
        return ftcxx::Slice(in.data(), in.size());
    }

    // This dictionary interface implementation powers default RecordStore
    // and SortedDataInterface implementations in src/mongo/db/storage/kv.
    class TokuFTDictionary : public KVDictionary {
    public:
        TokuFTDictionary(const ftcxx::DBEnv &env, const ftcxx::DBTxn &txn, const StringData &ident,
                         const KVDictionary::Encoding &enc, const TokuFTDictionaryOptions& options);

        class Encoding : public KVDictionary::Encoding {
        public:
            Encoding(const KVDictionary::Encoding &enc)
                : KVDictionary::Encoding(enc)
            {}

            Encoding(const ftcxx::Slice &serialized)
                : KVDictionary::Encoding(ftslice2slice(serialized))
            {}

            int operator()(const ftcxx::Slice &a, const ftcxx::Slice &b) const {
                return cmp(a, b);
            }

            static int cmp(const ftcxx::Slice &a, const ftcxx::Slice &b) {
                return KVDictionary::Encoding::cmp(ftslice2slice(a), ftslice2slice(b));
            }

            BSONObj extractKey(const ftcxx::Slice &key, const ftcxx::Slice &val) const {
                return KVDictionary::Encoding::extractKey(ftslice2slice(key), ftslice2slice(val));
            }

            RecordId extractRecordId(const ftcxx::Slice &s) const {
                return KVDictionary::Encoding::extractRecordId(ftslice2slice(s));
            }
        };

        class Cursor : public KVDictionary::Cursor {
        public:
            Cursor(const TokuFTDictionary &dict, OperationContext *txn, const Slice &key, const int direction = 1);
            Cursor(const TokuFTDictionary &dict,
                   OperationContext *txn,
                   const Slice &key,
                   const bool prelock,
                   const int direction = 1);

            Cursor(const TokuFTDictionary &dict, OperationContext *txn, const int direction = 1);
            Cursor(const TokuFTDictionary &dict,
                   OperationContext *txn,
                   const Slice &leftKey,
                   const Slice &rightKey,
                   const int direction = 1);

            virtual bool ok() const;

            virtual void seek(OperationContext *opCtx, const Slice &key);

            virtual void advance(OperationContext *opCtx);

            virtual Slice currKey() const;

            virtual Slice currVal() const;

        private:
            typedef ftcxx::BufferedCursor<TokuFTDictionary::Encoding, ftcxx::DB::NullFilter> FTCursor;
            FTCursor _cur;
            Slice _currKey;
            Slice _currVal;
            bool _ok;
        };

        virtual Status get(OperationContext *opCtx, const Slice &key, Slice &value, bool skipPessimisticLocking=false) const;

        virtual Status dupKeyCheck(OperationContext *opCtx, const Slice &lookupLeft, const Slice &lookupRight, const RecordId &id);
        virtual bool supportsDupKeyCheck() const {
            return true;
        }

        virtual Status insert(OperationContext *opCtx, const Slice &key, const Slice &value, bool skipPessimisticLocking);

        virtual bool updateSupported() const { return true; }

        virtual Status update(OperationContext *opCtx, const Slice &key, const Slice &oldValue,
                              const KVUpdateMessage &message) {
            return update(opCtx, key, message);
        }

        virtual Status update(OperationContext *opCtx, const Slice &key, const KVUpdateMessage &message);

        virtual Status remove(OperationContext *opCtx, const Slice &key);

        virtual void justDeletedCappedRange(OperationContext *opCtx, const Slice &left, const Slice &right,
                                            int64_t sizeSaved, int64_t docsRemoved);

        virtual KVDictionary::Cursor *getCursor(OperationContext *opCtx, const Slice &key, const int direction = 1) const;

        virtual KVDictionary::Cursor *getRangedCursor(OperationContext *opCtx, const Slice &key, const int direction = 1) const;

        virtual KVDictionary::Cursor *getRangedCursor(OperationContext *opCtx, const int direction = 1) const;

        virtual const char *name() const { return "PerconaFT"; }

        virtual KVDictionary::Stats getStats() const;
    
        virtual bool useExactStats() const { return true; }

        virtual bool appendCustomStats(OperationContext *opCtx, BSONObjBuilder* result, double scale ) const;

        virtual bool compactSupported() const { return true; }

        virtual bool compactsInPlace() const { return true; }

        virtual Status compact(OperationContext *opCtx);

        const ftcxx::DB &db() const { return _db; }

    private:
        KVDictionary::Cursor *CreatePrelockedCursorWithRetryAndStartKey(OperationContext *opCtx,
                                                                        const Slice &key,
                                                                        const int direction) const;
        KVDictionary::Cursor *CreatePrelockedCursorWithRetry(OperationContext *opCtx, const int direction = 1) const;
        KVDictionary::Cursor *CreatePrelockedCursorWithStartKey(OperationContext *opCtx,
                                                                const Slice &key,
                                                                const int direction) const;
        KVDictionary::Cursor *CreatePrelockedCursor(OperationContext *opCtx, const int direction = 1) const;
        Encoding encoding() const {
            return TokuFTDictionary::Encoding(_db.descriptor());
        }

        TokuFTDictionaryOptions _options;
        ftcxx::DB _db;
        boost::scoped_ptr<TokuFTCappedDeleteRangeOptimizer> _rangeOptimizer;
    };

} // namespace mongo
