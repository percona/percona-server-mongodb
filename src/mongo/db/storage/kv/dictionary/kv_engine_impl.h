// kv_engine_impl.h

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

#include <boost/scoped_ptr.hpp>
#include <boost/thread/mutex.hpp>

#include "mongo/db/storage/kv/dictionary/kv_dictionary.h"
#include "mongo/db/storage/kv/dictionary/kv_size_storer.h"
#include "mongo/db/storage/kv/kv_engine.h"

namespace mongo {

    /*
     * A KVEngine interface that provides implementations for each of
     * create, get, and drop recordStore/sortedDataInterface that use
     * classes built on top of KVDictionary.
     *
     * Storage engine authors that have access to a sorted kv store API
     * are likely going to want to use this interface for KVEngine as it
     * only requires them to implement a subclass of KVDictionary (and a
     * recovery unit) and nothing more.
     */
    class KVEngineImpl : public KVEngine {
        boost::scoped_ptr<KVSizeStorer> _sizeStorer;

    public:
        virtual ~KVEngineImpl() { }

        virtual RecoveryUnit* newRecoveryUnit() = 0;

        // ---------

        /**
         * @param ident Ident is a one time use string. It is used for this instance
         *              and never again.
         */
        Status createRecordStore( OperationContext* opCtx,
                                  const StringData& ns,
                                  const StringData& ident,
                                  const CollectionOptions& options );

        /**
         * Caller takes ownership
         * Having multiple out for the same ns is a rules violation;
         * Calling on a non-created ident is invalid and may crash.
         */
        RecordStore* getRecordStore( OperationContext* opCtx,
                                     const StringData& ns,
                                     const StringData& ident,
                                     const CollectionOptions& options );

        // --------

        Status createSortedDataInterface( OperationContext* opCtx,
                                          const StringData& ident,
                                          const IndexDescriptor* desc );

        SortedDataInterface* getSortedDataInterface( OperationContext* opCtx,
                                                     const StringData& ident,
                                                     const IndexDescriptor* desc );

        Status dropIdent( OperationContext* opCtx,
                          const StringData& ident );

        Status okToRename( OperationContext* opCtx,
                           const StringData& fromNS,
                           const StringData& toNS,
                           const StringData& ident,
                           const RecordStore* originalRecordStore ) const;

        void cleanShutdown();

    protected:
        // Create a KVDictionary (same rules as createRecordStore / createSortedDataInterface)
        // 
        // param: enc, the encoding that should be passed to the KVDictionary
        virtual Status createKVDictionary(OperationContext* opCtx,
                                          const StringData& ident,
                                          const KVDictionary::Encoding &enc,
                                          const BSONObj& options) = 0;

        // Get a KVDictionary (same rules as getRecordStore / getSortedDataInterface)
        //
        // param: enc, the encoding that should be passed to the KVDictionary
        virtual KVDictionary* getKVDictionary(OperationContext* opCtx,
                                              const StringData& ident,
                                              const KVDictionary::Encoding &enc,
                                              const BSONObj& options,
                                              bool mayCreate = false) = 0;

        // Drop a KVDictionary (same rules as dropRecordStore / dropSortedDataInterface)
        virtual Status dropKVDictionary( OperationContext* opCtx,
                                         const StringData& ident ) = 0;

        /**
         * If true, a record store built with this engine will store its stats (numRecords and
         * dataSize) in a separate metadata dictionary.
         */
        virtual bool persistDictionaryStats() const { return false; }

        /**
         * if persistDictionaryStats() is true, this should return an engine-wide dictionary to use
         * for stats metadata.  If false, it will never be called.
         */
        virtual KVDictionary *getMetadataDictionary() {
            invariant(false);
            return NULL;
        }

        virtual KVSizeStorer *getSizeStorer(OperationContext *opCtx);

        virtual void cleanShutdownImpl() = 0;

        friend class KVSortedDataPartitioned;
    };

}
