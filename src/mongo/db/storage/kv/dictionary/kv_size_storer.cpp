// kv_size_storer.cpp

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

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kStorage

#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/scoped_ptr.hpp>

#include "mongo/bson/bsonobj.h"
#include "mongo/bson/bsonobjbuilder.h"
#include "mongo/db/concurrency/write_conflict_exception.h"
#include "mongo/db/operation_context_noop.h"
#include "mongo/db/storage/kv/dictionary/kv_record_store.h"
#include "mongo/db/storage/kv/dictionary/kv_dictionary.h"
#include "mongo/db/storage/kv/dictionary/kv_size_storer.h"
#include "mongo/db/storage/kv/slice.h"
#include "mongo/db/storage/recovery_unit.h"
#include "mongo/stdx/functional.h"
#include "mongo/util/log.h"
#include "mongo/util/mongoutils/str.h"

namespace mongo {

    namespace {
        int MAGIC = 123321;
    }

    KVSizeStorer::KVSizeStorer(KVDictionary *metadataDict, RecoveryUnit *ru)
        : _metadataDict(metadataDict),
          _syncRunning(true),
          _syncTerminated(false),
          _syncThread(stdx::bind(&KVSizeStorer::syncThread, this, ru))
    {
        _magic = MAGIC;
    }

    KVSizeStorer::~KVSizeStorer() {
        {
            boost::mutex::scoped_lock lk(_syncMutex);
            _syncRunning = false;
            _syncCond.notify_one();
        }

        boost::mutex::scoped_lock lk(_syncMutex);
        while (!_syncTerminated) {
            _syncCond.wait(lk);
        }
        _syncThread.join();

        _magic = 11111;
    }

    void KVSizeStorer::syncThread(RecoveryUnit *ru) {
        boost::scoped_ptr<OperationContext> opCtx(new OperationContextNoop(ru));

        while (_syncRunning) {
            {
                boost::mutex::scoped_lock lk(_syncMutex);
                _syncCond.timed_wait(lk, boost::posix_time::milliseconds(1000));
            }

            storeIntoDict(opCtx.get());
        }
        boost::mutex::scoped_lock lk(_syncMutex);
        _syncTerminated = true;
        LOG(1) << "KVSizeStorer::syncThread terminating" << std::endl;
        _syncCond.notify_one();
    }

    void KVSizeStorer::_checkMagic() const {
        if ( _magic == MAGIC )
            return;
        log() << "KVSizeStorer magic wrong: " << _magic;
        invariant( _magic == MAGIC );
    }

    void KVSizeStorer::onCreate(RecordStore *rs, const StringData &ident,
                                long long numRecords, long long dataSize) {
        store(rs, ident, numRecords, dataSize);
    }

    void KVSizeStorer::onDestroy(const StringData &ident,
                                 long long numRecords, long long dataSize) {
        store(NULL, ident, numRecords, dataSize);
    }


    void KVSizeStorer::store(RecordStore *rs, const StringData& ident,
                             long long numRecords, long long dataSize) {
        _checkMagic();
        boost::mutex::scoped_lock lk( _entriesMutex );
        Entry& entry = _entries[ident.toString()];
        entry.numRecords = numRecords;
        entry.dataSize = dataSize;
        entry.dirty = true;
        entry.rs = rs;
    }

    void KVSizeStorer::load(const StringData& ident,
                            long long* numRecords, long long* dataSize) const {
        _checkMagic();
        boost::mutex::scoped_lock lk( _entriesMutex );
        Map::const_iterator it = _entries.find(ident.toString());
        if (it == _entries.end()) {
            *numRecords = 0;
            *dataSize = 0;
            return;
        }
        *numRecords = it->second.numRecords;
        *dataSize = it->second.dataSize;
    }

    BSONObj KVSizeStorer::Entry::serialize() const {
        return BSON( "numRecords" << numRecords <<
                     "dataSize" << dataSize );
    }

    KVSizeStorer::Entry::Entry(const BSONObj &serialized)
        : numRecords(serialized["numRecords"].safeNumberLong()),
          dataSize(serialized["dataSize"].safeNumberLong()),
          dirty(false),
          rs(NULL)
    {}

    void KVSizeStorer::loadFromDict(OperationContext *opCtx) {
        _checkMagic();

        Map m;
        {
            for (boost::scoped_ptr<KVDictionary::Cursor> cur(_metadataDict->getRangedCursor(opCtx));
                 cur->ok(); cur->advance(opCtx)) {
                const std::string key(cur->currKey().data(), cur->currKey().size());
                BSONObj data(cur->currVal().data());
                LOG(2) << "KVSizeStorer::loadFrom " << key << " -> " << data;
                Entry& e = m[key];
                e = Entry(data);
            }
        }

        boost::mutex::scoped_lock lk( _entriesMutex );
        _entries = m;
    }

    void KVSizeStorer::storeIntoDict(OperationContext *opCtx) {
        Map m;
        {
            boost::mutex::scoped_lock lk( _entriesMutex );
            for (Map::iterator it = _entries.begin(); it != _entries.end(); ++it) {
                const std::string &ident = it->first;
                Entry& entry = it->second;

                if ( entry.rs ) {
                    if ( entry.dataSize != entry.rs->dataSize( NULL ) ) {
                        entry.dataSize = entry.rs->dataSize( NULL );
                        entry.dirty = true;
                    }
                    if ( entry.numRecords != entry.rs->numRecords( NULL ) ) {
                        entry.numRecords = entry.rs->numRecords( NULL );
                        entry.dirty = true;
                    }
                }

                if (!entry.dirty) {
                    continue;
                }

                m[ident] = entry;
                entry.dirty = false;
            }
        }

        try {
            WriteUnitOfWork wuow(opCtx);
            for (Map::const_iterator it = m.begin(); it != m.end(); ++it) {
                const std::string &ident = it->first;
                const Entry& entry = it->second;

                BSONObj data = entry.serialize();

                LOG(2) << "KVSizeStorer::storeInto " << ident << " -> " << data;

                Slice key(ident);
                Slice value(data.objdata(), data.objsize());

                Status s = _metadataDict->insert(opCtx, key, value, false);
                massert(28635, str::stream() << "KVSizeStorer::storeInto: insert: " << s.toString(), s.isOK());
            }
            wuow.commit();
        } catch (WriteConflictException) {
            // meh, someone else must be doing it
        }
    }

}
