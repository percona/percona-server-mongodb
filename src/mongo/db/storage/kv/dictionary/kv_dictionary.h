// kv_dictionary.h

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

#include "mongo/base/status.h"
#include "mongo/bson/ordering.h"
#include "mongo/db/storage/kv/slice.h"

namespace mongo {

    class BSONElement;
    class BSONObjBuilder;
    class KVUpdateMessage;
    class OperationContext;

    /**
     * A sorted dictionary interface for mapping binary keys to binary
     * values.
     *
     * Used as the primary storage abstraction for KVRecordStore and
     * KVSortedDataInterface.
     */
    class KVDictionary {
    public:
        /**
         * Encoding describes how keys are packed in a KVDictionary.
         *
         * We use either an encoding of the RecordId which is memcmpable or KeyString which also is.
         * In TokuFT, we always use the builtin memcmp function, but the ftcxx cursors need a
         * comparison function as a template parameter for zero-copy bounds checking, so we've kept
         * the implementation of cmp and operator() here as a comparison.
         *
         * Also can describe whether we are a record store or an index, and can unpack an index's
         * keys in that case.  These facts are used somewhat by TokuFT in minor places, though the
         * KVDictionary implementation *usually* shouldn't need to know anything about the encoding.
         */
        class Encoding {
            const bool _isRecordStore;
            const bool _isIndex;
            const Ordering _ordering;

            Encoding(bool isRecordStore, bool isIndex, const Ordering &ordering)
                : _isRecordStore(isRecordStore),
                  _isIndex(isIndex),
                  _ordering(ordering)
            {}

        public:
            /**
             * An Encoding for raw bytes, compared with memcmp.
             */
            Encoding();

            /**
             * An Encoding for a record store.
             */
            static Encoding forRecordStore();

            /**
             * An Encoding for an index with the given ordering.
             */
            static Encoding forIndex(const Ordering &o);

            /**
             * Create an Encoding from a serialized byte slice.
             */
            explicit Encoding(const Slice &serialized);

            /**
             * Serialize this comparator into a byte slice that can later
             * be interpreted by the Slice constructor above. Useful for
             * dictionary implementations that need to serialize to disk
             * how keys can be sorted (and not always have that info
             * available at all times in memory with a virtual class, for
             * example).
             */
            Slice serialize() const;

            /**
             * Compare two keys with a memcmp style return value:
             *
             * < 0 iff a < b
             * == 0 iff a == b
             * > 0 iff a > b
             */
            int operator()(const Slice &a, const Slice &b) const {
                return cmp(a, b);
            }

            static int cmp(const Slice &a, const Slice &b);

            bool isRecordStore() const { return _isRecordStore; }

            bool isIndex() const { return _isIndex; }

            /**
             * Given a key-val pair, extract the key portion.  In accordance with the KeyString API,
             * we encode the TypeBits in the val, so we need that here.
             */
            BSONObj extractKey(const Slice &key, const Slice &val) const;

            /**
             * Extract the RecordId, which is either the whole slice (as a RecordStore) or the last
             * few bytes at the end (as a SortedDataInterface).
             */
            RecordId extractRecordId(const Slice &key) const;
        };

        virtual ~KVDictionary() { }

        /**
         * Get the associated value for `key' from the dictionary, storing
         * an owned slice into `value'
         *
         * Passing skipPessimisticLocking will avoid doing a serializable read even if opCtx seems
         * to be about to do a write.  This is only used by the KVCatalog to do non-serializable
         * reads when we intend to write to the collection, not the KVCatalog.  It is only
         * implemented in TokuFT at the moment.
         *
         * Return:
         *   Status::OK() success, value contains and owned slice.
         *   Status::code() == ErrorCodes::NoSuchKey when no key was found, value is not populated.
         */
        virtual Status get(OperationContext *opCtx, const Slice &key, Slice &value, bool skipPessimisticLocking=false) const = 0;

        /**
         * Insert `key' into the dictionary and associate it with `value',
         * overwriting any existing value.
         *
         * Return: Status::OK() success.
         */
        virtual Status insert(OperationContext *opCtx, const Slice &key, const Slice &value, bool skipPessimisticLocking) = 0;

        /**
         * Remove `key' and its associated value from the dictionary, if
         * any such key exists.
         *
         * Return: Status::OK() success.
         */
        virtual Status remove(OperationContext *opCtx, const Slice &key) = 0;

        /**
         * Returns true if the underlying implementation supports a fast update mechanism.  If so,
         * it should implement both overloads of update() below.
         */
        virtual bool updateSupported() const { return false; }

        /**
         * Update the value for `key' whose old value is `oldValue' and
         * whose new image should be the result of applying `message'.
         *
         * Only needs to be implemented if updateSupported().
         * 
         * Requires: `oldValue' is in fact the value
         *           `get(opCtx, key, ...)' would return
         * Note: violation of the requirement is undefined behavior, but
         *       usually leads to corrupt data / lost updates.
         * Return: Status:OK() success.
         */
        virtual Status update(OperationContext *opCtx, const Slice &key, const Slice &oldValue,
                              const KVUpdateMessage &message) {
            invariant(false);
            return Status::OK();
        }

        /**
         * Update the value for `key' whose new image should be the result of applying `message' to
         * whatever value is present.
         *
         * Note: Should have behavior equivalent to calling `get(opCtx, key, ...)' first, then
         *       calling the other `update' overload with the result (or `Slice()' if missing).
         * Return: Status:OK() success.
         */
        virtual Status update(OperationContext *opCtx, const Slice &key, const KVUpdateMessage &message) {
            invariant(false);
            return Status::OK();
        }

        /**
         * Called after a capped collection deletes a contiguous range of keys at the beginning of
         * the dictionary.  Gives the implementation a chance to do something to optimize the
         * dictionary.
         *
         * Note that this is called while holding the cappedDeleteMutex which will block threads if
         * the deleter gets too far behind as backpressure.
         */
        virtual void justDeletedCappedRange(OperationContext *opCtx, const Slice &left, const Slice &right,
                                            int64_t sizeSaved, int64_t docsRemoved) {}

        /**
         * Name of the dictionary.
         */
        virtual const char *name() const = 0;

        /**
         * Storage engines may override this and change supportsDupKeyCheck to return true if they
         * want to provide their own mechanism.
         *
         * The implementation must do a query for anything in the range [lookupLeft, lookupRight].
         *
         * If nothing is found, it can return Status::OK().
         * If something is found, compare its RecordId with id:
         *  - If they're identical, then also return Status::OK().
         *  - Otherwise, return Status(ErrorCodes::DuplicateKey, ...).
         */
        virtual Status dupKeyCheck(OperationContext *opCtx, const Slice &lookupLeft, const Slice &lookupRight, const RecordId &id) {
            invariant(false);
            return Status::OK();
        }
        virtual bool supportsDupKeyCheck() const {
            return false;
        }

        /**
         * Basic dictionary stats.
         */
        class Stats {
        public:
            Stats() : dataSize(0), storageSize(0), numKeys(0) { }
            // Size of current 'user data' in the dictionary (sum of key/value lengths)
            int64_t dataSize;

            // Space used on the storage device
            int64_t storageSize;

            // Total number of keys.
            int64_t numKeys;
        };

        /**
         * Get stats for the dictionary.
         *
         * Note: stats may be exact or estimated. Caller should not depend
         *       on exactness.
         * Return: initialized Stats object
         */
        virtual Stats getStats() const = 0;

        /**
         * Append specific stats about this dictionary to the given bson
         * builder.
         *
         * Return: Status::OK(), success
         */
        virtual bool appendCustomStats(OperationContext *opCtx, BSONObjBuilder* result, double scale) const = 0;

        virtual bool compactSupported() const { return false; }

        virtual bool compactsInPlace() const { invariant(false); }

        /**
         * Run compaction if the unerlying data structure supports it.
         *
         * Return: Status::OK(), success
         */
        virtual Status compact(OperationContext *opCtx) {
            invariant(false);
            return Status::OK();
        }

        /**
         * Sorted cursor interface over a KVDictionary.
         */
        class Cursor {
        public:
            virtual ~Cursor() { }

            /**
             * Checks if the cursor is safe to use.
             *
             * Return: true, the cursor is valid
             *         false, the cursor is dead and cannot be used any longer
             */
            virtual bool ok() const = 0;

            /**
             * Seek the cursor to a given key. If the key does not exist:
             * - The cursor is positioned over the first key > the given
             *   key, if getCursor() below was called with direction == 1
             * - Or the first key < the given key if direction was == -1
             *
             * TODO: Is ok() required here? I _think_ not.
             */
            virtual void seek(OperationContext *opCtx, const Slice &key) = 0;

            /**
             * Advance the cursor to the next key/value pair.
             *
             * Requires: ok() is true
             */
            virtual void advance(OperationContext *opCtx) = 0;

            /**
             * Get the current key from the cursor.
             *
             * Return: owned Slice representing the key data
             * Requires: ok() is true
             */
            virtual Slice currKey() const = 0;

            /**
             * Get the current value from the cursor.
             *
             * Return: owned Slice representing the value data
             * Requires: ok() is true
             */
            virtual Slice currVal() const = 0;
        };

        /**
         * Get a cursor over this dictionary that will iterate forward if
         * direction > 1 and backward if direction < 1. Direction also
         * affects how cursor seek lands on a key when an inexact match is
         * found. See Cursor::seek().
         *
         * Return: Cursor interface implementation (ownership passes to caller)
         */
        virtual Cursor *getCursor(OperationContext *opCtx, const Slice &key, const int direction = 1) const = 0;

        virtual Cursor *getRangedCursor(OperationContext *opCtx, const Slice &key, const int direction = 1) const = 0;

        virtual Cursor *getRangedCursor(OperationContext *opCtx, const int direction = 1) const = 0;
    };

} // namespace mongo
