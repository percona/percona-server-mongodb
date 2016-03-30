# Concepts

Like a capped collection, a partitioned collection must be declared partitioned when the collection is first created, and it must be created explicitly.

Partitioned collections are always divided according to the `primaryKey`. Each partition holds documents less or equal than a certain `primaryKey` value, in this way each partition holds a distinct range of documents according to the `primaryKey`.

## Creating Partitioned Collections

There are two ways to create a partitioned collection:

- Use the `create` command, and add the option `partitioned`.
- Use the **mongo** shell provided with Percona Server for MongoDB, and add `partitioned` to the options document of `db.createCollection()`.

Since partitioned collections use the `primaryKey` as the partitioning key, most applications will want to pick a custom `primaryKey`, which should also be done at create time.

Example: Suppose we want to create a collection prices, that is partitioned by a time field.

In the **mongo** shell, we can run:

```javascript
> db.createCollection('prices', {primaryKey: {time: 1},
                                 partitioned: true})
```

Alternatively, from another client, we could run this command:

```javascript
{
    create:      "prices",
    primaryKey:  {time: 1},
    partitioned: true
}
```
After creation, a new partitioned collection has one partition that will be used for all data. To break up the partitioned collection, use the commands explained in [Adding a Partition](#adding-a-partition) and [Dropping a Partition](#dropping-a-partition).

## Information About Partitioned Collections

Percona Server for MongoDB provides information about partitioned collections via the shell function `db.collection.getPartitionInfo()`, which is a wrapper around the [getPartitionInfo](commands.md#command-getpartitioninfo) command.

This command returns the number of partitions for the collection (`numPartitions`) and an array of objects (`partitions`), one describing each partition. For each partition, the object includes:

- _id: An integer identifier for the partition, used by [dropPartition](commands.md#command-droppartition) to drop the partition.
- max: The maximum value (of the primaryKey this partition may hold. A partition includes all documents with primary key less than or equal to its max, and greater than the max for the previous partition.
- createTime: The time this partition was created.

Example: For a newly created partitioned collection, `foo`, that has only one partition and `{a:1}` as a primary key, [getPartitionInfo](commands.md#command-getpartitioninfo) shows the following:
```javascript
> db.foo.getPartitionInfo()
{
	"numPartitions" : NumberLong(1),
	"partitions" : [
		{
			"_id" : NumberLong(0),
			"max" : {
				"a" : { "$maxKey" : 1 }
			},
			"createTime" : ISODate("2016-03-16T18:15:33.739Z")
		}
	],
	"ok" : 1
}
```

Note there is one partition and the maximum value of that partition is a special value "$maxKey", which is the greatest possible key.

After adding two partitions to this collection, [getPartitionInfo](commands.md#command-getpartitioninfo) returns:
```javascript
> db.foo.getPartitionInfo()
{
	"numPartitions" : NumberLong(3),
	"partitions" : [
		{
			"_id" : NumberLong(0),
			"max" : {
				"a" : 1000
			},
			"createTime" : ISODate("2016-03-16T18:15:33.739Z")
		},
		{
			"_id" : NumberLong(1),
			"max" : {
				"a" : 2000
			},
			"createTime" : ISODate("2016-03-16T18:21:43.473Z")
		},
		{
			"_id" : NumberLong(2),
			"max" : {
				"a" : { "$maxKey" : 1 }
			},
			"createTime" : ISODate("2016-03-16T18:21:47.503Z")
		}
	],
	"ok" : 1
}
```

In this example, any document with *a <= 1000* will be found in the first partition (_id 0), a document with *a <= 2000* will be in the second, and all other documents will be in the third.

## Changes to db.collection.stats()

Additionally, for a partitioned collection, the output of `db.collection.stats()` and the `collStats` command adds some information about individual partitions.

The result has an additional array `partitions` that contains essentially the `collStats` results for each individual partition, and the top-level information is an aggregation of the info for all partitions.

Example:

```javascript
> db.foo.stats().partitions
[
	{
		"_id" : 0,
		"count" : 1,
		"size" : 33,
		"avgObjSize" : 33,
		"storageSize" : 32768,
		"capped" : false,
		"PerconaFT" : {
			"size" : {
				"uncompressed" : 35,
				"compressed" : 32768
			},
			"numElements" : 1,
			"createOptions" : {
				"pageSize" : 4194304,
				"readPageSize" : 65536,
				"compression" : "zlib",
				"fanout" : 16
			}
		}
	},
	{
		"_id" : 1,
		"count" : 0,
		"size" : 0,
		"storageSize" : 32768,
		"capped" : false,
		"PerconaFT" : {
			"size" : {
				"uncompressed" : 0,
				"compressed" : 32768
			},
			"numElements" : 0,
			"createOptions" : {
				"pageSize" : 4194304,
				"readPageSize" : 65536,
				"compression" : "zlib",
				"fanout" : 16
			}
		}
	}
]
```

## Adding a Partition

A new, empty partition may be added after the last partition (the one containing the largest documents according to `primaryKey`). Existing partitions cannot be modified to create another partition. That is, an existing partition, including the first, cannot be “split”.

Partitions are added with the `db.collection.addPartition()` shell wrapper, or the [addPartition](commands.md#command-addpartition) command.

When adding a partition, the previously last partition is “capped” by assigning a new max value that must be larger or equal than the key of any document already in the collection, and a new partition is created with a `max` value of that special `"maxKey"` value that is larger than any key.

> Warning
>
> When querying a partitioned collection, the server maintains separate cursors on all existing partitions that are relevant to the query. Since adding and dropping partitions changes which partitions may be relevant, the act of adding or dropping a partition invalidates any existing cursors on the collection.
>
> This will return an error to any client which has not retrieved all results, and clients should be prepared to retry their queries in this case.

The `max` value chosen to “cap” the previous partition can be specified as the `newMax` parameter to [addPartition](commands.md#command-addpartition), or if not provided, the server will automatically use the largest key of any document currently in in the collection for that `max` value.

> Note
>
> It is considered an error to add a partition without specifying the newMax parameter if the last partition is currently empty.

Example: Consider a collection `foo`, with two partitions, each containing one document:

```javascript
> db.foo.getPartitionInfo()
{
	"numPartitions" : NumberLong(2),
	"partitions" : [
		{
			"_id" : NumberLong(0),
			"max" : {
				"a" : 1000
			},
			"createTime" : ISODate("2016-03-18T18:26:09.717Z")
		},
		{
			"_id" : NumberLong(1),
			"max" : {
				"a" : { "$maxKey" : 1 }
			},
			"createTime" : ISODate("2016-03-18T18:27:07.759Z")
		}
	],
	"ok" : 1
}
> db.foo.find()
{ "_id" : ObjectId("56ec4861367cccb4abaa1999"), "a" : 500 }
{ "_id" : ObjectId("56ec4880367cccb4abaa199a"), "a" : 1500 }
```

Adding a partition with a default `max`:

If we run [addPartition](commands.md#command-addpartition) without providing `newMax`, the server will choose the largest key, `{a: 1500}` to cap the second partition:

```javascript
> db.foo.addPartition()
{ "ok" : 1 }
> db.foo.getPartitionInfo()
{
	"numPartitions" : NumberLong(3),
	"partitions" : [
		{
			"_id" : NumberLong(0),
			"max" : {
				"a" : 1000
			},
			"createTime" : ISODate("2016-03-18T18:26:09.717Z")
		},
		{
			"_id" : NumberLong(1),
			"max" : {
				"a" : 1500
			},
			"createTime" : ISODate("2016-03-18T18:27:07.759Z")
		},
		{
			"_id" : NumberLong(2),
			"max" : {
				"a" : { "$maxKey" : 1 }
			},
			"createTime" : ISODate("2016-03-18T18:33:08.412Z")
		}
	],
	"ok" : 1
}
```

Adding a partition with a custom `max`:

Instead, we can provide a different key to cap the second partition:

```javascript
> db.foo.addPartition({a:1700})
{ "ok" : 1 }
> db.foo.getPartitionInfo()
{
	"numPartitions" : NumberLong(3),
	"partitions" : [
		{
			"_id" : NumberLong(0),
			"max" : {
				"a" : 1000
			},
			"createTime" : ISODate("2016-03-18T18:26:09.717Z")
		},
		{
			"_id" : NumberLong(1),
			"max" : {
				"a" : 1700
			},
			"createTime" : ISODate("2016-03-18T18:33:08.412Z")
		},
		{
			"_id" : NumberLong(2),
			"max" : {
				"a" : { "$maxKey" : 1 }
			},
			"createTime" : ISODate("2016-03-18T18:35:04.971Z")
		}
	],
	"ok" : 1
}
```

> Note
>
> A custom value for `max` must be a valid `primaryKey` and:
>
> Be greater than the `max` of all existing partitions except the last one (which is the one getting the new `max`).
> Be greater than any `primaryKey` that exists in the collection.

## Dropping a Partition

Partitions may also be dropped. This deletes all documents in that partition’s range by unlinking the underlying data and index files.

> Note
>
> Any partition of a collection may be dropped. Most time-series applications using partitioned collections will drop the first partition, but this is not the only option.
>
> When dropping the last partition (holding the largest documents by primaryKey) of a collection, the previous partition’s max is changed to be the special “maxKey” element.

There are two methods for dropping partitions, using different invocations of the [dropPartition](commands.md#command-droppartition) command:

- Drop a single partition by its `_id` (see [Information About Partitioned Collections](#information-about-partitioned-collections)).
- Drop all partitions whose `max` value is less than or equal to some key.

> Warning
>
> If a collection only has one partition, it is considered an error to drop that partition. Instead, simply drop the collection with `db.collection.drop()`.

Example:

Consider a collection `foo`, with two partitions, each containing one document (note the partitions’ `_ids`):

```javascript
> db.foo.getPartitionInfo()
{
	"numPartitions" : NumberLong(2),
	"partitions" : [
		{
			"_id" : NumberLong(4),
			"max" : {
				"a" : 1000
			},
			"createTime" : ISODate("2016-03-18T18:26:09.717Z")
		},
		{
			"_id" : NumberLong(6),
			"max" : {
				"a" : { "$maxKey" : 1 }
			},
			"createTime" : ISODate("2016-03-18T18:27:07.759Z")
		}
	],
	"ok" : 1
}
> db.foo.find()
{ "_id" : ObjectId("56ec4861367cccb4abaa1999"), "a" : 500 }
{ "_id" : ObjectId("56ec4880367cccb4abaa199a"), "a" : 1500 }
```

Dropping a partition by `_id`:

To drop the first partition by `_id`, use the `mongo` shell:

```javascript
> db.foo.dropPartition(4)
{ "ok" : 1 }
> db.foo.getPartitionInfo().partitions
[
    {
        "_id" : NumberLong(6),
        "max" : {
            "a" : { "$maxKey" : 1 }
        },
        "createTime" : ISODate("2016-03-18T18:27:07.759Z")
    }
]
> db.foo.find()
{ "_id" : ObjectId("56ec4880367cccb4abaa199a"), "a" : 1500 }
```

This can be done in other clients by running the command `{dropPartition: "foo", id: 4}`.

Dropping a partition by key:

To drop the first partition using a key, use the `mongo` shell:

```javascript
> db.foo.dropPartitionsLEQ({a:1000})
{ "ok" : 1 }
> db.foo.getPartitionInfo().partitions
[
    {
        "_id" : NumberLong(6),
        "max" : {
            "a" : { "$maxKey" : 1 }
        },
        "createTime" : ISODate("2016-03-18T18:27:07.759Z")
    }
]
> db.foo.find()
{ "_id" : ObjectId("56ec4880367cccb4abaa199a"), "a" : 1500 }
```

This can be done in other clients by running the command `{dropPartition: "foo", max: {a: 1000, _id: MaxKey}}`.

## Secondary Indexes

Partitioned collections support secondary indexes. Each partition maintains its own set of secondary indexes.

Primary key of partitioned collection in Percona Server for MongoDB is just a special case of secondary index. If primary key is not specified on collection cretion then `{_id: 1}` is used as a primary key.

If the primaryKey can be used to exclude some partitions from consideration for a query, that will be done. A query that only needs to search one partition will be faster than one that searches all partitions.

## Differences comparing to TokuMX's implementation

Current implementation of partitioned collections has following differences comparing to TokuMX's implementation:
- In TokuMX the `primaryKey` is always a `clustering` index. In Percona Server for MongoDB `primaryKey` is a specially treated index.

## Improvements in Percona Server for MongoDB over TokuMX's implementation

- In TokuMX the `primaryKey` must end in `{_id: 1}`, the partition endpoints must as well. In Percona Server for MongoDB this requirement does not exist.
- InTokuMX queries using secondary indexes may return results in different order than expected ([see here](https://www.percona.com/doc/percona-tokumx/partitioned_collections.html#secondary-indexes)). In Percona Server for MongoDB results of secondary index scan are in expected order.
- Unique secondary indexes are supported on partitioned collections in Percona Server for MongoDB.

## Features of TokuMX's partitioned collection which are not implemented yet
- In TokuMX, the oplog.rs and oplog.refs collections, both of which are used for replication, are partitioned collections. In Percona Server for MongoDB they aren't yet.
- TokuMX has special support for sharding partitoned collections ([see here](https://www.percona.com/doc/percona-tokumx/partitioned_collections.html#sharding-of-partitioned-collections)). Need to clarify how sharding of partitioned collections works in Percona Server for MongoDB.
