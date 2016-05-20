# Partitioned Collections Commands

## command addPartition

```javascript
{
  addPartition: '<collection>',
  newMax:       <document>
}
```

Argumants:

Field|Type|Description
-----|----|-----------
addPartition|string|The collection to which to add a partition.
newMax|document (optional)|Identifies what the maximum key of the current last partition should become before adding a new partition. This must be greater than any existing key in the collection. If newMax is not passed in, then the maximum key of the current last partition will be set to the key of the last element that currently exists in it.

Add a partition to a [Partitioned Collections](README.md). This command is used for [Adding a Partition](concepts.md#adding-a-partition).

In the **mongo** shell, there is a helper function `db.collection.addPartition([newMax])` that wraps this command.

Example:

```javascript
> db.runCommand({getPartitionInfo: 'bar'})
{
	"numPartitions" : NumberLong(1),
	"partitions" : [
		{
			"_id" : NumberLong(0),
			"max" : {
				"_id" : { "$maxKey" : 1 }
			},
			"createTime" : ISODate("2016-03-21T11:13:22.329Z")
		}
	],
	"ok" : 1
}
> db.bar.insert({_id:10})
WriteResult({ "nInserted" : 1 })
> db.runCommand({addPartition: 'bar'})
{ "ok" : 1 }
> db.runCommand({getPartitionInfo: 'bar'})
{
	"numPartitions" : NumberLong(2),
	"partitions" : [
		{
			"_id" : NumberLong(0),
			"max" : {
				"_id" : 10
			},
			"createTime" : ISODate("2016-03-21T11:13:22.329Z")
		},
		{
			"_id" : NumberLong(1),
			"max" : {
				"_id" : { "$maxKey" : 1 }
			},
			"createTime" : ISODate("2016-03-21T11:14:26.978Z")
		}
	],
	"ok" : 1
}
> db.runCommand({addPartition: 'bar', newMax: {_id : 20}})
{ "ok" : 1 }
> db.runCommand({getPartitionInfo: 'bar'})
{
	"numPartitions" : NumberLong(3),
	"partitions" : [
		{
			"_id" : NumberLong(0),
			"max" : {
				"_id" : 10
			},
			"createTime" : ISODate("2016-03-21T11:13:22.329Z")
		},
		{
			"_id" : NumberLong(1),
			"max" : {
				"_id" : 20
			},
			"createTime" : ISODate("2016-03-21T11:14:26.978Z")
		},
		{
			"_id" : NumberLong(2),
			"max" : {
				"_id" : { "$maxKey" : 1 }
			},
			"createTime" : ISODate("2016-03-21T11:15:07.011Z")
		}
	],
	"ok" : 1
}
```

## command dropPartition

```javascript
{
  dropPartition: '<collection>',
  id:            <number>
}
```
or
```javascript
{
  dropPartition: '<collection>',
  max:            <document>
}
```

Arguments:

Field|Type|Description
-----|----|-----------
dropPartition|string|The collection to get partition info from.
id|number (optional)|The id of the partition to be dropped. Partition ids may be identified by running [getPartitionInfo](#command-getpartitioninfo). Note that while optional, either id or max must be present, but not both.
max|document (optional)|Specifies the maximum partition key for dropping such that all partitions with documents less than or equal to max are dropped. Note that while optional, either id or max must be present, but not both.

Drop the partition given a partition id. This command is used for [Dropping a Partition](concepts.md#dropping-a-partition) of a [Partitioned Collections](README.md).

In the **mongo** shell, there is a helper function `db.collection.dropPartition([id])` that wraps this command for the case where a partition id is specified. Similarly, there is also a helper function, `db.collection.dropPartitionsLEQ([max])` that wraps this command for the case where a max partition key is specified.

Example:

```javascript
> db.runCommand({getPartitionInfo: 'bar'})
{
	"numPartitions" : NumberLong(3),
	"partitions" : [
		{
			"_id" : NumberLong(0),
			"max" : {
				"_id" : 10
			},
			"createTime" : ISODate("2016-03-21T11:13:22.329Z")
		},
		{
			"_id" : NumberLong(1),
			"max" : {
				"_id" : 20
			},
			"createTime" : ISODate("2016-03-21T11:14:26.978Z")
		},
		{
			"_id" : NumberLong(2),
			"max" : {
				"_id" : { "$maxKey" : 1 }
			},
			"createTime" : ISODate("2016-03-21T11:15:07.011Z")
		}
	],
	"ok" : 1
}
> db.runCommand({dropPartition: 'bar', id: 0})
{ "ok" : 1 }
> db.runCommand({getPartitionInfo: 'bar'})
{
	"numPartitions" : NumberLong(2),
	"partitions" : [
		{
			"_id" : NumberLong(1),
			"max" : {
				"_id" : 20
			},
			"createTime" : ISODate("2016-03-21T11:14:26.978Z")
		},
		{
			"_id" : NumberLong(2),
			"max" : {
				"_id" : { "$maxKey" : 1 }
			},
			"createTime" : ISODate("2016-03-21T11:15:07.011Z")
		}
	],
	"ok" : 1
}
```

## command getPartitionInfo

```javascript
{
  getPartitionInfo: '<collection>'
}
```

Arguments:

Field|Type|Description
-----|----|-----------
getPartitionInfo|string|The collection to get partition info from.

Retrieve the list of partitions for a partitioned collection. This command provides [Information About Partitioned Collections](concepts.md#information-about-partitioned-collections).

In the **mongo** shell, there is a helper function `db.collection.getPartitionInfo()` that wraps this command.

Example:

```javascript
> db.runCommand({getPartitionInfo: 'bar'})
{
	"numPartitions" : NumberLong(2),
	"partitions" : [
		{
			"_id" : NumberLong(1),
			"max" : {
				"_id" : 20
			},
			"createTime" : ISODate("2016-03-21T11:14:26.978Z")
		},
		{
			"_id" : NumberLong(2),
			"max" : {
				"_id" : { "$maxKey" : 1 }
			},
			"createTime" : ISODate("2016-03-21T11:15:07.011Z")
		}
	],
	"ok" : 1
}
```
