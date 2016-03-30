# Partitioned collections

Partitioned collections are collections that are divided into a number of sub-collections, or partitions, such that each partition is its own set of files on disk. Conceptually, a partitioned collection is similar to a [partitioned tables](http://dev.mysql.com/doc/refman/5.7/en/partitioning.html) in MySQL.

The primary advantage of partitioned collections is the ability to delete a partition efficiently and immediately reclaim its storage space in a manner similar to dropping a collection in Percona Server for MongoDB. All that’s required is removing some files.

In all other ways, a partitioned collection operates logically the same as a normal collection, including complex queries with sort and aggregation. The server does the required work to merge the results from all partitions, so the partitioning is invisible from the client’s perspective.

Use Cases Time-series data is the most obvious use case for partitioned collections. The typical pattern is to insert the newest data in the most recent partition, and periodically drop the oldest partition once it has passed some expiry time.

Partitioned collections make excellent replacements for capped collections and TTL indexes. Both of those strategies incur individual queries and deletes for each document that expires, while partitioned collections delete data in large batches. As such, they are much faster than capped collections or collections with TTL indexes. At the same time, they are more flexible and easier to manage and predict than either capped collections or TTL indexed collections.

For example, suppose you have some data being generated over time (financial data is a common such source), of which you would like to keep only the last year’s worth. With a capped collection, you need to analyze your insertion rate and guess the appropriate size for the collection, and this size is then hard to change later. With a partitioned collection, you just create a new partition each month and drop the oldest. In this way you have the most recent 12 or 13 months of data, but this can be adjusted in the application layer later.

If you have a use case for a TTL index on a collection, and all documents will have the same “time to live”, you should instead strongly consider making that collection partitioned. A TTL index incurs frequent queries on that index and deletes documents one at a time, whereas a partitioned collection is much faster and lighter weight.

Information on partitioning concepts and operation is in the [Concepts document](concepts.md).

Information on partition-related commands is in the [Partitioned Collections Commands document](commands.md).
