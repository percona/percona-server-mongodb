# NGRAM

###1) TOKEN DELIMITER
Unlike MongoDB native delimiter based tokenizer, NGram use only below 5 characters as tokenizer delimiter.
```
0x09 : HORIZONTAL-TAB
0x0a : LINE-FEED (\n)
0x0b : VERTICAL-TAB
0x0d : CARRIAGE-RETURN (\r)
0x20 : SPACE
```

In MongoDB native full text search, we should use `phrase search` to search the string which contains "-" character.
```
db.collection.find({ $text: { $search: "\"2016-12\"" } })
```

But using NGram tokenizer, we don't need to use `phrase search` because "-" is not a delimiter in NGram tokenizer.
```
db.collection.find({ $text: { $search: "2016-12" } })

```

Exceptionally if you use "-" character at first of search string, then NGram search understand that "-" character as negate sign (like MongoDB native full text search). 

For example, NGram full text search does not regarding "-"(in the middle of string) as either delimiter and negate-sign.
```
db.collection.find({ $text: { $search: "6-2" } })
```
But below case, NGram full text search will do negate search for string of "6-2".
```
db.collection.find({ $text: { $search: "-6-2" } })
```

###2) Create NGram index
If you specify `{default_language: "ngram"}` option on `createIndex` command, MongoDB will create NGram full text search index. Without this option, MongoDB will create native `delimiter based full text search` index.
```
db.collection.createIndex({name:"text"}, {default_language: "ngram"})
```

###3) Search with NGram index

####3-1) Basic search test
```
-- // Insert test document
db.coll.remove({})
db.coll.insert({ _id: 11, name: "MongoDB는 좋은 비관계형 데이터베이스 서버입니다" })

-- // Do test query
db.coll.find({ $text: { $search: "go" } }).count()     -- // ==> 1
db.coll.find({ $text: { $search: "od" } }).count()     -- // ==> 1
db.coll.find({ $text: { $search: "좋은" } }).count()    -- // ==> 1
db.coll.find({ $text: { $search: "계형" } }).count()    -- // ==> 1
db.coll.find({ $text: { $search: "데이" } }).count()    -- // ==> 1
db.coll.find({ $text: { $search: "이터" } }).count()    -- // ==> 1
db.coll.find({ $text: { $search: "터베" } }).count()    -- // ==> 1
db.coll.find({ $text: { $search: "베이" } }).count()    -- // ==> 1
db.coll.find({ $text: { $search: "이스" } }).count()    -- // ==> 1
db.coll.find({ $text: { $search: "서버" } }).count()    -- // ==> 1
db.coll.find({ $text: { $search: "버입" } }).count()    -- // ==> 1
db.coll.find({ $text: { $search: "입니" } }).count()    -- // ==> 1
db.coll.find({ $text: { $search: "니다" } }).count()    -- // ==> 1

db.coll.find({ $text: { $search: "나다 } }).count()    -- // ==> 0
```

####3-2) Special character search test
```
-- // Insert test document
db.coll.remove({})
db.coll.insert({ _id: 11, name: "MongoDB 3.6은 2016/12일 릴리즈되었습니다." })
db.coll.insert({ _id: 12, name: "MongoDB 3.6은 2016-12일 릴리저되었습니다." })
db.coll.insert({ _id: 13, name: "MongoDB 3.6은 2016+12일 릴리즈되었습니다." })
db.coll.insert({ _id: 14, name: "MongoDB 3.6은 2016*12일 릴리저되었습니다." })

-- // Do test query
db.coll.find({ $text: { $search: "2016" } }).count()        -- // ==> 4

db.coll.find({ $text: { $search: "2016/12" } }).count()     -- // ==> 1
db.coll.find({ $text: { $search: "2016-12" } }).count()     -- // ==> 1
db.coll.find({ $text: { $search: "2016+12" } }).count()     -- // ==> 1
db.coll.find({ $text: { $search: "2016*12" } }).count()     -- // ==> 1

db.coll.find({ $text: { $search: "\"2016/12\"" } }).count() -- // ==> 1
db.coll.find({ $text: { $search: "\"2016-12\"" } }).count() -- // ==> 1
db.coll.find({ $text: { $search: "\"2016+12\"" } }).count() -- // ==> 1
db.coll.find({ $text: { $search: "\"2016*12\"" } }).count() -- // ==> 1
```

####3-3) String contains special char(Single character before & after special char) search test
```
-- // Insert test document
db.coll.remove({})
db.coll.insert({ _id: 11, name: "MongoDB 3.6은 6/2일 릴리즈되었습니다." })
db.coll.insert({ _id: 12, name: "MongoDB 3.6은 6-2일 릴리저되었습니다." })
db.coll.insert({ _id: 13, name: "MongoDB 3.6은 6+2일 릴리즈되었습니다." })
db.coll.insert({ _id: 14, name: "MongoDB 3.6은 6*2일 릴리저되었습니다." })

-- // Do test query
db.coll.find({ $text: { $search: "6/2" } }).count()     // ==> 1
db.coll.find({ $text: { $search: "6-2" } }).count()     // ==> 1

db.coll.find({ $text: { $search: "\"6/2\"" } }).count() // ==> 1
db.coll.find({ $text: { $search: "\"6-2\"" } }).count() // ==> 1
db.coll.find({ $text: { $search: "\"6+2\"" } }).count() // ==> 1
db.coll.find({ $text: { $search: "\"6*2\"" } }).count() // ==> 1
```
 No newline at end of file
