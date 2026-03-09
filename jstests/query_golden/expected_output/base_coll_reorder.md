## 1. 3-Node graph, base node fully connected
### No join opt
### Random reordering with seed 0
```
HASH_JOIN_EMBEDDING [a = a]
leftEmbeddingField: "none"
rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [b = b]
  leftEmbeddingField: "y"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_b]
  direction: "forward"
```
### Random reordering with seed 1
```
HASH_JOIN_EMBEDDING [b = b]
leftEmbeddingField: "none"
rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "x"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_a]
  direction: "forward"
```
### Random reordering with seed 2
```
HASH_JOIN_EMBEDDING [b = b]
leftEmbeddingField: "none"
rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  direction: "forward"
```
### Random reordering with seed 7
```
HASH_JOIN_EMBEDDING [a = a]
leftEmbeddingField: "none"
rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [b = b]
  leftEmbeddingField: "none"
  rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  direction: "forward"
```

## 2. 3-Node graph, base node connected to one node
### No join opt
### Random reordering with seed 0
```
HASH_JOIN_EMBEDDING [x.a = a]
leftEmbeddingField: "none"
rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [b = b]
  leftEmbeddingField: "y"
  rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_b]
  direction: "forward"
```
### Random reordering with seed 1
```
HASH_JOIN_EMBEDDING [x.b = b]
leftEmbeddingField: "none"
rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "x"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_a]
  direction: "forward"
```
### Random reordering with seed 2
```
HASH_JOIN_EMBEDDING [x.b = b]
leftEmbeddingField: "none"
rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  direction: "forward"
```
### Random reordering with seed 3
```
HASH_JOIN_EMBEDDING [x.a = a]
leftEmbeddingField: "none"
rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [b = b]
  leftEmbeddingField: "x"
  rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_a]
  direction: "forward"
```

## 3. 3-Node graph + potentially inferred edge
### No join opt
### Random reordering with seed 0
```
HASH_JOIN_EMBEDDING [base = base,y.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "y"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_b]
  direction: "forward"
```
### Random reordering with seed 1
```
HASH_JOIN_EMBEDDING [base = base,x.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "x"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_a]
  direction: "forward"
```
### Random reordering with seed 2
```
HASH_JOIN_EMBEDDING [base = base,x.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  direction: "forward"
```
### Random reordering with seed 3
```
HASH_JOIN_EMBEDDING [x.base = base,y.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "x"
  rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_a]
  direction: "forward"
```
### Random reordering with seed 5
```
HASH_JOIN_EMBEDDING [x.base = base,y.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "y"
  rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_b]
  direction: "forward"
```
### Random reordering with seed 7
```
HASH_JOIN_EMBEDDING [base = base,y.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  direction: "forward"
```

## 4. 4-Node graph + potentially inferred edges & filters
### No join opt
### Random reordering with seed 0
```
HASH_JOIN_EMBEDDING [y.base = base,base = base,x.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "z"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "base" : { "$gt" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base,y.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  filter: { "b" : { "$eq" : 3 } }
  direction: "forward"
```
### Random reordering with seed 1
```
HASH_JOIN_EMBEDDING [y.base = base,base = base,x.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "z"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "base" : { "$gt" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base,x.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "x"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_a]
  direction: "forward"
```
### Random reordering with seed 2
```
HASH_JOIN_EMBEDDING [base = base,y.base = base,z.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [y.base = base,base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "z"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "base" : { "$gt" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  filter: { "b" : { "$eq" : 3 } }
  direction: "forward"
```
### Random reordering with seed 3
```
HASH_JOIN_EMBEDDING [base = base,y.base = base,z.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [y.base = base,base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "z"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "base" : { "$gt" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "y"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_b]
  direction: "forward"
```
### Random reordering with seed 4
```
HASH_JOIN_EMBEDDING [y.base = base,base = base,x.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "z"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "base" : { "$gt" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [x.base = base,y.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "y"
  rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_b]
  direction: "forward"
```
### Random reordering with seed 5
```
HASH_JOIN_EMBEDDING [x.base = base,y.base = base,z.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [z.base = base,x.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "z"
  rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  filter: { "base" : { "$gt" : 3 } }
  direction: "forward"
```
### Random reordering with seed 6
```
HASH_JOIN_EMBEDDING [x.base = base,y.base = base,z.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [y.base = base,x.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "z"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "base" : { "$gt" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "y"
  rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_b]
  direction: "forward"
```
### Random reordering with seed 7
```
HASH_JOIN_EMBEDDING [base = base,y.base = base,z.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [y.base = base,z.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "z"
  rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  filter: { "base" : { "$gt" : 3 } }
  direction: "forward"
```
### Random reordering with seed 9
```
HASH_JOIN_EMBEDDING [x.base = base,y.base = base,z.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [y.base = base,z.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "x"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "y"
  rightEmbeddingField: "z"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "base" : { "$gt" : 3 } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_b]
  direction: "forward"
```
### Random reordering with seed 10
```
HASH_JOIN_EMBEDDING [x.base = base,y.base = base,z.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [y.base = base,x.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "z"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "base" : { "$gt" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "x"
  rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_a]
  direction: "forward"
```
### Random reordering with seed 11
```
HASH_JOIN_EMBEDDING [y.base = base,base = base,x.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "z"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "base" : { "$gt" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [x.base = base,y.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "x"
  rightEmbeddingField: "y"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_a]
  direction: "forward"
```

## 5. 5-Node graph + filters
### No join opt
### Random reordering with seed 0
```
HASH_JOIN_EMBEDDING [b = b]
leftEmbeddingField: "none"
rightEmbeddingField: "bbb"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "base" : { "$gt" : 20 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [aaa.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "ccc"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$lt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "aaa"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  filter: { "base" : { "$in" : [ 22, 33 ] } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "ddd"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_b]
  filter: { "b" : { "$gt" : 0 } }
  direction: "forward"
```
### Random reordering with seed 1
```
HASH_JOIN_EMBEDDING [base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "ddd"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "b" : { "$gt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [b = b]
  leftEmbeddingField: "none"
  rightEmbeddingField: "bbb"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "base" : { "$gt" : 20 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [aaa.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "ccc"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$lt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "aaa"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  filter: { "base" : { "$in" : [ 22, 33 ] } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  filter: { "b" : { "$eq" : 3 } }
  direction: "forward"
```
### Random reordering with seed 2
```
HASH_JOIN_EMBEDDING [b = b]
leftEmbeddingField: "none"
rightEmbeddingField: "bbb"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "base" : { "$gt" : 20 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "ddd"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "b" : { "$gt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [aaa.a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "ccc"
  rightEmbeddingField: "aaa"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  filter: { "base" : { "$in" : [ 22, 33 ] } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  filter: { "b" : { "$lt" : 0 } }
  direction: "forward"
```
### Random reordering with seed 3
```
HASH_JOIN_EMBEDDING [b = b]
leftEmbeddingField: "none"
rightEmbeddingField: "bbb"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "base" : { "$gt" : 20 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "ddd"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "b" : { "$gt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [aaa.a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "aaa"
  rightEmbeddingField: "ccc"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$lt" : 0 } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_a]
  filter: { "base" : { "$in" : [ 22, 33 ] } }
  direction: "forward"
```
### Random reordering with seed 4
```
HASH_JOIN_EMBEDDING [base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "ddd"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "b" : { "$gt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [aaa.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "ccc"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$lt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "aaa"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  filter: { "base" : { "$in" : [ 22, 33 ] } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [b = b]
  leftEmbeddingField: "none"
  rightEmbeddingField: "bbb"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "base" : { "$gt" : 20 } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  filter: { "b" : { "$eq" : 3 } }
  direction: "forward"
```
### Random reordering with seed 7
```
HASH_JOIN_EMBEDDING [b = b]
leftEmbeddingField: "none"
rightEmbeddingField: "bbb"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "base" : { "$gt" : 20 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [aaa.base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "ccc"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$lt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "aaa"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  filter: { "base" : { "$in" : [ 22, 33 ] } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "ddd"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "b" : { "$gt" : 0 } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  filter: { "b" : { "$eq" : 3 } }
  direction: "forward"
```
### Random reordering with seed 8
```
HASH_JOIN_EMBEDDING [base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "ddd"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "b" : { "$gt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [b = b]
  leftEmbeddingField: "none"
  rightEmbeddingField: "bbb"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "base" : { "$gt" : 20 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [aaa.a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "ccc"
  rightEmbeddingField: "aaa"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  filter: { "base" : { "$in" : [ 22, 33 ] } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  filter: { "b" : { "$lt" : 0 } }
  direction: "forward"
```
### Random reordering with seed 9
```
HASH_JOIN_EMBEDDING [aaa.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "ccc"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$lt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "aaa"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  filter: { "base" : { "$in" : [ 22, 33 ] } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [b = b]
  leftEmbeddingField: "none"
  rightEmbeddingField: "bbb"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "base" : { "$gt" : 20 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "ddd"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "b" : { "$gt" : 0 } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_base]
  filter: { "b" : { "$eq" : 3 } }
  direction: "forward"
```
### Random reordering with seed 10
```
HASH_JOIN_EMBEDDING [aaa.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "ccc"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$lt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "aaa"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_a]
  |  filter: { "base" : { "$in" : [ 22, 33 ] } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "ddd"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "b" : { "$gt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [b = b]
  leftEmbeddingField: "bbb"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_b]
  filter: { "base" : { "$gt" : 20 } }
  direction: "forward"
```
### Random reordering with seed 11
```
HASH_JOIN_EMBEDDING [aaa.base = base]
leftEmbeddingField: "none"
rightEmbeddingField: "ccc"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$lt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [base = base]
  leftEmbeddingField: "none"
  rightEmbeddingField: "ddd"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "b" : { "$gt" : 0 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [b = b]
  leftEmbeddingField: "none"
  rightEmbeddingField: "bbb"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_b]
  |  filter: { "base" : { "$gt" : 20 } }
  |  direction: "forward"
  |
  HASH_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "aaa"
  rightEmbeddingField: "none"
  |  |
  |  COLLSCAN [test.base_coll_reorder_md_base]
  |  filter: { "b" : { "$eq" : 3 } }
  |  direction: "forward"
  |
  COLLSCAN [test.base_coll_reorder_md_a]
  filter: { "base" : { "$in" : [ 22, 33 ] } }
  direction: "forward"
```

