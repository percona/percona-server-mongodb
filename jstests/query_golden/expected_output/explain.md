## 1. Test getting rejected plan out of explain
### Bottom-up, zig-zag, 4-node join
usedJoinOptimization: true

### Winning plan
```
NESTED_LOOP_JOIN_EMBEDDING [a2.a = a,a = a,a1.a = a]
leftEmbeddingField: "none"
rightEmbeddingField: "a3"
  |  |
  |  COLLSCAN [test.explain_md]
  |  direction: "forward"
  |
  NESTED_LOOP_JOIN_EMBEDDING [a1.a = a,a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "a2"
  |  |
  |  COLLSCAN [test.explain_md]
  |  direction: "forward"
  |
  NESTED_LOOP_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "a1"
  |  |
  |  COLLSCAN [test.explain_md]
  |  direction: "forward"
  |
  COLLSCAN [test.explain_md]
  direction: "forward"
```
### Rejected plans
```
HASH_JOIN_EMBEDDING [a2.a = a,a = a,a1.a = a]
leftEmbeddingField: "none"
rightEmbeddingField: "a3"
  |  |
  |  COLLSCAN [test.explain_md]
  |  direction: "forward"
  |
  NESTED_LOOP_JOIN_EMBEDDING [a1.a = a,a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "a2"
  |  |
  |  COLLSCAN [test.explain_md]
  |  direction: "forward"
  |
  NESTED_LOOP_JOIN_EMBEDDING [a = a]
  leftEmbeddingField: "none"
  rightEmbeddingField: "a1"
  |  |
  |  COLLSCAN [test.explain_md]
  |  direction: "forward"
  |
  COLLSCAN [test.explain_md]
  direction: "forward"
```
