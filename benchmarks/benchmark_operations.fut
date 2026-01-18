import "../lib/github.com/diku-dk/vtree/vtree"

module T = vtree

def random_parents (n: i64) (seed: i64) : [n]i64 =
  -- Simple hash function (based on MurmurHash3)
  let hash (x: u64): u64 =
    let x = x ^ (x >> 30)
    let x = x * 0xbf58476d1ce4e5b9u64
    let x = x ^ (x >> 27)
    let x = x * 0x94d049bb133111ebu64
    in x ^ (x >> 31)
  in tabulate n (\i ->
                   if i == 0
                   then 0i64
                   else i64.u64 (hash (u64.i64 (seed + i))) % i)

-- Random tree generation function
def gen_random_tree (n: i64) (seed: i64) : ([]i64, []i64, []i64) =
  let parents = random_parents n seed
  let tree = T.getData (T.from_parent parents (iota n))
  in (tree.lp, tree.rp, tree.data)

-- Benchmark entries

-- ==
-- entry: bench_delete
-- script input { mk_delete_test 10000 }
-- script input { mk_delete_test 100000 }
-- script input { mk_delete_test 1000000 }
-- script input { mk_delete_test 10000000 }

entry bench_delete [n] (tree: T.t i64 [n]) (keep: [n]bool) =
  T.deleteVertices tree keep

entry mk_delete_test (numNodes: i64) : (T.t i64 [numNodes], [numNodes]bool) =
  let (lp, rp, data) = gen_random_tree numNodes 42
  let keep = tabulate numNodes (\i -> i % 2 == 0)
  in (T.lprp {lp, rp, data}, keep)

-- ==
-- entry: bench_split
-- script input { mk_split_test 10000 }
-- script input { mk_split_test 100000 }
-- script input { mk_split_test 1000000 }
-- script input { mk_split_test 10000000 }
entry bench_split [n] (tree: T.t i64 [n]) (splits: [n]bool) =
  T.split tree splits

entry mk_split_test (numNodes: i64) : (T.t i64 [numNodes], [numNodes]bool) =
  let (lp, rp, data) = gen_random_tree numNodes 42
  let split_node = 1 + (numNodes / 2)
  -- split at middle node
  let splits = tabulate numNodes (\i -> i == split_node)
  in (T.lprp {lp, rp, data}, splits)

-- ==
-- entry: bench_merge
-- script input { mk_merge_test 10000 1 1 }
-- script input { mk_merge_test 10000 1 10 }
-- script input { mk_merge_test 10000 1 100 }
-- script input { mk_merge_test 10000 1 1000 }
-- script input { mk_merge_test 100 10 100 }
-- script input { mk_merge_test 1000 10 100 }
-- script input { mk_merge_test 10000 10 100 }
-- script input { mk_merge_test 100000 10 100 }
entry bench_merge [n] [m] [k]
                  (lp: [n]i64)
                  (rp: [n]i64)
                  (data: [n]i64)
                  (lpsub: [m]i64)
                  (rpsub: [m]i64)
                  (datasub: [m]i64)
                  (shp: [k]i64)
                  (parent_pointers: [n]i64) : T.t i64 [] =
  let parent = T.lprp {lp, rp, data}
  let children = T.lprp {lp = lpsub, rp = rpsub, data = datasub}
  let merged_tree = T.merge {subtrees = children, subtrees_shape = shp} parent parent_pointers
  in merged_tree

entry mk_subtrees (num_subtrees: i64) (subtree_size: i64) : ([num_subtrees * subtree_size]i64, [num_subtrees * subtree_size]i64, [num_subtrees * subtree_size]i64) =
  let (lp, rp, data) = map (\_ -> gen_random_tree subtree_size 42) (replicate num_subtrees 0) |> unzip3
  in (flatten lp, flatten rp, flatten data)

entry mk_parent_pointers (num_parents: i64) (num_subtrees: i64) (seed: i64) : [num_parents]i64 =
  let lcg s = (s * 1103515245 + 12345) % (1 << 31)
  let (ptrs, _) =
    loop (ps, s) = (replicate num_parents 0i64, seed)
    for i in 1..<num_parents do
      (ps with [i] = s % num_subtrees, lcg s)
  in ptrs

entry mk_merge_test (num_parents: i64) (num_subtrees: i64) (subtree_size: i64) : ( [num_parents]i64
                                                                                 , [num_parents]i64
                                                                                 , [num_parents]i64
                                                                                 , [num_subtrees * subtree_size]i64
                                                                                 , [num_subtrees * subtree_size]i64
                                                                                 , [num_subtrees * subtree_size]i64
                                                                                 , [num_subtrees]i64
                                                                                 , [num_parents]i64
                                                                                 ) =
  let (lp1, rp1, data1) = gen_random_tree num_parents 42
  let (lp2, rp2, data2) = mk_subtrees num_subtrees subtree_size
  let ptrs = mk_parent_pointers num_parents num_subtrees 42
  let shp = replicate num_subtrees subtree_size
  in (lp1, rp1, data1, lp2, rp2, data2, shp, ptrs)

-- ==
-- entry: bench_from_parent
-- script input { mk_from_parent_test 10000 }
-- script input { mk_from_parent_test 100000 }
-- script input { mk_from_parent_test 1000000 }
-- script input { mk_from_parent_test 10000000 }

entry bench_from_parent [n] (parent: [n]i64) (data: [n]i64) : T.t i64 [n] =
  T.from_parent parent data

entry mk_from_parent_test (numNodes: i64) : ([numNodes]i64, [numNodes]i64) =
  let parent = random_parents numNodes 42
  let data = iota numNodes
  in (parent, data)
