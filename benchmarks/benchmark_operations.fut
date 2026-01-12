import "../lib/github.com/diku-dk/vtree/vtree"

module T = vtree
def random_parents (n: i64) (seed: i64) : []i64 =
  let lcg s = (s * 1103515245 + 12345) % (1 << 31)
  let (parents, _) = 
    loop (ps, s) = (replicate n 0i64, seed) for i in 1..<n do
      (ps with [i] = s % i, lcg s)
  in parents

-- Data generation entry
entry gen_random_tree (n: i64) (seed: i64): ([]i64, []i64, []i64) =
  let parents = random_parents n seed
  let tree = T.getData(T.from_parent parents (iota n))
  in (tree.lp, tree.rp, tree.data)



-- Benchmark entries 


-- ==
-- entry: bench_delete
-- input @ data/random_10k.in
-- input @ data/random_100k.in
-- input @ data/random_1m.in
-- input @ data/random_10m.in

entry bench_delete [n] (lp: [n]i64) (rp: [n]i64) (data: [n]i64) : i64 =
  let t = T.lprp {lp, rp, data}
  let keep = tabulate n (\i -> i % 2 == 0)
  let result = T.deleteVertices t keep
  in length (T.getData result).data

-- ==
-- entry: bench_split
-- input @ data/random_10k.in
-- input @ data/random_100k.in
-- input @ data/random_1m.in
-- input @ data/random_10m.in

entry bench_split [n] (lp: [n]i64) (rp: [n]i64) (data: [n]i64) : i64 =
  let t = T.lprp {lp, rp, data}
  let split_node = 1 + (n / 2)  -- split at middle node
  let splits = tabulate n (\i -> i == split_node)
  let (subtree_res, _) = T.split t splits
  in length subtree_res.subtrees_shape



-- ==
-- entry: bench_merge
-- script input { mk_merge_test 10000 1000 1000 }
-- script input { mk_merge_test 100000 1000 1000 }
-- script input { mk_merge_test 1000000 1000 1000 }

entry bench_merge [n] [m] [k] (lp: [n]i64) (rp: [n]i64) (data: [n]i64) 
  (lpsub: [m]i64) (rpsub: [m]i64) (datasub: [m]i64) (shp: [k]i64) (parent_pointers: [n]i64): i64 = 
  let parent = T.lprp {lp, rp, data}
  let children = T.lprp {lp = lpsub, rp = rpsub, data = datasub}
  let merged_tree = T.merge {subtrees = children, subtrees_shape = shp} parent parent_pointers
  in length (T.getData merged_tree).lp

entry mk_subtrees (num_subtrees: i64) (subtree_size: i64): 
  ([num_subtrees*subtree_size]i64, [num_subtrees*subtree_size]i64, [num_subtrees*subtree_size]i64) =  
  let (lp, rp, data) = map (\_ -> gen_random_tree subtree_size 42) (replicate num_subtrees 0) |> unzip3
  in (flatten lp, flatten rp, flatten data)

entry mk_parent_pointers (num_parents:i64) (num_subtrees: i64) (seed:i64): [num_parents]i64 =
  let lcg s = (s * 1103515245 + 12345) % (1 << 31)
  let (ptrs, _) = 
    loop (ps, s) = (replicate num_parents 0i64, seed) for i in 1..<num_parents do
      (ps with [i] = s % num_subtrees, lcg s)
  in ptrs

entry mk_merge_test (num_parents: i64) (num_subtrees: i64) (subtree_size: i64) :
  ([num_parents]i64, [num_parents]i64, [num_parents]i64, 
  [num_subtrees*subtree_size]i64, 
  [num_subtrees*subtree_size]i64, 
  [num_subtrees*subtree_size]i64, 
  [num_subtrees]i64,
  [num_parents]i64) = 
    let (lp1, rp1, data1) = gen_random_tree num_parents 42
    let (lp2, rp2, data2) = mk_subtrees num_subtrees subtree_size
    let ptrs = mk_parent_pointers num_parents num_subtrees 42
    let shp = replicate num_subtrees subtree_size
    in (lp1, rp1, data1, lp2, rp2, data2, shp, ptrs)

