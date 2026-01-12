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