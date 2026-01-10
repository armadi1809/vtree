-- filepath: /Users/azizrmadi/DIKU/vtree/benchmarks/benchmark_operations.fut
import "../lib/github.com/diku-dk/vtree/vtree"
import "../lib/github.com/diku-dk/segmented/segmented"

module T = vtree

def exscan [n] 'a (op: a -> a -> a) (ne: a) (xs: [n]a) : [n]a =
  map2 (\i x -> if i == 0 then ne else x)
       (iota n)
       (rotate (-1) (scan op ne xs))

def wyllie_list_rank_from [n] (pt: [n]i64) (start: i64) : [n]i64 =
  let pt = copy pt with [start] = start
  let v = tabulate n (\i -> if pt[i] == i then 0 else 1)
  let (v, _) =
    loop (v, pt) = (v, pt) for _i < 64 - i64.clz n do
      let nv = map2 (\vi p -> vi + v[p]) v pt
      let npt = map (\p -> pt[p]) pt
      in (nv, npt)
  in v

def euler_tour_from_edges [m] (edges: [m](i64, i64)) (n: i64) : ([n]i64, [n]i64) =
  let num_directed = 2 * m
  
  let e = edges ++ map (\(i, j) -> (j, i)) edges :> [num_directed](i64, i64)
  let sources = map (.0) e
  let targets = map (.1) e
  
  let counts = reduce_by_index (replicate n 0i64) (+) 0 sources (replicate num_directed 1)
  let offsets = exscan (+) 0 counts
  
  let local_idx = tabulate num_directed (\i ->
    let src = sources[i]
    in i64.sum (tabulate i (\j -> if sources[j] == src then 1 else 0))
  )
  let positions = map2 (\src idx -> offsets[src] + idx) sources local_idx
  
  let sorted_targets = scatter (replicate num_directed 0i64) positions targets
  let sorted_edge_ids = scatter (replicate num_directed 0i64) positions (iota num_directed)
  
  let tour_next = tabulate num_directed (\edge_i ->
    let (u, v) = e[edge_i]
    let v_start = offsets[v]
    let v_count = counts[v]
    let pos_in_v = loop pos = 0 while pos < v_count && sorted_targets[v_start + pos] != u do pos + 1
    let next_pos = (pos_in_v + 1) % v_count
    in sorted_edge_ids[v_start + next_pos]
  )
  
  let back_to_root = 
    loop found = m while found < num_directed && targets[found] != 0 do found + 1
  
  let ranks = wyllie_list_rank_from tour_next back_to_root
  let final_ranks = map (\r -> num_directed - r) ranks
  
  let forward_ranks = take m final_ranks :> [m]i64
  let reverse_ranks = drop m final_ranks :> [m]i64
  
  let children = map (.1) edges
  let node_lp = scatter (replicate n 0i64) children forward_ranks
  let node_rp = scatter (replicate n 0i64) children reverse_ranks
  
  let node_lp = node_lp with [0] = 0
  let node_rp = node_rp with [0] = 2*n - 1
  
  in (node_lp, node_rp)

-- Generate random tree edges: node 0 is root, for node i > 0, parent is random in [0, i-1]
def random_tree_edges (n: i64) (seed: i64) : [](i64, i64) =
  let lcg s = (s * 1103515245 + 12345) % (1 << 31)
  let m = n - 1
  let (edges, _) = 
    loop (es, s) = (replicate m (0i64, 0i64), seed) for i in 1..<n do
      let parent = s % i
      in (es with [i-1] = (parent, i), lcg s)
  in edges

-- Build vtree from random edges (node 0 is always root)
def random_vtree (n: i64) (seed: i64) : T.t i64 [] =
  let edges = random_tree_edges n seed
  let (lp, rp) = euler_tour_from_edges edges n
  in T.lprp {lp, rp, data = iota n}

-- entry test_chain : ([4]i64, [4]i64) =
--   let edges : [3](i64, i64) = [(0, 1), (1, 2), (2, 3)]
--   in euler_tour_from_edges edges 4

-- entry test_star : ([4]i64, [4]i64) =
--   let edges : [3](i64, i64) = [(0, 1), (0, 2), (0, 3)]
--   in euler_tour_from_edges edges 4

-- Data generation entry
entry gen_random_tree (n: i64) (seed: i64) : ([]i64, []i64, []i64) =
  let edges = random_tree_edges n seed
  let (lp, rp) = euler_tour_from_edges edges n
  in (lp, rp, iota n)



-- Benchmark entries 


-- ==
-- entry: bench_delete
-- input @ data/random_10k.in
-- input @ data/random_100k.in
-- input @ data/random_500k.in

entry bench_delete [n] (lp: [n]i64) (rp: [n]i64) (data: [n]i64) : i64 =
  let t = T.lprp {lp, rp, data}
  let keep = tabulate n (\i -> i % 2 == 0)
  let result = T.deleteVertices t keep
  in length (T.getData result).data

-- ==
-- entry: bench_split
-- input @ data/random_10k.in
-- input @ data/random_100k.in
-- input @ data/random_500k.in

entry bench_split [n] (lp: [n]i64) (rp: [n]i64) (data: [n]i64) : i64 =
  let t = T.lprp {lp, rp, data}
  let split_node = 1 + (n / 2)  -- split at middle node
  let splits = tabulate n (\i -> i == split_node)
  let (subtree_res, _) = T.split t splits
  in length subtree_res.subtrees_shape