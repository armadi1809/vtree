import "../lib/github.com/diku-dk/vtree/vtree"

module T = vtree

entry test_split =
  let t: T.t i64 [6] =
    T.lprp { lp = [0, 1, 2, 4, 6, 9]
           , rp = [11, 8, 3, 5, 7, 10]
           , data = iota 6
           }
  let splits = [false, true, false, false, false, false]
  let (subtree_res, remainder) = T.split t splits
  let subtrees = T.getData subtree_res.subtrees
  -- Check subtrees
  let subtrees_ok =
    length subtrees.data == 4
    && and (map2 (==) (sized (4) subtrees.data) [1, 2, 3, 4])
    && and (map2 (==) (sized (4) subtrees.lp) [0i64, 1, 3, 5])
    && and (map2 (==) (sized (4) subtrees.rp) [7i64, 2, 4, 6])
  -- Check offsets
  let offsets_ok =
    length subtree_res.offsets == 1
    && and (map2 (==) (sized (1) subtree_res.offsets) [0i64])
  -- Check remainder
  let rem = T.getData remainder
  let remainder_ok =
    length rem.data == 2
    && and (map2 (==) (sized (2) rem.data) [0, 5])
    && and (map2 (==) (sized (2) rem.lp) [0i64, 1])
    && and (map2 (==) (sized (2) rem.rp) [3i64, 2])
  in subtrees_ok && offsets_ok && remainder_ok

-- entry test_split_at_root =
--   let t: T.t i64 [6] =
--     T.lprp { lp = [0, 1, 2, 4, 6, 9]
--            , rp = [11, 8, 3, 5, 7, 10]
--            , data = iota 6
--            }
--   let splits = [true, false, false, false, false, false]
--   let (subtree_res, remainder) = T.split t splits
--   let subtrees = T.getData subtree_res.subtrees
--   let rem = T.getData remainder
--   -- Entire tree becomes subtree, remainder is empty
--   let subtrees_ok = length subtrees.data == 6
--   let remainder_ok = length rem.data == 0
--   in subtrees_ok && remainder_ok

entry test_split_at_leaf =
  let t: T.t i64 [6] =
    T.lprp { lp = [0, 1, 2, 4, 6, 9]
           , rp = [11, 8, 3, 5, 7, 10]
           , data = iota 6
           }
  -- Split at node 2 (a leaf under node 1)
  let splits = [false, false, true, false, false, false]
  let (subtree_res, remainder) = T.split t splits
  let subtrees = T.getData subtree_res.subtrees
  let rem = T.getData remainder
  -- Subtree should just be node 2
  let subtrees_ok =
    length subtrees.data == 1
    && and (map2 (==) (sized (1) subtrees.data) [2])
  -- Remainder should be nodes 0, 1, 3, 4, 5
  let remainder_ok = length rem.data == 5
  in subtrees_ok && remainder_ok

entry test_split_multiple =
  let t: T.t i64 [6] =
    T.lprp { lp = [0, 1, 2, 4, 6, 9]
           , rp = [11, 8, 3, 5, 7, 10]
           , data = iota 6
           }
  -- Split at both node 1 and node 5 (siblings under root)
  let splits = [false, true, false, false, false, true]
  let (subtree_res, remainder) = T.split t splits
  let subtrees = T.getData subtree_res.subtrees
  let rem = T.getData remainder
  -- Subtrees should contain nodes 1,2,3,4 and node 5
  let subtrees_ok = length subtrees.data == 5
  -- Offsets should be [0, 1] for two subtrees
  let offsets_ok =
    length subtree_res.offsets == 2
    && and (map2 (==) (sized (2) subtree_res.offsets) [0i64, 4])
  -- Remainder should only be root (node 0)
  let remainder_ok =
    length rem.data == 1
    && and (map2 (==) (sized (1) rem.data) [0])
  in subtrees_ok && offsets_ok && remainder_ok

entry test_split_none =
  let t: T.t i64 [6] =
    T.lprp { lp = [0, 1, 2, 4, 6, 9]
           , rp = [11, 8, 3, 5, 7, 10]
           , data = iota 6
           }
  let splits = [false, false, false, false, false, false]
  let (subtree_res, remainder) = T.split t splits
  let subtrees = T.getData subtree_res.subtrees
  let rem = T.getData remainder
  -- No subtrees
  let subtrees_ok = length subtrees.data == 0
  let offsets_ok = length subtree_res.offsets == 0
  -- All nodes in remainder
  let remainder_ok = length rem.data == 6
  in subtrees_ok && offsets_ok && remainder_ok

entry test_delete_vertices =
  let t: T.t i64 [6] =
    T.lprp { lp = [0, 1, 2, 4, 6, 9]
           , rp = [11, 8, 3, 5, 7, 10]
           , data = iota 6
           }
  -- Keep only nodes 0, 1, 5
  let keep = [true, true, false, false, false, true]
  let result = T.deleteVertices t keep
  let res = T.getData result
  let ok =
    length res.data == 3
    && and (map2 (==) (sized (3) res.data) [0, 1, 5])
  in ok

entry test_merge_tree = 
  let parent_tree: T.t i64 [4] =
    T.lprp {
    lp = [0,1,3,4],
    rp = [7,2,6,5],
    data = [0,1,2,3]
  }
  let subtrees: T.t i64 [5] =
    T.lprp {
      lp = [0,1,0,1,3],
      rp = [3,2,5,2,4],
      data = [4,5,6,7,8]
    }
  let subtree_offsets = [0i64,2i64]
  let parent_pointers = [0i64,1i64,0i64,-1i64]
  let expected = {
      lp = [0,1,2,5,6,7,9,13,14,15,18],
      rp = [21,4,3,12,11,8,10,20,17,16,19],
      data = [0,4,5,1,6,7,8,2,4,5,3]
    }
  let actual = T.getData (T.merge {subtrees = subtrees, subtree_offsets = subtree_offsets} parent_tree parent_pointers)
  let ok = 
    length actual.data == 11
    && and (map2 (==) (sized (11) actual.lp) expected.lp) 
    && and (map2 (==) (sized (11) actual.rp) expected.rp) 
    && and (map2 (==) (sized (11) actual.data) expected.data)
  in ok

entry test_merge_no_subtrees = 
  let parent_tree: T.t i64 [4] =
    T.lprp {
    lp = [0,1,3,4],
    rp = [7,2,6,5],
    data = [0,1,2,3]
  }
  let subtrees: T.t i64 [0] =
    T.lprp {
      lp = [],
      rp = [],
      data = []
    }
  let subtree_offsets = []
  let parent_pointers = [-1i64,-1i64,-1i64,-1i64]
  let expected = T.getData parent_tree
  let actual = T.getData (T.merge {subtrees = subtrees, subtree_offsets = subtree_offsets} parent_tree parent_pointers)
  let ok = 
    length actual.data == 4
    && and (map2 (==) (sized (4) actual.lp) expected.lp) 
    && and (map2 (==) (sized (4) actual.rp) expected.rp) 
    && and (map2 (==) (sized (4) actual.data) expected.data)
  in ok

-- Tests 
-- ==
-- entry: test_split test_split_at_leaf test_split_multiple test_split_none test_delete_vertices test_merge_tree test_merge_no_subtrees
-- input {} output { true }