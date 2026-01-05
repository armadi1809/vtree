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