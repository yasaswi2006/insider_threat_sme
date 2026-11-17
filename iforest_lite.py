"""
Score a trained scikit-learn IsolationForest with numpy only.

Why: some Windows machines (Smart App Control) block scikit-learn's compiled files from loading.
The pipeline trains with scikit-learn, then `export()` copies every tree into plain numpy arrays;
`score_samples()` reproduces IsolationForest.score_samples exactly without importing scikit-learn.
"""
import numpy as np


def _c(n):
    """Average path length of an unsuccessful search in a binary search tree of n points (Liu et al., 2008)."""
    n = np.asarray(n, dtype=float)
    out = np.zeros_like(n)
    out[n == 2] = 1.0
    big = n > 2
    out[big] = 2.0 * (np.log(n[big] - 1.0) + np.euler_gamma) - 2.0 * (n[big] - 1.0) / n[big]
    return out


def export(model):
    trees = []
    for est, feats in zip(model.estimators_, model.estimators_features_):
        t = est.tree_
        depth = np.zeros(t.node_count)
        stack = [(0, 0)]
        while stack:
            node, d = stack.pop()
            depth[node] = d
            if t.children_left[node] != -1:
                stack.append((t.children_left[node], d + 1))
                stack.append((t.children_right[node], d + 1))
        leaf_value = depth + _c(t.n_node_samples)  # path length credited at each leaf
        trees.append({"left": t.children_left.copy(), "right": t.children_right.copy(),
                      "feature": np.asarray(feats)[np.maximum(t.feature, 0)], "threshold": t.threshold.copy(),
                      "is_leaf": t.children_left == -1, "leaf_value": leaf_value})
    return {"trees": trees, "max_samples": int(model.max_samples_)}


def score_samples(lite, X):
    """Same value as sklearn IsolationForest.score_samples(X): -2^(-mean path length / c(max_samples))."""
    X = np.asarray(X, dtype=np.float32).astype(float)
    total = np.zeros(len(X))
    for t in lite["trees"]:
        node = np.zeros(len(X), dtype=np.int64)
        active = ~t["is_leaf"][node]
        while active.any():
            idx = np.where(active)[0]
            n = node[idx]
            go_left = X[idx, t["feature"][n]] <= t["threshold"][n]
            node[idx] = np.where(go_left, t["left"][n], t["right"][n])
            active[idx] = ~t["is_leaf"][node[idx]]
        total += t["leaf_value"][node]
    mean_depth = total / len(lite["trees"])
    return -(2.0 ** (-mean_depth / _c(np.array([lite["max_samples"]]))[0]))
