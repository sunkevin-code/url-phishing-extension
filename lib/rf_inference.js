// ============================================================
// Random Forest Inference Engine
// 30 decision trees (max_depth=6) → averaged probability
// No external dependencies — pure JS tree traversal
// ============================================================

let _rfWeights = null;
let _rfModelLoaded = false;
const RF_CACHE_KEY = "rf_weights_cache_v2";

/**
 * Load Random Forest model weights — prefer persistent cache, fall back to fetch.
 */
export async function loadRFModel() {
  if (_rfModelLoaded) return true;
  try {
    // 1. Try persistent cache first
    const cached = await chrome.storage.local.get(RF_CACHE_KEY);
    if (cached && cached[RF_CACHE_KEY] && cached[RF_CACHE_KEY].n_estimators) {
      _rfWeights = cached[RF_CACHE_KEY];
      _rfModelLoaded = true;
      return true;
    }
    // 2. Fall back to fetching the bundled weights
    const resp = await fetch(chrome.runtime.getURL("lib/rf_weights.json"));
    _rfWeights = await resp.json();
    _rfModelLoaded = true;
    // 3. Persist for next cold start
    chrome.storage.local.set({ [RF_CACHE_KEY]: _rfWeights }).catch(function() {});
    console.log("[RF] Model loaded:", _rfWeights.n_estimators, "trees");
    return true;
  } catch (e) {
    console.error("[RF] Failed to load:", e);
    return false;
  }
}

/**
 * Traverse a single decision tree and return the leaf value.
 */
function _predictTree(tree, features) {
  var node = 0;
  var feature = tree.feature;
  var threshold = tree.threshold;
  var left = tree.children_left;
  var right = tree.children_right;
  var value = tree.value;

  while (feature[node] !== -2) {
    if (features[feature[node]] <= threshold[node]) {
      node = left[node];
    } else {
      node = right[node];
    }
  }
  // Return [prob_class0, prob_class1]
  return value[node];
}

/**
 * Run Random Forest inference on extracted features.
 * @param {number[]} features - Array of 38 binary feature values (0 or 1)
 * @returns {object} { probability, riskScore, votes }
 *   probability: 0-1 float (phishing probability)
 *   riskScore: 0-100 scaled score
 *   votes: { for: N, against: N, total: N }
 */
export function rfPredict(features) {
  if (!_rfWeights || !_rfModelLoaded) {
    console.warn("[RF] Model not loaded");
    return { probability: 0.5, riskScore: 50, votes: { for: 0, against: 0, total: 0 } };
  }

  if (features.length !== _rfWeights.n_features) {
    console.error("[RF] Expected", _rfWeights.n_features, "features, got", features.length);
    return { probability: 0.5, riskScore: 50, votes: { for: 0, against: 0, total: 0 } };
  }

  var nTrees = _rfWeights.n_estimators;
  var totalProb = 0;
  var votesFor = 0;
  var votesAgainst = 0;

  for (var t = 0; t < nTrees; t++) {
    var leafValues = _predictTree(_rfWeights.trees[t], features);
    var probPhish = leafValues[1]; // [prob_benign, prob_phish]
    totalProb += probPhish;
    if (probPhish > 0.5) votesFor++;
    else votesAgainst++;
  }

  var probability = totalProb / nTrees;
  var riskScore = Math.round(probability * 100);

  return {
    probability: probability,
    riskScore: riskScore,
    votes: { for: votesFor, against: votesAgainst, total: nTrees }
  };
}

/**
 * Check if RF model is loaded
 */
export function isRFModelLoaded() {
  return _rfModelLoaded;
}

/**
 * Get model info
 */
export function getRFModelInfo() {
  if (!_rfWeights) return null;
  return {
    n_estimators: _rfWeights.n_estimators,
    n_features: _rfWeights.n_features,
    // Top 5 features by importance
    topFeatures: _rfWeights.feature_importance
      .map(function(v, i) { return { index: i, importance: v }; })
      .sort(function(a, b) { return b.importance - a.importance; })
      .slice(0, 5)
  };
}
