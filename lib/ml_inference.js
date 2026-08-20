// ============================================================
// ML Inference Engine - Tiny Neural Network for Phishing Detection
// Architecture: 38 inputs → 16 hidden (ReLU) → 1 output (Sigmoid)
// No external dependencies — pure JS matrix operations
// ============================================================

let _mlWeights = null;
let _mlModelLoaded = false;
const ML_CACHE_KEY = "ml_weights_cache_v2";

/**
 * Load ML model weights — prefer persistent cache, fall back to fetch.
 * @returns {Promise<boolean>} Whether model loaded successfully
 */
export async function loadMLModel() {
  if (_mlModelLoaded) return true;
  try {
    // 1. Try persistent cache first (survives service-worker cold start)
    const cached = await chrome.storage.local.get(ML_CACHE_KEY);
    if (cached && cached[ML_CACHE_KEY] && cached[ML_CACHE_KEY].input_size) {
      _mlWeights = cached[ML_CACHE_KEY];
      _mlModelLoaded = true;
      return true;
    }
    // 2. Fall back to fetching the bundled weights
    const resp = await fetch(chrome.runtime.getURL("lib/ml_weights.json"));
    _mlWeights = await resp.json();
    _mlModelLoaded = true;
    // 3. Persist for next cold start (fire-and-forget)
    chrome.storage.local.set({ [ML_CACHE_KEY]: _mlWeights }).catch(function() {});
    console.log("[ML] Model loaded:", _mlWeights.description);
    return true;
  } catch (e) {
    console.error("[ML] Failed to load model:", e);
    return false;
  }
}

/**
 * Sigmoid activation function
 */
function _sigmoid(x) {
  return 1.0 / (1.0 + Math.exp(-x));
}

/**
 * ReLU activation function
 */
function _relu(x) {
  return x > 0 ? x : 0;
}

/**
 * Run ML inference on extracted features.
 * @param {number[]} features - Array of 38 binary feature values (0 or 1)
 * @returns {object} { probability, riskScore }
 *   probability: 0-1 float (phishing probability)
 *   riskScore: 0-100 scaled score
 */
export function mlPredict(features) {
  if (!_mlWeights || !_mlModelLoaded) {
    console.warn("[ML] Model not loaded, returning default score");
    return { probability: 0.5, riskScore: 50 };
  }

  if (features.length !== _mlWeights.input_size) {
    console.error(`[ML] Expected ${_mlWeights.input_size} features, got ${features.length}`);
    return { probability: 0.5, riskScore: 50 };
  }

  const { w1, b1, w2, b2, hidden_size } = _mlWeights;

  // Hidden layer: 38 inputs → 16 neurons, ReLU
  const hidden = [];
  for (let i = 0; i < hidden_size; i++) {
    let sum = b1[i];
    for (let j = 0; j < features.length; j++) {
      sum += w1[i][j] * features[j];
    }
    hidden.push(_relu(sum));
  }

  // Output layer: 16 → 1, Sigmoid
  let output = b2;
  for (let i = 0; i < hidden_size; i++) {
    output += w2[i] * hidden[i];
  }
  const probability = _sigmoid(output);

  // Scale to 0-100 risk score
  const riskScore = Math.round(probability * 100);

  return { probability, riskScore };
}

/**
 * Batch predict multiple feature sets (for bulk analysis)
 */
export function mlPredictBatch(featuresArray) {
  return featuresArray.map(features => mlPredict(features));
}

/**
 * Check if ML model is loaded
 */
export function isMLModelLoaded() {
  return _mlModelLoaded;
}

/**
 * Get model info
 */
export function getMLModelInfo() {
  if (!_mlWeights) return null;
  return {
    input_size: _mlWeights.input_size,
    hidden_size: _mlWeights.hidden_size,
    version: _mlWeights.version,
    description: _mlWeights.description
  };
}
