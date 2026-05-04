import math
import numpy as np

def calculate_shannon_entropy(payload: bytes) -> float:
    """
    Calculates the Shannon entropy of a packet payload.
    High entropy indicates encrypted or compressed data.
    """
    if not payload:
        return 0.0
    
    entropy = 0.0
    length = len(payload)
    
    frequencies = {byte: 0 for byte in range(256)}
    for byte in payload:
        frequencies[byte] += 1
        
    for count in frequencies.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)
            
    # Normalize to the [0, 1] range (byte entropy max is 8.0).
    return entropy / 8.0

def extract_statistical_features(values: list) -> dict:
    """
    Returns summary statistics used in the RL state representation.
    """
    if not values:
        return {"mean": 0.0, "std": 0.0, "var": 0.0, "min": 0.0, "max": 0.0, "iqr": 0.0, "autocorr": 0.0}
    
    arr = np.array(values)
    stats = {
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr)),
        "var": float(np.var(arr)),
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "iqr": 0.0,
        "autocorr": 0.0
    }
    
    if len(arr) > 1:
        q75, q25 = np.percentile(arr, [75, 25])
        stats["iqr"] = float(q75 - q25)
        
        if stats["var"] > 0:
            corr_matrix = np.corrcoef(arr[:-1], arr[1:])
            if not np.isnan(corr_matrix[0, 1]):
                stats["autocorr"] = float(corr_matrix[0, 1])
                
    return stats

def normalize_vector(vector: list, max_vals: list) -> list:
    """
    Normalizes scalar values into a standard continuous range (0.0 to 1.0)
    to prevent destabilizing gradient descent during backpropagation.
    """
    normalized = []
    for val, max_v in zip(vector, max_vals):
        norm_val = val / max_v if max_v > 0 else 0.0
        normalized.append(min(1.0, max(0.0, norm_val)))
    return normalized