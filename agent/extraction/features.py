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
    
    # Calculate byte frequencies
    frequencies = {byte: 0 for byte in range(256)}
    for byte in payload:
        frequencies[byte] += 1
        
    # Calculate entropy
    for count in frequencies.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)
            
    # Normalize to 0.0 - 1.0 range (max entropy for bytes is 8.0)
    return entropy / 8.0

def extract_statistical_features(values: list) -> dict:
    """
    Derives mean, standard deviation, variance, min, max, IQR, and Autocorrelation 
    from a list of values to construct the reinforcement learning state space[cite: 74, 76].
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
        # Calculate Inter-quartile range (IQR) 
        q75, q25 = np.percentile(arr, [75, 25])
        stats["iqr"] = float(q75 - q25)
        
        # Calculate Lag-1 Autocorrelation 
        if stats["var"] > 0:  # Prevent division by zero if all values are identical
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
        normalized.append(min(1.0, max(0.0, norm_val))) # Clamp between 0 and 1
    return normalized