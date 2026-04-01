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
    Derives mean, standard deviation, min, and max from a list of values 
    (used for Payload Sizes and Inter-Arrival Times).
    """
    if not values:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0}
    
    arr = np.array(values)
    return {
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr)),
        "min": float(np.min(arr)),
        "max": float(np.max(arr))
    }

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