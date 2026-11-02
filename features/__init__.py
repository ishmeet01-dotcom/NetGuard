"""
NetGuard Features Package
Provides vectorized numerical traffic analysis and comprehensive feature extraction.
"""

from features.numpy_analyzer import NumPyTrafficAnalyzer
from features.feature_extractor import TrafficFeatureExtractor, extract_traffic_features

__all__ = [
    "NumPyTrafficAnalyzer",
    "TrafficFeatureExtractor",
    "extract_traffic_features",
]
