"""
feature_extraction package
==========================
Exposes Flow and FeatureExtractor for converting raw packets to ML features,
plus ScanDetector for the heuristic PortScan aggregation layer.
"""

from feature_extraction.flow import Flow
from feature_extraction.extractor import FeatureExtractor
from feature_extraction.scan_detector import ScanDetector

__all__ = ["Flow", "FeatureExtractor", "ScanDetector"]
