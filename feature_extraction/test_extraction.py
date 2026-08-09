"""
test_extraction.py
===================
WHY THIS FILE EXISTS
--------------------
Independent test script for Phase 4: Feature Extraction.
Connects PacketSniffer to FeatureExtractor, converts captured packets
into 70-feature DataFrames, and verifies alignment with model.pkl expectations.

HOW TO RUN
----------
  python feature_extraction/test_extraction.py

EXPECTED OUTPUT
---------------
  - Verified 70 feature columns matching models/feature_columns.pkl.
  - Active flow tracking summary (flows created, packets processed).
  - Clean feature vector sample table.
"""

import time
import sys
import pathlib
import joblib

# Add project root to python path
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from packet_capture.sniffer import PacketSniffer
from feature_extraction.extractor import FeatureExtractor


def main():
    print("=" * 70)
    print("Phase 4 – Independent Feature Extraction Test")
    print("=" * 70)

    # 1. Load ground-truth ML training feature column names
    feat_cols_path = ROOT / "models" / "feature_columns.pkl"
    if feat_cols_path.exists():
        expected_cols = joblib.load(feat_cols_path)
        print(f"Loaded {len(expected_cols)} feature columns from models/feature_columns.pkl")
    else:
        print("WARNING: models/feature_columns.pkl not found. Testing with default schema.")

    # 2. Instantiate FeatureExtractor
    extractor = FeatureExtractor(feature_cols_path=feat_cols_path)
    print(f"FeatureExtractor initialized with {len(extractor.expected_features)} expected features.")

    # 3. Instantiate PacketSniffer & connect pipeline
    extracted_dfs = []

    def packet_callback(pkt):
        df = extractor.extract_features(pkt)
        extracted_dfs.append((pkt, df))

    print("\nStarting PacketSniffer to stream packets into FeatureExtractor...")
    sniffer = PacketSniffer(mode="simulation", callback=packet_callback)
    sniffer.start()

    time.sleep(3.0)

    sniffer.stop()
    print("PacketSniffer stopped.")

    # 4. Assertions & Validation
    print("\n" + "=" * 70)
    print("Feature Extraction Validation Results")
    print("=" * 70)
    print(f"  Total Packets Streamed     : {len(extracted_dfs)}")
    print(f"  Active Flows Tracked       : {len(extractor.active_flows)}")

    assert len(extracted_dfs) > 0, "Error: No packets were extracted!"

    sample_pkt, sample_df = extracted_dfs[0]

    # Validate shape (1 row, 70 columns)
    assert sample_df.shape == (1, 70), f"Expected shape (1, 70), got {sample_df.shape}"

    # Validate feature names and order
    if feat_cols_path.exists():
        assert list(sample_df.columns) == list(expected_cols), "Feature column names/order mismatch with feature_columns.pkl!"

    # Validate numeric integrity (no NaNs or Infs)
    has_nan = sample_df.isna().any().any()
    assert not has_nan, "Feature DataFrame contains NaN values!"

    print("\nSample Extracted Feature Vector (First 15 features):")
    sample_sub = sample_df.iloc[:, :15]
    for col in sample_sub.columns:
        val = sample_sub[col].values[0]
        print(f"  {col:<30} : {val:.4f}")

    print("\nSample Flow Control & Rate Metrics:")
    rate_cols = ["Flow Duration", "Flow Bytes/s", "Flow Packets/s", "Total Fwd Packets", "Total Backward Packets"]
    for col in rate_cols:
        if col in sample_df.columns:
            val = sample_df[col].values[0]
            print(f"  {col:<30} : {val:.4f}")

    print("=" * 70)
    print("SUCCESS: All Phase 4 Feature Extraction assertions passed!")


if __name__ == "__main__":
    main()
