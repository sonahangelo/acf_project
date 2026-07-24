"""
Quick manual check: force a synthetic anomalous vector through
explain() to confirm it produces sensible output, without waiting
on live traffic to naturally trigger a BLOCK.
"""
from ai_model import AnomalyModel
from features import MODEL_FEATURE_COLUMNS

model = AnomalyModel(model_path="models/anomaly_model.pkl").load()

print("Feature columns:", MODEL_FEATURE_COLUMNS)
print("Trained means:", model.feature_means)
print()

# Build a synthetic vector that looks like a port scan:
# huge scan_distinct_ports and scan_pps, everything else modest.
fake_scan_vector = [74, 12345, 80, 0.5, 3, 300, 6.0, 600.0, 50, 200.0]

label, score = model.predict(fake_scan_vector)
explanation = model.explain(fake_scan_vector)

print(f"Predicted label: {label} (-1 = anomaly, 1 = normal)")
print(f"Score: {score:.4f}")
print("Top reasons:")
for name, value, dev in explanation:
    print(f"  {name} = {value}  ({dev:+.2f} std from normal)")
