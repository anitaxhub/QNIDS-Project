"""
test_predict.py — Quick sanity check for predict.py interface.
Run from project root: python test_predict.py
"""
import predict

predict.load_models()

test_flows = [
    {"name": "Normal flow",    "flow_duration": 1.2,  "total_fwd_packets": 5},
    {"name": "Heavy SYN flow", "flow_duration": 0.01, "total_fwd_packets": 800,
     "syn_flag_count": 800, "flow_bytes_per_sec": 950000},
    {"name": "Empty flow",     },
]

print("\n" + "=" * 55)
print(f"  {'FLOW':<20} {'LABEL':<12} {'CONF':>6}  {'IF':>6}  DECISION")
print("=" * 55)

for flow in test_flows:
    name = flow.pop("name")
    result = predict.predict(flow)
    print(
        f"  {name:<20} {result['label']:<12} "
        f"{result['rf_confidence']:>6.2f}  "
        f"{result['if_score']:>6.3f}  "
        f"{result['decision']}"
    )

print("=" * 55)
print("\n[test_predict] All tests passed.\n")