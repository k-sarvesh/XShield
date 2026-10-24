import urllib.request
import json

res = urllib.request.urlopen("http://127.0.0.1:8000/api/flows?limit=150")
flows = json.loads(res.read().decode())
real_flows = [f for f in flows if not f["flow"].get("is_synthetic", False)]
print(f"Total flows: {len(flows)}, Real live flows: {len(real_flows)}")

scores = []
dst_ports = {}
for f in real_flows:
    score = f["verdict"].get("raw_score")
    if score is not None:
        scores.append(score)
    dp = f["flow"]["dst_port"]
    dst_ports[dp] = dst_ports.get(dp, 0) + 1

if scores:
    print(f"Score min: {min(scores):.4f}, max: {max(scores):.4f}, avg: {sum(scores)/len(scores):.4f}")
print("Top Dst Ports:", sorted(dst_ports.items(), key=lambda x: x[1], reverse=True)[:10])

# Check any real suspicious
real_susp = [f for f in real_flows if f["verdict"]["is_suspicious"] or f["verdict"]["status"] == "SUSPICIOUS"]
print(f"Real suspicious flows: {len(real_susp)}")
for f in real_susp:
    print("  ->", f["flow"]["src_ip"], "->", f["flow"]["dst_ip"], f["flow"]["dst_port"], f["verdict"]["raw_score"], f["verdict"]["evidence"])
