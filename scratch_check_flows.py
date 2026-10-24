import urllib.request
import json

res = urllib.request.urlopen("http://127.0.0.1:8000/api/flows?limit=50")
flows = json.loads(res.read().decode())
print(f"Total flows returned: {len(flows)}")
suspicious_count = 0
for f in flows:
    v = f["verdict"]
    fl = f["flow"]
    if v["is_suspicious"] or v["status"] == "SUSPICIOUS" or v["risk_tier"] in ("HIGH", "CRITICAL", "SUSPICIOUS"):
        suspicious_count += 1
        print(f"SUSPICIOUS: {fl['src_ip']}:{fl['src_port']} -> {fl['dst_ip']}:{fl['dst_port']} ({fl['proto']}) | score: {v['raw_score']} | tier: {v['risk_tier']} | src: {v['detection_source']} | evid: {v['evidence']}")

print(f"\nTotal suspicious in last 50: {suspicious_count}")
