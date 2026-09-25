import json

with open("benchmarks/data.json", "r") as f:
    data = json.load(f)

active = [item for item in data if item["status"] == "active"]
total_cpu = sum(item["cpu"] for item in active)
print(f"Python: Processed {len(active)} active nodes, Total CPU: {total_cpu}")
