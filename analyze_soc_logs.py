import re, os, ipaddress
import pandas as pd
import matplotlib.pyplot as plt
from datetime import timedelta

INPUT = "SOC_Task2_Sample_Logs.txt"
OUTDIR = "outputs"
os.makedirs(OUTDIR, exist_ok=True)

# --- Parse the text log into a DataFrame ---
pattern = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \| user=(?P<user>[^|]+) \| ip=(?P<ip>[^|]+) \| action=(?P<action>[^|]+)(?: \| threat=(?P<threat>.*))?'
)

rows = []
with open(INPUT, "r") as f:
    for line in f:
        m = pattern.search(line)
        if m:
            d = m.groupdict()
            d["ts"] = pd.to_datetime(d["ts"])
            d["user"] = d["user"].strip()
            d["ip"] = d["ip"].strip()
            d["action"] = d["action"].strip()
            d["threat"] = (d.get("threat") or "").strip()
            rows.append(d)

df = pd.DataFrame(rows).sort_values("ts")
# Basic flags
def is_private(ip):
    try:
        ipobj = ipaddress.ip_address(ip)
        return ipobj.is_private
    except Exception:
        return False
df["is_private"] = df["ip"].apply(is_private)
df["kind"] = df["action"].str.lower().str.extract(r'(login (?:failed|success)|malware detected)', expand=False).fillna("other")

# Save parsed data (nice for your appendix)
df.to_csv(os.path.join(OUTDIR, "parsed_events.csv"), index=False)

# --- 1) Chart: Malware detections by user ---
mal = df[df["kind"]=="malware detected"]
if not mal.empty:
    counts = mal["user"].value_counts()
    plt.figure()
    counts.plot(kind="bar", title="Malware detections by user")
    plt.xlabel("User"); plt.ylabel("Detections")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTDIR, "chart_malware_by_user.png"))
    plt.close()

# --- 2) Chart: Login failures vs successes over time (hourly) ---
auth = df[df["kind"].str.startswith("login")]
if not auth.empty:
    auth["hour"] = auth["ts"].dt.floor("H")
    auth["outcome"] = auth["kind"].str.extract(r'login (failed|success)', expand=False)
    trend = auth.pivot_table(index="hour", columns="outcome", values="user", aggfunc="count").fillna(0)
    plt.figure()
    trend.plot()
    plt.title("Login outcomes per hour")
    plt.xlabel("Time (hour)"); plt.ylabel("Event count")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTDIR, "chart_logins_over_time.png"))
    plt.close()

# --- 3) Chart: Top external IPs by event count ---
ext = df[~df["is_private"]]
if not ext.empty:
    top_ips = ext["ip"].value_counts().head(10)
    plt.figure()
    top_ips.plot(kind="bar", title="Top external IPs by events")
    plt.xlabel("IP"); plt.ylabel("Events")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTDIR, "chart_top_external_ips.png"))
    plt.close()

# --- Detect “success after failures” (possible brute force) ---
findings = []
window = timedelta(minutes=30)

for (user, ip), grp in auth.sort_values("ts").groupby(["user","ip"]):
    fails = []
    for _, row in grp.iterrows():
        if row["outcome"] == "failed":
            fails.append(row["ts"])
        else:  # success
            recent_fails = [t for t in fails if row["ts"]-t <= window]
            if len(recent_fails) >= 1:
                findings.append({
                    "Event_Type": "Success after failures",
                    "User": user, "Source_IP": ip,
                    "Timestamp": row["ts"],
                    "Count_Failures_Before_Success_30m": len(recent_fails),
                    "Severity": "High",
                    "Why": "Login success preceded by failures (within 30m)"
                })
            fails = []  # reset after success

# --- Add malware findings (High if ‘ransomware’, else Medium/High) ---
for _, r in mal.iterrows():
    sev = "High" if "ransomware" in r["threat"].lower() else "Medium"
    findings.append({
        "Event_Type": "Malware detection",
        "User": r["user"], "Source_IP": r["ip"],
        "Timestamp": r["ts"], "Threat": r["threat"],
        "Severity": "High" if "ransomware" in r["threat"].lower() else "Medium",
        "Why": "EDR/AV alert in logs"
    })

# --- Add repeated events from same external IP (context) ---
if not ext.empty:
    ext_counts = ext.groupby("ip").size().reset_index(name="count").sort_values("count", ascending=False)
    for _, r in ext_counts.head(5).iterrows():
        findings.append({
            "Event_Type": "External IP activity",
            "User": "(various)", "Source_IP": r["ip"],
            "Timestamp": df[df["ip"]==r["ip"]]["ts"].min(),
            "Count_Events": int(r["count"]),
            "Severity": "Medium",
            "Why": "Multiple events from a public IP"
        })

fd = pd.DataFrame(findings).sort_values("Timestamp")
fd.to_csv(os.path.join(OUTDIR, "findings_suggestions.csv"), index=False)

print("Done. Open the 'outputs/' folder for charts and CSV.")
