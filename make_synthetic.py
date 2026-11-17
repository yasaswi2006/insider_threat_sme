"""Generate a small CERT-r4.2-format dataset for testing the pipeline (NOT real data)."""
import csv, os, random, sys
from datetime import datetime, timedelta
random.seed(7)
out = sys.argv[1]
os.makedirs(f"{out}/r4.2/LDAP", exist_ok=True)
for s in (1, 2, 3): os.makedirs(f"{out}/answers/r4.2-{s}", exist_ok=True)
F = "%m/%d/%Y %H:%M:%S"
depts = ["Finance", "Engineering", "Sales", "Research"]
roles = ["Salesman", "ProductionLineWorker", "ITAdmin", "Engineer", "Manager"]
users = []
for i in range(60):
    uid = f"{chr(65+i%26)}{chr(65+(i*7)%26)}{chr(65+(i*3)%26)}{1000+i:04d}"
    users.append(dict(uid=uid, role=random.choice(roles), dept=random.choice(depts),
                      pc=f"PC-{1000+i}", usb=random.random() < .3, night=random.random() < .1))
insiders = {users[3]["uid"]: 1, users[11]["uid"]: 1, users[20]["uid"]: 2, users[33]["uid"]: 3, users[47]["uid"]: 2}
start = datetime(2010, 1, 4); ndays = 150
eid = [0]
def nid():
    eid[0] += 1; return "{%08d}" % eid[0]
lg, dv, fl = [], [], []
ans = {u: [] for u in insiders}
exts = [".doc", ".pdf", ".txt", ".jpg", ".zip"]
for u in users:
    mal_start = 60 + random.randint(0, 40) if u["uid"] in insiders else None
    leave = mal_start + 25 if mal_start else None
    for d in range(ndays):
        day = start + timedelta(days=d)
        if day.weekday() >= 5 or (leave and d > leave): continue
        if random.random() < .05: continue
        mal = mal_start is not None and mal_start <= d <= leave and random.random() < .5
        sc = insiders.get(u["uid"])
        h = 7 + random.random() * 2
        t = day + timedelta(hours=h)
        r = [nid(), t.strftime(F), u["uid"], u["pc"], "Logon"]; lg.append(r)
        if u["role"] == "ITAdmin" and random.random() < .5:
            lg.append([nid(), (t + timedelta(hours=2)).strftime(F), u["uid"], f"PC-{random.randint(1000,1059)}", "Logon"])
        if u["usb"] and random.random() < .3:
            tt = t + timedelta(hours=3)
            dv.append([nid(), tt.strftime(F), u["uid"], u["pc"], "Connect"])
            for _ in range(random.randint(0, 3)):
                fl.append([nid(), (tt + timedelta(minutes=5)).strftime(F), u["uid"], u["pc"],
                           f"{random.randint(10**7, 10**8)}{random.choice(exts)}", "word words"])
        lg.append([nid(), (t + timedelta(hours=9)).strftime(F), u["uid"], u["pc"], "Logoff"])
        if u["night"] and random.random() < .2:
            lg.append([nid(), (day + timedelta(hours=21)).strftime(F), u["uid"], u["pc"], "Logon"])
        if mal:
            pc = u["pc"] if sc != 3 else users[0]["pc"]
            nt = day + timedelta(hours=22 if sc == 1 else 14)
            rows = [["logon", nid(), nt.strftime(F), u["uid"], pc, "Logon"],
                    ["device", nid(), (nt + timedelta(minutes=3)).strftime(F), u["uid"], pc, "Connect"]]
            for k in range(random.randint(3, 12) if sc != 3 else 1):
                ext = ".exe" if sc == 3 else random.choice(exts)
                rows.append(["file", nid(), (nt + timedelta(minutes=5 + k)).strftime(F), u["uid"], pc,
                             f"{random.randint(10**7, 10**8)}{ext}", "secret words"])
            for row in rows:
                {"logon": lg, "device": dv, "file": fl}[row[0]].append(row[1:])
                ans[u["uid"]].append(row)
    u["leave"] = leave
for name, rows, hdr in [("logon", lg, ["id", "date", "user", "pc", "activity"]),
                        ("device", dv, ["id", "date", "user", "pc", "activity"]),
                        ("file", fl, ["id", "date", "user", "pc", "filename", "content"])]:
    rows.sort(key=lambda r: datetime.strptime(r[1], F))
    with open(f"{out}/r4.2/{name}.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow(hdr); w.writerows(rows)
for m in range(1, 7):
    with open(f"{out}/r4.2/LDAP/2010-{m:02d}.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["employee_name", "user_id", "email", "role", "business_unit", "functional_unit", "department", "team", "supervisor"])
        for u in users:
            if u["leave"] and (start + timedelta(days=u["leave"])).month < m: continue
            w.writerow([f"Emp {u['uid']}", u["uid"], "x@dtaa.com", u["role"], "1", u["dept"], u["dept"], "T1", "Boss"])
with open(f"{out}/answers/insiders.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["dataset", "scenario", "details", "user", "start", "end"])
    for u, sc in insiders.items():
        fn = f"r4.2-{sc}-{u}.csv"
        with open(f"{out}/answers/r4.2-{sc}/{fn}", "w", newline="") as g:
            csv.writer(g).writerows(ans[u])
        ds = sorted(datetime.strptime(r[2], F) for r in ans[u])
        w.writerow(["4.2", sc, fn, u, ds[0].strftime(F), ds[-1].strftime(F)])
print("synthetic users", len(users), "logons", len(lg), "files", len(fl))
