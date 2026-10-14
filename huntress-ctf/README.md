# Huntress CTF 2026 — Script Analysis solver

One-command solver for the daily **Script Analysis** challenge (all three modes).

```bash
export HUNTRESS_GM_TOKEN=gm1.....      # your Game Master bearer — never commit it
python3 huntress-ctf/solve_day.py 10   # solves single + time_trial + mastery for day 10
# or a single route:
python3 huntress-ctf/solve_any.py script-analysis-day-10-wmi-persistence-reconstruction/time_trial
```

Requirements: `python3`, `node`, `curl`, and Python deps:

```bash
pip install -r huntress-ctf/requirements.txt
```

See **PLAYBOOK.md** for how it works, the Game Master API, submission semantics,
every file/codec family, and how to extend it for a new day.
