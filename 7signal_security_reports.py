"""
7SIGNAL Wireless Security Reports
Generates two security reports using the 7SIGNAL API:
  1. Wireless Security Posture Assessment (Monthly)
  2. Wireless Threat Indicator Weekly Digest

Incorporates intelligence from the 7SIGNAL WIDS engine:
  - YAML-driven threshold configuration (wids_config.yaml)
  - Evidence accumulation + threat/health split scoring
  - 802.11 reason code taxonomy (benign / attack / cipher / DoS)
  - UX impact scoring (MOS / jitter / packet loss tiers)
  - Robust retry/backoff API layer with rate limiting
"""

from __future__ import annotations

import io
import os
import random
import threading
import time
from datetime import date, timedelta, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import pandas as pd
import requests
import streamlit as st

try:
    import yaml
    _YAML_OK = True
except ImportError:
    _YAML_OK = False

# ─────────────────────────────────────────────────────────────
# Page config & CSS
# ─────────────────────────────────────────────────────────────
st.set_page_config(page_title="7SIGNAL Security Reports", page_icon="🔒", layout="wide")

PRIMARY_RED = "#E4002B"
DARK_NAVY   = "#1E2A3B"
MID_GREY    = "#6B7280"

st.markdown(f"""
<style>
  .report-header{{background:{DARK_NAVY};color:#fff;padding:1.2rem 1.6rem;border-radius:8px;margin-bottom:1.4rem;}}
  .report-header h1{{margin:0;font-size:1.6rem;}}
  .report-header p{{margin:.3rem 0 0;font-size:.9rem;color:#c0c8d4;}}
  .section-heading{{font-size:1.05rem;font-weight:700;color:{DARK_NAVY};border-left:4px solid {PRIMARY_RED};padding-left:.6rem;margin:1.2rem 0 .6rem;}}
  .kpi-row{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:1rem;}}
  .kpi-card{{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:.8rem 1.1rem;min-width:160px;flex:1;}}
  .kpi-label{{font-size:.75rem;color:{MID_GREY};margin-bottom:4px;}}
  .kpi-value{{font-size:1.4rem;font-weight:700;color:{DARK_NAVY};}}
  .kpi-sub{{font-size:.72rem;color:{MID_GREY};}}
  .sev-HIGH{{background:#fee2e2;color:#991b1b;border-radius:4px;padding:3px 10px;font-size:.82rem;font-weight:700;}}
  .sev-MED{{background:#fef9c3;color:#854d0e;border-radius:4px;padding:3px 10px;font-size:.82rem;font-weight:700;}}
  .sev-LOW{{background:#e0f2fe;color:#075985;border-radius:4px;padding:3px 10px;font-size:.82rem;font-weight:700;}}
  .sev-OK{{background:#dcfce7;color:#166534;border-radius:4px;padding:3px 10px;font-size:.82rem;font-weight:700;}}
  .etag{{display:inline-block;background:#f1f5f9;color:#334155;border-radius:3px;padding:1px 6px;font-size:.72rem;margin:1px;font-family:monospace;}}
  .mtag{{display:inline-block;background:#ede9fe;color:#5b21b6;border-radius:3px;padding:1px 6px;font-size:.72rem;margin:1px;font-family:monospace;}}
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════
# WIDS INTELLIGENCE LAYER
# ═══════════════════════════════════════════════════════════════

def _load_config() -> Dict[str, Any]:
    if not _YAML_OK:
        return {}
    p = Path(__file__).parent / "wids_config.yaml"
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            pass
    return {}

def _cv(cfg, *keys, default=None):
    v = cfg
    for k in keys:
        if isinstance(v, dict):
            v = v.get(k)
        else:
            return default
        if v is None:
            return default
    return v

CFG = _load_config()

TH: Dict[str, float] = {
    "attach_sr_min":        _cv(CFG,"attachment","success_rate_avg_min_pct",  default=95.0),
    "attach_ms_peak":       _cv(CFG,"attachment","attach_time_peak_max_ms",   default=5000.0),
    "attach_ms_avg":        _cv(CFG,"attachment","attach_time_avg_max_ms",    default=500.0),
    "airtime_avg":          _cv(CFG,"rf_performance","airtime_avg_max_pct",   default=30.0),
    "airtime_peak":         _cv(CFG,"rf_performance","airtime_peak_max_pct",  default=60.0),
    "retries_avg":          _cv(CFG,"rf_performance","retries_avg_max_pct",   default=30.0),
    "deauth_managed_peak":  _cv(CFG,"deauth_detection","storm_from_managed_peak",   default=200.0),
    "deauth_client_peak":   _cv(CFG,"deauth_detection","storm_from_client_peak",    default=100.0),
    "deauth_combined_peak": _cv(CFG,"deauth_detection","storm_combined_peak",       default=300.0),
    "deauth_severe_mult":   _cv(CFG,"deauth_detection","storm_severe_multiplier",    default=10.0),
    "deauth_extreme_mult":  _cv(CFG,"deauth_detection","storm_extreme_multiplier",   default=100.0),
    "dhcp_sr_min":          _cv(CFG,"dhcp","success_rate_avg_min_pct",        default=98.0),
    "dns_sr_min":           _cv(CFG,"dns","success_rate_avg_min_pct",         default=98.0),
    "eap_sr_min":           _cv(CFG,"security","eap","success_rate_min_pct",  default=90.0),
    "beacon_avail_min":     _cv(CFG,"beacon","availability_worst_min_pct",    default=95.0),
    "mos_poor":             _cv(CFG,"ux_impact","voip_mos","poor",            default=3.5),
    "mos_bad":              _cv(CFG,"ux_impact","voip_mos","bad",             default=3.0),
    "mos_very_bad":         _cv(CFG,"ux_impact","voip_mos","very_bad",        default=2.5),
    "jitter_elevated":      _cv(CFG,"ux_impact","jitter_ms","elevated",       default=10),
    "jitter_high":          _cv(CFG,"ux_impact","jitter_ms","high",           default=20),
    "jitter_very_high":     _cv(CFG,"ux_impact","jitter_ms","very_high",      default=30),
    "pkt_loss_elevated":    _cv(CFG,"ux_impact","packet_loss_pct","elevated", default=1.0),
    "pkt_loss_high":        _cv(CFG,"ux_impact","packet_loss_pct","high",     default=3.0),
    "pkt_loss_severe":      _cv(CFG,"ux_impact","packet_loss_pct","severe",   default=5.0),
    "tput_low":             _cv(CFG,"ux_impact","throughput_mbps","low",      default=5.0),
    "tput_very_low":        _cv(CFG,"ux_impact","throughput_mbps","very_low", default=1.0),
    "ux_moderate":          _cv(CFG,"ux_impact","impact_level","moderate",    default=25),
    "ux_severe":            _cv(CFG,"ux_impact","impact_level","severe",      default=50),
    "sev_high":             _cv(CFG,"severity","high_threshold",              default=70),
    "sev_med":              _cv(CFG,"severity","med_threshold",               default=50),
    "gateway_ping_min":     95.0,
    "web_dur_warn_ms":      3000.0,
    "gw_lat_warn_ms":       50.0,
    "closer_aps_warn":      1.0,
    "rssi_gap_warn_db":     5.0,
    "sticky_warn":          3.0,
    "adj_bssids_warn":      10.0,
    "vpn_low_pct":          80.0,
}

def _ep_defaults() -> Dict[str, int]:
    d = {
        "DEAUTH_ATTACK_SIGNATURE":70,"CIPHER_ATTACK_DETECTED":65,
        "ENCRYPTION_MISMATCH":60,"DOS_INDICATOR_DETECTED":45,
        "AUTH_DOWNGRADE":45,"CIPHER_DOWNGRADE":40,
        "DEAUTH_STORM_EXTREME":50,"PMF_DOWNGRADE":35,
        "MIC_FAILURE_DETECTED":28,"DISASSOC_FLOOD":35,
        "HIGH_DEAUTH_RATE":30,"ROGUE_AP":30,
        "DEAUTH_STORM_SEVERE":25,"EVIL_TWIN":25,
        "AUTH_FLOOD":25,"CIPHER_ATTACK":25,
        "ASSOC_FLOOD":20,"EAP_METHOD_MISMATCH":20,
        "EAP_FAILED_AUTH_SLOW":18,"HANDSHAKE_ATTACK_INDICATOR":25,
        "DEAUTH_STORM":22,"ASSOC_REJECTS":15,
        "EAP_PHASE_FAILURE":15,"WEAK_SECURITY":15,
        "SUSPICIOUS_DISCONNECT_CODES":10,"AAA_DEGRADED":12,
        "AUTH_FLOOD_HEALTH":12,"ASSOC_FLOOD_HEALTH":12,
        "DHCP_DEGRADED":10,"DNS_DEGRADED":10,
        "CLOSER_APS_DETECTED":15,"RSSI_GAP_DETECTED":12,
        "GATEWAY_PING_FAILURE":15,"DNS_QUERY_FAILURE":15,
        "WEB_DURATION_ANOMALY":10,"LOW_VPN_RATE":8,
        "ATTACH_DEGRADED":8,"ATTACH_TIME_PEAK":8,
        "RF_CONGESTION":5,"RF_RETRIES":5,"HIGH_BEACON_DENSITY":5,
        "HIGH_STICKY_FACTOR":8,"HIGH_ADJ_BSSID_DENSITY":5,
        "NO_PMF":2,"UX_IMPACT_MODERATE":10,"UX_IMPACT_SEVERE":20,
    }
    cfg_pts = _cv(CFG,"evidence_points",default={})
    if cfg_pts:
        d.update(cfg_pts)
    return d

EP: Dict[str,int] = _ep_defaults()

THREAT_EV: Set[str] = {
    "DEAUTH_ATTACK_SIGNATURE","CIPHER_ATTACK_DETECTED","DOS_INDICATOR_DETECTED",
    "MIC_FAILURE_DETECTED","HANDSHAKE_ATTACK_INDICATOR",
    "ROGUE_AP","EVIL_TWIN","ENCRYPTION_MISMATCH",
    "PMF_DOWNGRADE","CIPHER_DOWNGRADE","AUTH_DOWNGRADE",
    "DEAUTH_STORM","DEAUTH_STORM_SEVERE","DEAUTH_STORM_EXTREME",
    "SUSPICIOUS_DISCONNECT_CODES",
    "CLOSER_APS_DETECTED","RSSI_GAP_DETECTED",
    "GATEWAY_PING_FAILURE","DNS_QUERY_FAILURE","WEB_DURATION_ANOMALY",
}

BENIGN_RC: Set[int] = set(_cv(CFG,"disconnect_analysis","benign_disconnect_codes",
    default=[1,2,3,4,6,7,8,36,128,169,181,252]))
ATTACK_RC:  Set[int] = {1,2,6,7}
CIPHER_RC:  Set[int] = {17,18,24,25,26,27,28}
DOS_RC:     Set[int] = {5,99,100,103,106}
SEC_RC:     Set[int] = {14,15}

RC_MEANING: Dict[int,str] = {
    1:"Unspecified (common in floods)",
    2:"Previous auth no longer valid (spoofing)",
    3:"Station leaving / normal roaming",
    4:"Disassociated due to inactivity",
    5:"AP capacity exceeded (DoS indicator)",
    6:"Class 2 frame from non-authenticated STA (ATTACK)",
    7:"Class 3 frame from non-associated STA (ATTACK)",
    8:"Station leaving BSS / normal roaming",
    14:"MIC failure (potential key attack)",
    15:"4-way handshake timeout (PSK attack indicator)",
    17:"4-way handshake rejected – MIC failure (CIPHER ATTACK)",
    18:"4-way handshake rejected – invalid PMK/PTK (CIPHER ATTACK)",
    23:"IEEE 802.1X authentication failed",
    24:"Invalid group cipher (DOWNGRADE ATTACK)",
    25:"Invalid pairwise cipher (CIPHER ATTACK)",
    26:"Invalid AKMP (CIPHER ATTACK)",
    27:"Unsupported RSN IE version (CIPHER ATTACK)",
    28:"Invalid RSN IE capabilities (CIPHER ATTACK)",
    36:"QoS/QBSS disconnect (normal)",
    99:"Excessive frames before assoc (DoS/flood)",
    100:"Excessive data frames (DoS)",
    103:"Poor channel conditions (jamming indicator)",
    106:"Excessive retry (flood indicator)",
}

MITRE: Dict[str,Dict[str,str]] = {
    "DEAUTH_ATTACK_SIGNATURE": {"id":"T1499.003","name":"Network DoS – Deauth Flood",     "tactic":"Impact"},
    "DEAUTH_STORM":            {"id":"T1499.003","name":"Network DoS – Deauth Storm",     "tactic":"Impact"},
    "DEAUTH_STORM_SEVERE":     {"id":"T1499.003","name":"Network DoS – Severe Storm",     "tactic":"Impact"},
    "DEAUTH_STORM_EXTREME":    {"id":"T1499.003","name":"Network DoS – Extreme Storm",    "tactic":"Impact"},
    "EVIL_TWIN":               {"id":"T1557.003","name":"Evil Twin AP",                   "tactic":"Collection"},
    "ROGUE_AP":                {"id":"T1200",    "name":"Hardware Additions – Rogue AP",  "tactic":"Initial Access"},
    "MIC_FAILURE_DETECTED":    {"id":"T1040",    "name":"Network Sniffing – Key Cracking","tactic":"Credential Access"},
    "HANDSHAKE_ATTACK_INDICATOR":{"id":"T1110",  "name":"Brute Force – PSK Attack",       "tactic":"Credential Access"},
    "CIPHER_ATTACK_DETECTED":  {"id":"T1600.001","name":"Cipher Downgrade Attack",         "tactic":"Defense Evasion"},
    "CIPHER_DOWNGRADE":        {"id":"T1600.001","name":"Reduce Key Space",                "tactic":"Defense Evasion"},
    "PMF_DOWNGRADE":           {"id":"T1562",    "name":"Impair Defenses – PMF Bypass",   "tactic":"Defense Evasion"},
    "AUTH_DOWNGRADE":          {"id":"T1562",    "name":"Impair Defenses – Auth Downgrade","tactic":"Defense Evasion"},
    "ENCRYPTION_MISMATCH":     {"id":"T1557",    "name":"Adversary-in-the-Middle",         "tactic":"Collection"},
    "AUTH_FLOOD":              {"id":"T1498",    "name":"Network DoS – Auth Flood",        "tactic":"Impact"},
    "AUTH_FLOOD_HEALTH":       {"id":"T1498",    "name":"Network DoS – Auth Flood",        "tactic":"Impact"},
    "ASSOC_FLOOD":             {"id":"T1498",    "name":"Network DoS – Assoc Flood",       "tactic":"Impact"},
    "GATEWAY_PING_FAILURE":    {"id":"T1557",    "name":"ARP Cache Poisoning",             "tactic":"Collection"},
    "WEB_DURATION_ANOMALY":    {"id":"T1557",    "name":"Transparent Proxy Insertion",     "tactic":"Collection"},
    "DNS_QUERY_FAILURE":       {"id":"T1557.002","name":"DNS Spoofing",                    "tactic":"Collection"},
    "CLOSER_APS_DETECTED":     {"id":"T1557.003","name":"Evil Twin – Closer AP Detected",  "tactic":"Collection"},
    "RSSI_GAP_DETECTED":       {"id":"T1557.003","name":"Evil Twin – RSSI Vulnerability",  "tactic":"Collection"},
    "DOS_INDICATOR_DETECTED":  {"id":"T1499",    "name":"Endpoint Denial of Service",      "tactic":"Impact"},
}

def score_ev(ev: Set[str]) -> int:
    return max(0, min(100, sum(EP.get(t, 0) for t in ev)))

def split_scores(ev: Set[str]) -> Tuple[int,int]:
    t = sum(EP.get(x,0) for x in ev if x in THREAT_EV)
    h = sum(EP.get(x,0) for x in ev if x not in THREAT_EV)
    return t, h

def severity(t: int, h: int) -> str:
    if t >= 70:              return "HIGH"
    if t >= 40:              return "MED"
    if t >= 20 and h >= 30:  return "MED"
    if t >= 10:              return "LOW"
    if h >= 30:              return "LOW"
    return "OK"

def sev_html(s: str) -> str:
    return f'<span class="sev-{s}">{s}</span>'

def ev_html(ev: Set[str]) -> str:
    return " ".join(f'<span class="etag">{t}({EP.get(t,0)})</span>'
                    for t in sorted(ev, key=lambda x: EP.get(x,0), reverse=True))

def mitre_html(ev: Set[str]) -> str:
    seen, out = set(), []
    for t in ev:
        m = MITRE.get(t)
        if m and m["id"] not in seen:
            seen.add(m["id"])
            out.append(f'<span class="mtag">{m["id"]}</span>')
    return " ".join(out)

def mitre_df(ev: Set[str]) -> pd.DataFrame:
    seen, rows = set(), []
    for t in ev:
        m = MITRE.get(t)
        if m and m["id"] not in seen:
            seen.add(m["id"])
            rows.append(m)
    return pd.DataFrame(rows) if rows else pd.DataFrame()

def ux_score(mos_dl, mos_ul, jitter, pkt_loss, http_dl, http_ul) -> Tuple[int, List[str]]:
    pts, findings = 0, []
    for v, label in [(mos_dl,"VoIP DL MOS"),(mos_ul,"VoIP UL MOS")]:
        if v is None: continue
        if float(v) < TH["mos_very_bad"]:   pts+=30; findings.append(f"{label} {v:.2f} (very bad)")
        elif float(v) < TH["mos_bad"]:      pts+=20; findings.append(f"{label} {v:.2f} (bad)")
        elif float(v) < TH["mos_poor"]:     pts+=10; findings.append(f"{label} {v:.2f} (poor)")
    if jitter is not None:
        j = float(jitter)
        if j > TH["jitter_very_high"]:      pts+=25; findings.append(f"Jitter {j:.1f}ms (very high)")
        elif j > TH["jitter_high"]:         pts+=15; findings.append(f"Jitter {j:.1f}ms (high)")
        elif j > TH["jitter_elevated"]:     pts+=8;  findings.append(f"Jitter {j:.1f}ms (elevated)")
    if pkt_loss is not None:
        p = float(pkt_loss)
        if p > TH["pkt_loss_severe"]:       pts+=30; findings.append(f"Packet loss {p:.1f}% (severe)")
        elif p > TH["pkt_loss_high"]:       pts+=20; findings.append(f"Packet loss {p:.1f}% (high)")
        elif p > TH["pkt_loss_elevated"]:   pts+=10; findings.append(f"Packet loss {p:.1f}% (elevated)")
    for v, label in [(http_dl,"HTTP DL"),(http_ul,"HTTP UL")]:
        if v is None: continue
        if float(v) < TH["tput_very_low"]:  pts+=15; findings.append(f"{label} {v:.1f}Mbps (very low)")
        elif float(v) < TH["tput_low"]:     pts+=8;  findings.append(f"{label} {v:.1f}Mbps (low)")
    return pts, findings

def classify_rc(code: int) -> Tuple[str,str]:
    m = RC_MEANING.get(code, f"Unknown code {code}")
    if code in ATTACK_RC:    return "attack",  f"Code {code}: ⚠️ ATTACK SIGNATURE — {m}"
    if code in CIPHER_RC:    return "cipher",  f"Code {code}: ⚠️ CIPHER ATTACK — {m}"
    if code in DOS_RC:       return "dos",     f"Code {code}: ⚠️ DoS INDICATOR — {m}"
    if code == 14:           return "mic",     f"Code {code}: ⚠️ MIC FAILURE — {m}"
    if code == 15:           return "psk",     f"Code {code}: ⚠️ HANDSHAKE ATTACK — {m}"
    if code in BENIGN_RC:    return "benign",  f"Code {code}: {m.split('(')[0].strip()} (benign)"
    return "unknown",                          f"Code {code}: {m} (investigate)"


# ═══════════════════════════════════════════════════════════════
# ROBUST API LAYER
# ═══════════════════════════════════════════════════════════════

BASE_URL      = "https://api-v2.7signal.com"
MAX_RETRIES   = 8
MAX_BACKOFF   = 20
MAX_SRV_ERR   = 3

class _RL:
    def __init__(self, rps):
        self._min = 1.0/rps if rps>0 else 0
        self._lk = threading.Lock(); self._last = 0.0
    def wait(self):
        if not self._min: return
        with self._lk:
            e = time.time()-self._last
            if e < self._min: time.sleep(self._min-e)
            self._last = time.time()

_rl = _RL(20.0)

@st.cache_data(ttl=300, show_spinner=False)
def get_token(cid, csec):
    r = requests.post(f"{BASE_URL}/oauth2/token",
        data={"grant_type":"client_credentials","client_id":cid,"client_secret":csec},
        timeout=15)
    r.raise_for_status()
    return r.json()["access_token"]

def _get(token, path, params=None):
    hdrs = {"Authorization":f"Bearer {token}","accept":"application/json"}
    srv = 0
    for att in range(MAX_RETRIES+1):
        _rl.wait()
        try:
            r = requests.get(f"{BASE_URL}{path}", headers=hdrs, params=params, timeout=90)
        except Exception:
            if att >= MAX_RETRIES: raise
            time.sleep(min(MAX_BACKOFF,(2**att)+random.uniform(0,.6))); continue
        if r.status_code < 400: return r.json()
        if r.status_code in (502,503):
            srv += 1
            if srv >= MAX_SRV_ERR: raise RuntimeError(f"GET {path} persistent {r.status_code}")
        if r.status_code in (429,500,502,503,504):
            ra = r.headers.get("Retry-After")
            time.sleep(float(ra) if ra else min(MAX_BACKOFF,(2**att)+random.uniform(0,.6))); continue
        r.raise_for_status()
    raise RuntimeError(f"GET {path} failed")

def _post(token, path, body):
    hdrs = {"Authorization":f"Bearer {token}","Content-Type":"application/json","accept":"application/json"}
    srv = 0
    for att in range(MAX_RETRIES+1):
        _rl.wait()
        try:
            r = requests.post(f"{BASE_URL}{path}", headers=hdrs, json=body, timeout=90)
        except Exception:
            if att >= MAX_RETRIES: raise
            time.sleep(min(MAX_BACKOFF,(2**att)+random.uniform(0,.6))); continue
        if r.status_code < 400: return r.json()
        if r.status_code in (502,503):
            srv += 1
            if srv >= MAX_SRV_ERR: raise RuntimeError(f"POST {path} persistent {r.status_code}")
        if r.status_code in (429,500,502,503,504):
            ra = r.headers.get("Retry-After")
            time.sleep(float(ra) if ra else min(MAX_BACKOFF,(2**att)+random.uniform(0,.6))); continue
        r.raise_for_status()
    raise RuntimeError(f"POST {path} failed")

def iso(d, eod=False):
    if eod: return datetime(d.year,d.month,d.day,23,59,59,tzinfo=timezone.utc).isoformat()
    return datetime(d.year,d.month,d.day,0,0,0,tzinfo=timezone.utc).isoformat()

def fetch_agent(token, s, e, metrics, group_by=None, agg=None):
    if agg is None: agg=["AVG","MIN","MAX","COUNT"]
    b = {"start":s,"end":e,"metrics":metrics,"aggregate_functions":agg}
    if group_by: b["group_by_dimension"]=group_by
    return _post(token,"/v2/agents/time-series/numeric/summary",b)

def fetch_sensor(token, s, e, metrics, group_by=None, agg=None):
    if agg is None: agg=["AVG","MIN","MAX","COUNT"]
    b = {"start":s,"end":e,"metrics":metrics,"aggregate_functions":agg}
    if group_by: b["group_by_dimension"]=group_by
    return _post(token,"/v2/sensors/time-series/numeric/summary",b)

def fetch_sensor_ap(token, s, e, metrics, agg=None):
    return fetch_sensor(token,s,e,metrics,group_by="accessPoint",agg=agg)

def sv(data, metric, agg="avg", default=None, prec=1):
    try:
        rows = data.get("data") or data.get("results") or []
        row = rows[0] if rows else data
        val = (row.get(metric) or {}).get(agg)
        return round(val,prec) if val is not None else default
    except Exception:
        return default

def to_df(data, metrics):
    try:
        rows = data.get("data") or data.get("results") or []
        if not rows: return pd.DataFrame()
        recs = []
        for row in rows:
            rec = {"group": row.get("groupValue") or row.get("label","—")}
            for m in metrics:
                md = row.get(m) or {}
                rec[f"{m}_avg"]=md.get("avg"); rec[f"{m}_min"]=md.get("min"); rec[f"{m}_max"]=md.get("max")
            recs.append(rec)
        return pd.DataFrame(recs)
    except Exception:
        return pd.DataFrame()

def build_excel(sheets, account, title, sd, ed):
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="xlsxwriter") as w:
        wb = w.book
        hf = wb.add_format({"bold":True,"bg_color":"#1E2A3B","font_color":"#FFFFFF","border":1})
        mf = wb.add_format({"bold":True,"font_size":11})
        for name, df in sheets.items():
            if df is None or df.empty:
                df = pd.DataFrame({"Note":["No data available."]})
            df.to_excel(w, sheet_name=name[:31], index=False, startrow=5)
            ws = w.sheets[name[:31]]
            ws.write("A1","Account:",mf); ws.write("B1",account)
            ws.write("A2","Report:",mf);  ws.write("B2",title)
            ws.write("A3","Period:",mf);  ws.write("B3",f"{sd} → {ed}")
            ws.write("A4","Generated:",mf); ws.write("B4",datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
            for ci,cn in enumerate(df.columns):
                ws.write(5,ci,cn,hf); ws.set_column(ci,ci,max(len(str(cn))+4,14))
        cov=wb.add_worksheet("Cover")
        cov.write("A1","7SIGNAL Security Report",mf)
        cov.write("A2",f"Account: {account}"); cov.write("A3",f"Report: {title}")
        cov.write("A4",f"Period: {sd} → {ed}")
        cov.write("A5",f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    buf.seek(0); return buf.read()


# ═══════════════════════════════════════════════════════════════
# REPORT 1 — SECURITY POSTURE ASSESSMENT
# ═══════════════════════════════════════════════════════════════

def report_posture(token, account, sd, ed):
    s, e = iso(sd), iso(ed, eod=True)
    st.markdown(f'<div class="report-header"><h1>🔒 Wireless Security Posture Assessment</h1>'
                f'<p>{account} &nbsp;|&nbsp; {sd} → {ed}</p></div>', unsafe_allow_html=True)

    all_ev: Set[str] = set()
    xls: Dict[str, pd.DataFrame] = {}

    # ── S1: Authentication & Access Control ───────────────────────────────
    st.markdown('<div class="section-heading">1 · Authentication & Access Control (Sensor)</div>', unsafe_allow_html=True)
    with st.spinner("Fetching sensor authentication data…"):
        try:
            d = fetch_sensor(token,s,e,["AC001","AC002","AC004","AC008","AC009","RA103","AV008","DN002","QURT007"])
            ac001=sv(d,"AC001"); ac002=sv(d,"AC002"); ac004=sv(d,"AC004"); ac004_mx=sv(d,"AC004","max")
            ra103=sv(d,"RA103"); av008=sv(d,"AV008"); av008_mn=sv(d,"AV008","min")
            dn002=sv(d,"DN002"); qurt=sv(d,"QURT007")

            ev: Set[str] = set()
            if ac001 and float(ac001)<TH["attach_sr_min"]:   ev.add("ATTACH_DEGRADED")
            if ac002 and float(ac002)<TH["dhcp_sr_min"]:     ev.add("DHCP_DEGRADED")
            if dn002 and float(dn002)<TH["dns_sr_min"]:      ev.add("DNS_DEGRADED")
            if ra103 and float(ra103)<TH["eap_sr_min"]:      ev.add("AAA_DEGRADED")
            if av008_mn and float(av008_mn)<TH["beacon_avail_min"]: ev.add("ATTACH_DEGRADED")
            if ac004_mx and float(ac004_mx)>TH["attach_ms_peak"]:   ev.add("ATTACH_TIME_PEAK")
            all_ev|=ev; ts,hs=split_scores(ev); sev=severity(ts,hs)

            c1,c2=st.columns([3,1])
            with c2:
                st.markdown(f"**Severity:** {sev_html(sev)}", unsafe_allow_html=True)
                if ev: st.markdown(ev_html(ev), unsafe_allow_html=True)
                mh=mitre_html(ev)
                if mh: st.markdown(f"**MITRE:** {mh}", unsafe_allow_html=True)
            with c1:
                st.markdown(f"""<div class="kpi-row">
                  <div class="kpi-card"><div class="kpi-label">Beacon Avail (AV008)</div><div class="kpi-value">{av008 or 'N/A'}%</div><div class="kpi-sub">Min: {av008_mn}% · Target ≥{TH['beacon_avail_min']}%</div></div>
                  <div class="kpi-card"><div class="kpi-label">Attach Success (AC001)</div><div class="kpi-value">{ac001 or 'N/A'}%</div><div class="kpi-sub">Target ≥{TH['attach_sr_min']}%</div></div>
                  <div class="kpi-card"><div class="kpi-label">EAP Success (RA103)</div><div class="kpi-value">{ra103 or 'N/A'}%</div><div class="kpi-sub">Target ≥{TH['eap_sr_min']}%</div></div>
                  <div class="kpi-card"><div class="kpi-label">DHCP Success (AC002)</div><div class="kpi-value">{ac002 or 'N/A'}%</div><div class="kpi-sub">Target ≥{TH['dhcp_sr_min']}%</div></div>
                  <div class="kpi-card"><div class="kpi-label">DNS Success (DN002)</div><div class="kpi-value">{dn002 or 'N/A'}%</div><div class="kpi-sub">Target ≥{TH['dns_sr_min']}%</div></div>
                  <div class="kpi-card"><div class="kpi-label">Ping Success (QURT007)</div><div class="kpi-value">{qurt or 'N/A'}%</div><div class="kpi-sub">E2E reachability</div></div>
                  <div class="kpi-card"><div class="kpi-label">Attach Time avg (AC004)</div><div class="kpi-value">{ac004 or 'N/A'} ms</div><div class="kpi-sub">Peak: {ac004_mx} ms</div></div>
                </div>""", unsafe_allow_html=True)
            d_ap=fetch_sensor_ap(token,s,e,["AC001","AC002","AC008","RA103","AC004","AV008","DN002"],agg=["AVG","MIN","COUNT"])
            df_ap=to_df(d_ap,["AC001","AC002","AC008","RA103","AC004","AV008","DN002"])
            if not df_ap.empty: st.caption("Per-AP breakdown"); st.dataframe(df_ap,use_container_width=True,hide_index=True)
            xls["Auth Per AP"]=df_ap if not df_ap.empty else pd.DataFrame({"KPI":["AC001","AC002","RA103","AV008","DN002","AC004_peak"],"Value":[ac001,ac002,ra103,av008,dn002,ac004_mx]})
        except Exception as ex:
            st.warning(f"Auth data unavailable: {ex}"); xls["Auth Per AP"]=pd.DataFrame()

    # ── S2: RF & Deauth ────────────────────────────────────────────────────
    st.markdown('<div class="section-heading">2 · RF Performance & Deauth Analysis (Sensor)</div>', unsafe_allow_html=True)
    with st.spinner("Fetching RF / deauth data…"):
        try:
            d=fetch_sensor(token,s,e,["TR062","QURS007","TR126","TR127","TR124","TR112","TR116","QUAP005","QUAP006","QUAP008","QUAP009","QURT004","QURS002","QURS004"],agg=["AVG","MIN","MAX"])
            atime=sv(d,"TR062"); atime_pk=sv(d,"TR062","max")
            ret=sv(d,"QURS007"); ret_pk=sv(d,"QURS007","max")
            d_ap_mx=sv(d,"TR126","max"); d_ap_avg=sv(d,"TR126")
            d_cli_mx=sv(d,"TR127","max"); d_cli_avg=sv(d,"TR127")
            dis_mx=sv(d,"TR124","max"); auth_req=sv(d,"TR112","max"); assoc_req=sv(d,"TR116","max")
            mos_dl=sv(d,"QUAP005"); mos_ul=sv(d,"QUAP006")
            http_dl=sv(d,"QUAP008"); http_ul=sv(d,"QUAP009")
            ping_rtt=sv(d,"QURT004"); sig=sv(d,"QURS002"); ap_ret=sv(d,"QURS004")

            comb_mx=(float(d_ap_mx or 0)+float(d_cli_mx or 0))
            sev_thr=TH["deauth_combined_peak"]*TH["deauth_severe_mult"]
            ext_thr=TH["deauth_combined_peak"]*TH["deauth_extreme_mult"]

            ev: Set[str]=set()
            if atime and float(atime)>TH["airtime_avg"]: ev.add("RF_CONGESTION")
            if atime_pk and float(atime_pk)>TH["airtime_peak"]: ev.add("RF_CONGESTION")
            if ret and float(ret)>TH["retries_avg"]: ev.add("RF_RETRIES")
            if comb_mx>=ext_thr: ev.add("DEAUTH_STORM_EXTREME")
            elif comb_mx>=sev_thr: ev.add("DEAUTH_STORM_SEVERE")
            elif comb_mx>=TH["deauth_combined_peak"]: ev.add("DEAUTH_STORM")
            elif d_ap_mx and float(d_ap_mx)>=TH["deauth_managed_peak"]: ev.add("DEAUTH_STORM")
            if auth_req and float(auth_req)>50: ev.add("AUTH_FLOOD_HEALTH")
            if assoc_req and float(assoc_req)>40: ev.add("ASSOC_FLOOD_HEALTH")
            ux_pts,ux_f=ux_score(mos_dl,mos_ul,None,None,http_dl,http_ul)
            if ux_pts>=TH["ux_severe"]: ev.add("UX_IMPACT_SEVERE")
            elif ux_pts>=TH["ux_moderate"]: ev.add("UX_IMPACT_MODERATE")

            all_ev|=ev; ts,hs=split_scores(ev); sev=severity(ts,hs)
            d_sev="HIGH" if comb_mx>=ext_thr else("MED" if comb_mx>=sev_thr else("LOW" if comb_mx>=TH["deauth_combined_peak"] else "OK"))

            c1,c2=st.columns([3,1])
            with c2:
                st.markdown(f"**Severity:** {sev_html(sev)}", unsafe_allow_html=True)
                if ev: st.markdown(ev_html(ev), unsafe_allow_html=True)
                mh=mitre_html(ev)
                if mh: st.markdown(f"**MITRE:** {mh}", unsafe_allow_html=True)
                if ux_f:
                    st.caption("UX Impact Findings")
                    for f in ux_f: st.caption(f"• {f}")
            with c1:
                st.markdown(f"""<div class="kpi-row">
                  <div class="kpi-card"><div class="kpi-label">Air Time avg (TR062)</div><div class="kpi-value">{atime or 'N/A'}%</div><div class="kpi-sub">Peak: {atime_pk}% · Threshold: {TH['airtime_avg']}%</div></div>
                  <div class="kpi-card"><div class="kpi-label">Client Retries avg (QURS007)</div><div class="kpi-value">{ret or 'N/A'}%</div><div class="kpi-sub">Peak: {ret_pk}%</div></div>
                  <div class="kpi-card"><div class="kpi-label">Deauth AP→Cli peak (TR126) {sev_html(d_sev)}</div><div class="kpi-value">{d_ap_mx or 'N/A'}/min</div><div class="kpi-sub">Avg: {d_ap_avg} · Threshold: {TH['deauth_managed_peak']:.0f}</div></div>
                  <div class="kpi-card"><div class="kpi-label">Deauth Cli→AP peak (TR127)</div><div class="kpi-value">{d_cli_mx or 'N/A'}/min</div><div class="kpi-sub">Avg: {d_cli_avg} · Threshold: {TH['deauth_client_peak']:.0f}</div></div>
                  <div class="kpi-card"><div class="kpi-label">Combined deauth peak</div><div class="kpi-value">{comb_mx:.0f}/min</div><div class="kpi-sub">Severe@{sev_thr:.0f} Extreme@{ext_thr:.0f}</div></div>
                  <div class="kpi-card"><div class="kpi-label">Disassoc peak (TR124)</div><div class="kpi-value">{dis_mx or 'N/A'}/min</div><div class="kpi-sub">Disassociation frames</div></div>
                  <div class="kpi-card"><div class="kpi-label">VoIP MOS DL (QUAP005)</div><div class="kpi-value">{mos_dl or 'N/A'}</div><div class="kpi-sub">Poor&lt;{TH['mos_poor']} Bad&lt;{TH['mos_bad']}</div></div>
                  <div class="kpi-card"><div class="kpi-label">VoIP MOS UL (QUAP006)</div><div class="kpi-value">{mos_ul or 'N/A'}</div><div class="kpi-sub">Poor&lt;{TH['mos_poor']}</div></div>
                  <div class="kpi-card"><div class="kpi-label">HTTP DL (QUAP008)</div><div class="kpi-value">{http_dl or 'N/A'} Mbps</div><div class="kpi-sub">Low&lt;{TH['tput_low']} Mbps</div></div>
                  <div class="kpi-card"><div class="kpi-label">HTTP UL (QUAP009)</div><div class="kpi-value">{http_ul or 'N/A'} Mbps</div><div class="kpi-sub">Low&lt;{TH['tput_low']} Mbps</div></div>
                  <div class="kpi-card"><div class="kpi-label">Ping RTT (QURT004)</div><div class="kpi-value">{ping_rtt or 'N/A'} ms</div><div class="kpi-sub">E2E latency</div></div>
                  <div class="kpi-card"><div class="kpi-label">AP Retries (QURS004)</div><div class="kpi-value">{ap_ret or 'N/A'}</div><div class="kpi-sub">SU AP retransmits</div></div>
                </div>""", unsafe_allow_html=True)
            xls["RF & Deauth"]=pd.DataFrame({"Metric":["Air Time avg%","Air Time peak%","Client Retries%","Deauth AP /min","Deauth Cli /min","Combined peak /min","Disassoc /min","Auth Req /min","VoIP MOS DL","VoIP MOS UL","HTTP DL Mbps","HTTP UL Mbps","Ping RTT ms","AP Retries"],"Value":[atime,atime_pk,ret,d_ap_mx,d_cli_mx,comb_mx,dis_mx,auth_req,mos_dl,mos_ul,http_dl,http_ul,ping_rtt,ap_ret]})
        except Exception as ex:
            st.warning(f"RF/deauth data unavailable: {ex}"); xls["RF & Deauth"]=pd.DataFrame()

    # ── S3: Rogue & Neighbor Exposure ─────────────────────────────────────
    st.markdown('<div class="section-heading">3 · Rogue & Neighbor Device Exposure (Agent)</div>', unsafe_allow_html=True)
    with st.spinner("Fetching neighbor exposure data…"):
        try:
            d=fetch_agent(token,s,e,["NUMBER_OF_CLOSER_ACCESS_POINTS","NUMBER_OF_CLOSER_ACCESS_POINTS_PREFERRED_BAND","NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS","NUMBER_OF_CO_CHANNEL_OVERLAPPING_BSSIDS","OVERALL_BEST_NEIGHBOR_SIGNAL_STRENGTH","SIGNAL_STRENGTH","STICKY_FACTOR","CLASSIC_STICKY_FACTOR"],agg=["AVG","MAX"])
            cap=sv(d,"NUMBER_OF_CLOSER_ACCESS_POINTS"); cap_mx=sv(d,"NUMBER_OF_CLOSER_ACCESS_POINTS","max")
            adj=sv(d,"NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS"); co=sv(d,"NUMBER_OF_CO_CHANNEL_OVERLAPPING_BSSIDS")
            bnr=sv(d,"OVERALL_BEST_NEIGHBOR_SIGNAL_STRENGTH"); conn=sv(d,"SIGNAL_STRENGTH")
            stk=sv(d,"STICKY_FACTOR"); stk_mx=sv(d,"STICKY_FACTOR","max")
            gap=round(float(bnr)-float(conn),1) if bnr and conn else None

            ev: Set[str]=set()
            if cap and float(cap)>TH["closer_aps_warn"]:  ev.add("CLOSER_APS_DETECTED")
            if gap and gap>TH["rssi_gap_warn_db"]:         ev.add("RSSI_GAP_DETECTED")
            if stk and float(stk)>TH["sticky_warn"]:       ev.add("HIGH_STICKY_FACTOR")
            if adj and float(adj)>TH["adj_bssids_warn"]:   ev.add("HIGH_ADJ_BSSID_DENSITY")

            all_ev|=ev; ts,hs=split_scores(ev); sev=severity(ts,hs)
            gd=f"+{gap}" if gap and gap>0 else str(gap) if gap is not None else "N/A"

            c1,c2=st.columns([3,1])
            with c2:
                st.markdown(f"**Severity:** {sev_html(sev)}", unsafe_allow_html=True)
                if ev: st.markdown(ev_html(ev), unsafe_allow_html=True)
                mh=mitre_html(ev)
                if mh: st.markdown(f"**MITRE:** {mh}", unsafe_allow_html=True)
            with c1:
                st.markdown(f"""<div class="kpi-row">
                  <div class="kpi-card"><div class="kpi-label">Closer APs avg</div><div class="kpi-value">{cap or 'N/A'}</div><div class="kpi-sub">Max: {cap_mx} · Evil twin risk · Threshold >{TH['closer_aps_warn']}</div></div>
                  <div class="kpi-card"><div class="kpi-label">RSSI Gap (neighbor vs connected)</div><div class="kpi-value">{gd} dBm</div><div class="kpi-sub">+dBm = rogue may be stronger · Threshold >{TH['rssi_gap_warn_db']}</div></div>
                  <div class="kpi-card"><div class="kpi-label">Sticky Factor avg</div><div class="kpi-value">{stk or 'N/A'}</div><div class="kpi-sub">Max: {stk_mx} · Threshold >{TH['sticky_warn']}</div></div>
                  <div class="kpi-card"><div class="kpi-label">Adj Overlapping BSSIDs</div><div class="kpi-value">{adj or 'N/A'}</div><div class="kpi-sub">Unmanaged AP density · Threshold >{TH['adj_bssids_warn']}</div></div>
                  <div class="kpi-card"><div class="kpi-label">Co-Channel BSSIDs</div><div class="kpi-value">{co or 'N/A'}</div><div class="kpi-sub">Interference + rogue risk</div></div>
                </div>""", unsafe_allow_html=True)
            dn=fetch_agent(token,s,e,["NUMBER_OF_CLOSER_ACCESS_POINTS","NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS","STICKY_FACTOR"],group_by="network",agg=["AVG","MAX"])
            df_n=to_df(dn,["NUMBER_OF_CLOSER_ACCESS_POINTS","NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS","STICKY_FACTOR"])
            if not df_n.empty: st.caption("Rogue exposure by network"); st.dataframe(df_n,use_container_width=True,hide_index=True)
            xls["Rogue Exposure"]=df_n if not df_n.empty else pd.DataFrame({"Metric":["Closer APs avg","Closer APs max","RSSI Gap dBm","Sticky avg","Adj BSSIDs avg"],"Value":[cap,cap_mx,gap,stk,adj]})
        except Exception as ex:
            st.warning(f"Rogue exposure unavailable: {ex}"); xls["Rogue Exposure"]=pd.DataFrame()

    # ── S4: Connectivity Integrity ─────────────────────────────────────────
    st.markdown('<div class="section-heading">4 · Connectivity Integrity (Agent + Sensor)</div>', unsafe_allow_html=True)
    with st.spinner("Fetching connectivity data…"):
        try:
            da=fetch_agent(token,s,e,["VPN_CONNECTION","GATEWAY_PING_CONNECTIVITY","GATEWAY_PING_LATENCY","WEB_CONNECTIVITY","WEB_DURATION","APPLICATION_CONNECTIVITY","MOS_UPLOAD_PACKET_LOSS","MOS_UPLOAD_JITTER","MOS_UPLOAD"],agg=["AVG","MIN","MAX"])
            ds=fetch_sensor(token,s,e,["DN002","QURT007","QURT004","QUAP005","QUAP006","QUAP008","QUAP009","QURS002","QURS004","QURS007","TR062","AV008"],agg=["AVG","MIN","MAX"])
            vpn=sv(da,"VPN_CONNECTION"); gw=sv(da,"GATEWAY_PING_CONNECTIVITY"); gw_lat=sv(da,"GATEWAY_PING_LATENCY"); gw_lat_mx=sv(da,"GATEWAY_PING_LATENCY","max")
            wc=sv(da,"WEB_CONNECTIVITY"); wd=sv(da,"WEB_DURATION"); wd_mx=sv(da,"WEB_DURATION","max")
            ac=sv(da,"APPLICATION_CONNECTIVITY"); pl=sv(da,"MOS_UPLOAD_PACKET_LOSS"); jit=sv(da,"MOS_UPLOAD_JITTER"); mos_up=sv(da,"MOS_UPLOAD")
            dns_s=sv(ds,"DN002"); dns_mn=sv(ds,"DN002","min"); ping_s=sv(ds,"QURT007"); rtt_s=sv(ds,"QURT004")
            http_dl_s=sv(ds,"QUAP008"); http_ul_s=sv(ds,"QUAP009"); mos_dl_s=sv(ds,"QUAP005"); mos_ul_s=sv(ds,"QUAP006")
            sig_s=sv(ds,"QURS002"); ap_ret_s=sv(ds,"QURS004"); cli_ret_s=sv(ds,"QURS007"); air_s=sv(ds,"TR062")

            ev: Set[str]=set()
            if gw and float(gw)<TH["gateway_ping_min"]:   ev.add("GATEWAY_PING_FAILURE")
            if gw_lat and float(gw_lat)>TH["gw_lat_warn_ms"]: ev.add("GATEWAY_PING_FAILURE")
            if wd and float(wd)>TH["web_dur_warn_ms"]:    ev.add("WEB_DURATION_ANOMALY")
            if dns_s and float(dns_s)<TH["dns_sr_min"]:   ev.add("DNS_QUERY_FAILURE")
            if vpn and float(vpn)<TH["vpn_low_pct"]:      ev.add("LOW_VPN_RATE")
            ux_pts,ux_f=ux_score(mos_dl_s,mos_ul_s,jit,pl,http_dl_s,http_ul_s)
            if ux_pts>=TH["ux_severe"]: ev.add("UX_IMPACT_SEVERE")
            elif ux_pts>=TH["ux_moderate"]: ev.add("UX_IMPACT_MODERATE")

            all_ev|=ev; ts,hs=split_scores(ev); sev=severity(ts,hs)

            c1,c2=st.columns([3,1])
            with c2:
                st.markdown(f"**Severity:** {sev_html(sev)}", unsafe_allow_html=True)
                if ev: st.markdown(ev_html(ev), unsafe_allow_html=True)
                mh=mitre_html(ev)
                if mh: st.markdown(f"**MITRE:** {mh}", unsafe_allow_html=True)
                if ux_f:
                    st.caption("UX Impact")
                    for f in ux_f: st.caption(f"• {f}")
            with c1:
                st.markdown(f"""<div class="kpi-row">
                  <div class="kpi-card"><div class="kpi-label">VPN Session Rate</div><div class="kpi-value">{vpn or 'N/A'}%</div><div class="kpi-sub">Target ≥{TH['vpn_low_pct']}%</div></div>
                  <div class="kpi-card"><div class="kpi-label">Gateway Ping %</div><div class="kpi-value">{gw or 'N/A'}%</div><div class="kpi-sub">ARP/gateway integrity · Target ≥{TH['gateway_ping_min']}%</div></div>
                  <div class="kpi-card"><div class="kpi-label">Gateway Latency</div><div class="kpi-value">{gw_lat or 'N/A'} ms</div><div class="kpi-sub">Peak: {gw_lat_mx} ms</div></div>
                  <div class="kpi-card"><div class="kpi-label">DNS Success (sensor)</div><div class="kpi-value">{dns_s or 'N/A'}%</div><div class="kpi-sub">Min: {dns_mn}%</div></div>
                  <div class="kpi-card"><div class="kpi-label">Ping Success (sensor)</div><div class="kpi-value">{ping_s or 'N/A'}%</div><div class="kpi-sub">RTT: {rtt_s} ms</div></div>
                  <div class="kpi-card"><div class="kpi-label">Web Duration</div><div class="kpi-value">{wd or 'N/A'} ms</div><div class="kpi-sub">Peak: {wd_mx} ms · Proxy indicator >{TH['web_dur_warn_ms']:.0f}</div></div>
                  <div class="kpi-card"><div class="kpi-label">Upload Packet Loss</div><div class="kpi-value">{pl or 'N/A'}%</div><div class="kpi-sub">Elevated>{TH['pkt_loss_elevated']}% Severe>{TH['pkt_loss_severe']}%</div></div>
                  <div class="kpi-card"><div class="kpi-label">Upload Jitter</div><div class="kpi-value">{jit or 'N/A'} ms</div><div class="kpi-sub">High>{TH['jitter_high']} ms</div></div>
                  <div class="kpi-card"><div class="kpi-label">VoIP MOS DL (sensor)</div><div class="kpi-value">{mos_dl_s or 'N/A'}</div><div class="kpi-sub">Poor&lt;{TH['mos_poor']}</div></div>
                  <div class="kpi-card"><div class="kpi-label">HTTP DL Mbps (sensor)</div><div class="kpi-value">{http_dl_s or 'N/A'}</div><div class="kpi-sub">Low&lt;{TH['tput_low']}</div></div>
                  <div class="kpi-card"><div class="kpi-label">App Connectivity</div><div class="kpi-value">{ac or 'N/A'}%</div><div class="kpi-sub">Named app availability</div></div>
                  <div class="kpi-card"><div class="kpi-label">Air Time (sensor)</div><div class="kpi-value">{air_s or 'N/A'}%</div><div class="kpi-sub">TR062 sensor-side</div></div>
                </div>""", unsafe_allow_html=True)
            dc=fetch_agent(token,s,e,["GATEWAY_PING_CONNECTIVITY","WEB_CONNECTIVITY","VPN_CONNECTION","APPLICATION_CONNECTIVITY"],group_by="network",agg=["AVG","MIN"])
            df_c=to_df(dc,["GATEWAY_PING_CONNECTIVITY","WEB_CONNECTIVITY","VPN_CONNECTION","APPLICATION_CONNECTIVITY"])
            if not df_c.empty: st.caption("Connectivity by network"); st.dataframe(df_c,use_container_width=True,hide_index=True)
            xls["Connectivity"]=df_c if not df_c.empty else pd.DataFrame({"Metric":["VPN%","GW Ping%","GW Lat ms","Web Conn%","Web Dur ms","DNS SR%","Pkt Loss%","Jitter ms","MOS DL","HTTP DL","Air Time%"],"Value":[vpn,gw,gw_lat,wc,wd,dns_s,pl,jit,mos_dl_s,http_dl_s,air_s]})
        except Exception as ex:
            st.warning(f"Connectivity data unavailable: {ex}"); xls["Connectivity"]=pd.DataFrame()

    # ── S5: Composite Score ────────────────────────────────────────────────
    st.markdown('<div class="section-heading">5 · Composite Security Posture Score</div>', unsafe_allow_html=True)
    ts,hs=split_scores(all_ev); combined=score_ev(all_ev); final_sev=severity(ts,hs)
    posture=max(0,100-combined)
    color="#166534" if posture>=80 else ("#854d0e" if posture>=55 else "#991b1b")

    c1,c2=st.columns([1,2])
    with c1:
        st.markdown(f"""<div style="background:#fff;border:2px solid {color};border-radius:12px;padding:1.4rem;text-align:center;">
          <div style="font-size:.85rem;color:{MID_GREY};margin-bottom:6px;">Security Posture Score</div>
          <div style="font-size:3rem;font-weight:800;color:{color};">{posture}</div>
          <div style="font-size:.8rem;color:{MID_GREY};">/ 100 &nbsp;|&nbsp; {sev_html(final_sev)}</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"**Threat Score:** {ts} &nbsp;|&nbsp; **Health Score:** {hs} &nbsp;|&nbsp; **Evidence Score:** {combined}")
        if all_ev: st.markdown(f"**Evidence:** {ev_html(all_ev)}", unsafe_allow_html=True)
        mdf=mitre_df(all_ev)
        if not mdf.empty:
            st.markdown("**MITRE ATT&CK:**")
            st.dataframe(mdf,use_container_width=True,hide_index=True)
            xls["MITRE ATT&CK"]=mdf

    sdf=pd.DataFrame([{"Evidence":t,"Points":EP.get(t,0),"Category":"Threat" if t in THREAT_EV else "Health","MITRE":MITRE[t]["id"] if t in MITRE else ""} for t in sorted(all_ev,key=lambda x:EP.get(x,0),reverse=True)]) if all_ev else pd.DataFrame({"Status":["No evidence — posture clean."]})
    xls["Posture Score"]=sdf

    st.divider()
    xb=build_excel(xls,account,"Wireless Security Posture Assessment",sd,ed)
    st.download_button("📥 Download Posture Assessment (.xlsx)",data=xb,
        file_name=f"7SIGNAL_SecurityPosture_{account.replace(' ','_')}_{sd}_{ed}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        use_container_width=True)


# ═══════════════════════════════════════════════════════════════
# REPORT 2 — THREAT INDICATOR DIGEST
# ═══════════════════════════════════════════════════════════════

def report_digest(token, account, sd, ed):
    s, e = iso(sd), iso(ed, eod=True)
    st.markdown(f'<div class="report-header"><h1>⚠️ Wireless Threat Indicator Digest</h1>'
                f'<p>{account} &nbsp;|&nbsp; {sd} → {ed}</p></div>', unsafe_allow_html=True)

    all_flags: List[Dict] = []
    xls: Dict[str, pd.DataFrame] = {}

    # ── Cat1: Auth Anomalies ──────────────────────────────────────────────
    st.markdown('<div class="section-heading">Category 1 · Authentication Anomaly Events (Sensor)</div>', unsafe_allow_html=True)
    with st.spinner("Fetching auth anomaly data…"):
        try:
            d=fetch_sensor(token,s,e,["AC001","AC002","AC004","AC008","RA103","AV008","DN002","QURT007"],agg=["AVG","MIN","MAX","COUNT"])
            vv={"ac001":sv(d,"AC001"),"ac001_mn":sv(d,"AC001","min"),"ac002":sv(d,"AC002"),"ac002_mn":sv(d,"AC002","min"),
                "ac004":sv(d,"AC004"),"ac004_mx":sv(d,"AC004","max"),"ac008":sv(d,"AC008"),"ac008_mn":sv(d,"AC008","min"),
                "ra103":sv(d,"RA103"),"ra103_mn":sv(d,"RA103","min"),"av008":sv(d,"AV008"),"av008_mn":sv(d,"AV008","min"),
                "dn002":sv(d,"DN002"),"dn002_mn":sv(d,"DN002","min")}
            ev: Set[str]=set(); flags=[]
            def chk(val,thr,label,etag,up=False,extra=""):
                if val is None: return
                if (float(val)>thr if up else float(val)<thr):
                    ev.add(etag)
                    flags.append({"Category":"Auth","Finding":f"{label}: {val} ({'above' if up else 'below'} {thr}){' — '+extra if extra else ''}","Evidence":etag,"Severity":severity(*split_scores({etag}))})
            chk(vv["ac001"],TH["attach_sr_min"],"Attach success (AC001)","ATTACH_DEGRADED",extra=f"min: {vv['ac001_mn']}%")
            chk(vv["ac002"],TH["dhcp_sr_min"],"DHCP success (AC002)","DHCP_DEGRADED",extra=f"min: {vv['ac002_mn']}% — possible exhaustion")
            chk(vv["ac008"],TH["attach_sr_min"],"Association success (AC008)","ATTACH_DEGRADED",extra=f"min: {vv['ac008_mn']}%")
            chk(vv["ra103"],TH["eap_sr_min"],"EAP auth success (RA103)","AAA_DEGRADED",extra=f"min: {vv['ra103_mn']}%")
            chk(vv["av008_mn"],TH["beacon_avail_min"],"Beacon availability min (AV008)","ATTACH_DEGRADED",extra="AP beacon instability")
            chk(vv["dn002"],TH["dns_sr_min"],"DNS success (DN002)","DNS_DEGRADED",extra=f"min: {vv['dn002_mn']}%")
            chk(vv["ac004_mx"],TH["attach_ms_peak"],"Attach time peak (AC004)","ATTACH_TIME_PEAK",up=True,extra=f"avg: {vv['ac004']} ms")
            all_flags.extend(flags)
            ts,hs=split_scores(ev); sev=severity(ts,hs)
            if flags:
                for f in flags: st.warning(f"⚠️ [{f['Severity']}] {f['Finding']}")
            else:
                st.success("✅ No authentication anomaly thresholds exceeded.")
            if ev:
                st.markdown(f"**Evidence:** {ev_html(ev)} &nbsp; **Severity:** {sev_html(sev)}", unsafe_allow_html=True)
                mh=mitre_html(ev)
                if mh: st.markdown(f"**MITRE:** {mh}", unsafe_allow_html=True)
            d_ap=fetch_sensor_ap(token,s,e,["AC001","AC002","AC008","RA103","AV008","DN002","AC004"],agg=["AVG","MIN","MAX"])
            df_ap=to_df(d_ap,["AC001","AC002","AC008","RA103","AV008","DN002","AC004"])
            if not df_ap.empty: st.caption("Per-AP auth metrics"); st.dataframe(df_ap,use_container_width=True,hide_index=True)
            xls["Auth Anomalies"]=df_ap if not df_ap.empty else pd.DataFrame([{"KPI":k,"Value":v} for k,v in vv.items()])
        except Exception as ex:
            st.warning(f"Auth data unavailable: {ex}"); xls["Auth Anomalies"]=pd.DataFrame()

    # ── Cat2: Deauth & Frame Analysis ─────────────────────────────────────
    st.markdown('<div class="section-heading">Category 2 · Deauth Frame & Reason Code Analysis (Sensor)</div>', unsafe_allow_html=True)
    with st.spinner("Fetching deauth data…"):
        try:
            d=fetch_sensor(token,s,e,["TR126","TR127","TR124","TR112","TR116"],agg=["AVG","MAX","COUNT"])
            da_avg=sv(d,"TR126"); da_mx=sv(d,"TR126","max")
            dc_avg=sv(d,"TR127"); dc_mx=sv(d,"TR127","max")
            dis_avg=sv(d,"TR124"); dis_mx=sv(d,"TR124","max")
            ar=sv(d,"TR112","max"); asr=sv(d,"TR116","max")
            comb_mx=(float(da_mx or 0)+float(dc_mx or 0))
            sev_thr=TH["deauth_combined_peak"]*TH["deauth_severe_mult"]
            ext_thr=TH["deauth_combined_peak"]*TH["deauth_extreme_mult"]
            ev: Set[str]=set(); dflags=[]
            if comb_mx>=ext_thr:
                ev.add("DEAUTH_STORM_EXTREME")
                dflags.append({"Category":"Deauth","Finding":f"EXTREME deauth storm: {comb_mx:.0f}/min peak (>={ext_thr:.0f}) — automatic HIGH","Evidence":"DEAUTH_STORM_EXTREME","Severity":"HIGH"})
            elif comb_mx>=sev_thr:
                ev.add("DEAUTH_STORM_SEVERE")
                dflags.append({"Category":"Deauth","Finding":f"SEVERE deauth storm: {comb_mx:.0f}/min peak (>={sev_thr:.0f})","Evidence":"DEAUTH_STORM_SEVERE","Severity":"MED"})
            elif comb_mx>=TH["deauth_combined_peak"]:
                ev.add("DEAUTH_STORM")
                dflags.append({"Category":"Deauth","Finding":f"Deauth storm: {comb_mx:.0f}/min peak (>={TH['deauth_combined_peak']:.0f})","Evidence":"DEAUTH_STORM","Severity":"MED"})
            elif da_mx and float(da_mx)>=TH["deauth_managed_peak"]:
                ev.add("DEAUTH_STORM")
                dflags.append({"Category":"Deauth","Finding":f"AP→Client deauth peak: {da_mx:.0f}/min (threshold {TH['deauth_managed_peak']:.0f})","Evidence":"DEAUTH_STORM","Severity":"MED"})
            if ar and float(ar)>50:
                ev.add("AUTH_FLOOD_HEALTH")
                dflags.append({"Category":"Deauth","Finding":f"Auth request flood: {ar:.0f}/min peak","Evidence":"AUTH_FLOOD_HEALTH","Severity":"LOW"})
            all_flags.extend(dflags)
            d_sev="HIGH" if comb_mx>=ext_thr else("MED" if comb_mx>=sev_thr else("LOW" if comb_mx>=TH["deauth_combined_peak"] else "OK"))
            st.markdown(f"""<div class="kpi-row">
              <div class="kpi-card"><div class="kpi-label">Deauth AP avg (TR126)</div><div class="kpi-value">{da_avg or 'N/A'}/min</div><div class="kpi-sub">Peak: {da_mx}/min · Threshold: {TH['deauth_managed_peak']:.0f}</div></div>
              <div class="kpi-card"><div class="kpi-label">Deauth Client avg (TR127)</div><div class="kpi-value">{dc_avg or 'N/A'}/min</div><div class="kpi-sub">Peak: {dc_mx}/min · Threshold: {TH['deauth_client_peak']:.0f}</div></div>
              <div class="kpi-card"><div class="kpi-label">Combined deauth peak {sev_html(d_sev)}</div><div class="kpi-value">{comb_mx:.0f}/min</div><div class="kpi-sub">Severe@{sev_thr:.0f} Extreme@{ext_thr:.0f}</div></div>
              <div class="kpi-card"><div class="kpi-label">Disassoc peak (TR124)</div><div class="kpi-value">{dis_mx or 'N/A'}/min</div><div class="kpi-sub">Avg: {dis_avg}/min</div></div>
              <div class="kpi-card"><div class="kpi-label">Auth Req peak (TR112)</div><div class="kpi-value">{ar or 'N/A'}/min</div><div class="kpi-sub">Auth flood indicator</div></div>
            </div>""", unsafe_allow_html=True)
            if dflags:
                for f in dflags: st.warning(f"⚠️ [{f['Severity']}] {f['Finding']}")
            else:
                st.success("✅ No deauth storm thresholds exceeded.")
            if ev:
                st.markdown(f"**Evidence:** {ev_html(ev)}", unsafe_allow_html=True)
                mh=mitre_html(ev)
                if mh: st.markdown(f"**MITRE:** {mh}", unsafe_allow_html=True)

            with st.expander("802.11 Reason Code Reference"):
                rc_rows=[{"Code":c,"Meaning":RC_MEANING.get(c,f"Unknown code {c}"),"Classification":classify_rc(c)[0].upper(),"Action":"Investigate immediately" if classify_rc(c)[0] in ("attack","cipher","dos","mic","psk") else "Monitor" if classify_rc(c)[0]=="unknown" else "Normal"} for c in sorted(RC_MEANING.keys())]
                df_rc=pd.DataFrame(rc_rows)
                st.dataframe(df_rc,use_container_width=True,hide_index=True)
                xls["Reason Code Reference"]=df_rc
            xls["Deauth Analysis"]=pd.DataFrame({"Metric":["Deauth AP avg","Deauth AP peak","Deauth Cli avg","Deauth Cli peak","Combined peak","Disassoc avg","Disassoc peak","Auth Req peak"],"Value":[da_avg,da_mx,dc_avg,dc_mx,comb_mx,dis_avg,dis_mx,ar],"Threshold":[f"<{TH['deauth_managed_peak']:.0f}",f"<{TH['deauth_managed_peak']:.0f}",f"<{TH['deauth_client_peak']:.0f}",f"<{TH['deauth_client_peak']:.0f}",f"<{TH['deauth_combined_peak']:.0f}","N/A","N/A","<50"]})
        except Exception as ex:
            st.warning(f"Deauth data unavailable: {ex}"); xls["Deauth Analysis"]=pd.DataFrame()

    # ── Cat3: Rogue Risk ──────────────────────────────────────────────────
    st.markdown('<div class="section-heading">Category 3 · Rogue & Impersonation Risk (Agent)</div>', unsafe_allow_html=True)
    with st.spinner("Fetching rogue risk data…"):
        try:
            d=fetch_agent(token,s,e,["NUMBER_OF_CLOSER_ACCESS_POINTS","OVERALL_BEST_NEIGHBOR_SIGNAL_STRENGTH","SIGNAL_STRENGTH","STICKY_FACTOR","CLASSIC_STICKY_FACTOR","NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS","NUMBER_OF_CO_CHANNEL_OVERLAPPING_BSSIDS"],agg=["AVG","MAX"])
            cap=sv(d,"NUMBER_OF_CLOSER_ACCESS_POINTS"); cap_mx=sv(d,"NUMBER_OF_CLOSER_ACCESS_POINTS","max")
            bnr=sv(d,"OVERALL_BEST_NEIGHBOR_SIGNAL_STRENGTH"); conn=sv(d,"SIGNAL_STRENGTH")
            stk=sv(d,"STICKY_FACTOR"); stk_mx=sv(d,"STICKY_FACTOR","max")
            adj=sv(d,"NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS"); adj_mx=sv(d,"NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS","max")
            gap=round(float(bnr)-float(conn),1) if bnr and conn else None
            ev: Set[str]=set(); rflags=[]
            if cap and float(cap)>TH["closer_aps_warn"]:
                ev.add("CLOSER_APS_DETECTED")
                rflags.append({"Category":"Rogue","Finding":f"Avg {cap} APs closer than connected AP (max: {cap_mx}) — elevated evil twin risk","Evidence":"CLOSER_APS_DETECTED","Severity":severity(*split_scores({"CLOSER_APS_DETECTED"}))})
            if gap and gap>TH["rssi_gap_warn_db"]:
                ev.add("RSSI_GAP_DETECTED")
                rflags.append({"Category":"Rogue","Finding":f"Best neighbor RSSI is {gap} dBm stronger than connected AP — impersonation vulnerability","Evidence":"RSSI_GAP_DETECTED","Severity":severity(*split_scores({"RSSI_GAP_DETECTED"}))})
            if stk and float(stk)>TH["sticky_warn"]:
                ev.add("HIGH_STICKY_FACTOR")
                rflags.append({"Category":"Rogue","Finding":f"High sticky factor avg {stk} (max {stk_mx}) — devices won't roam away from rogue AP","Evidence":"HIGH_STICKY_FACTOR","Severity":"LOW"})
            if adj and float(adj)>TH["adj_bssids_warn"]:
                ev.add("HIGH_ADJ_BSSID_DENSITY")
                rflags.append({"Category":"Rogue","Finding":f"{adj} adjacent overlapping BSSIDs avg (max: {adj_mx}) — dense unmanaged RF environment","Evidence":"HIGH_ADJ_BSSID_DENSITY","Severity":"LOW"})
            all_flags.extend(rflags)
            ts,hs=split_scores(ev); sev=severity(ts,hs)
            if rflags:
                for f in rflags: st.warning(f"⚠️ [{f['Severity']}] {f['Finding']}")
            else:
                st.success("✅ No rogue or impersonation risk thresholds exceeded.")
            if ev:
                st.markdown(f"**Evidence:** {ev_html(ev)} &nbsp; **Severity:** {sev_html(sev)}", unsafe_allow_html=True)
                mh=mitre_html(ev)
                if mh: st.markdown(f"**MITRE:** {mh}", unsafe_allow_html=True)
            dl=fetch_agent(token,s,e,["NUMBER_OF_CLOSER_ACCESS_POINTS","SIGNAL_STRENGTH","STICKY_FACTOR"],group_by="locationId",agg=["AVG","MAX"])
            df_l=to_df(dl,["NUMBER_OF_CLOSER_ACCESS_POINTS","SIGNAL_STRENGTH","STICKY_FACTOR"])
            if not df_l.empty: st.caption("Rogue risk by location"); st.dataframe(df_l,use_container_width=True,hide_index=True)
            xls["Rogue Risk"]=df_l if not df_l.empty else pd.DataFrame({"Indicator":["Closer APs avg","Closer APs max","RSSI Gap dBm","Sticky avg","Sticky max","Adj BSSIDs avg","Adj BSSIDs max"],"Value":[cap,cap_mx,gap,stk,stk_mx,adj,adj_mx]})
        except Exception as ex:
            st.warning(f"Rogue risk unavailable: {ex}"); xls["Rogue Risk"]=pd.DataFrame()

    # ── Cat4: Client Behavior & UX ────────────────────────────────────────
    st.markdown('<div class="section-heading">Category 4 · Client Behavior & UX Impact (Agent + Sensor)</div>', unsafe_allow_html=True)
    with st.spinner("Fetching client behavior / UX data…"):
        try:
            da=fetch_agent(token,s,e,["RF_PROBLEM","CHANNEL_UTILIZATION","CONGESTION","NOISE","INTERFERENCE","MOS_UPLOAD_PACKET_LOSS","MOS_UPLOAD_JITTER","MOS_UPLOAD","CO_CHANNEL_INTERFERENCE","ADJACENT_CHANNEL_INTERFERENCE"],agg=["AVG","MAX"])
            ds=fetch_sensor(token,s,e,["QUAP005","QUAP006","QUAP008","QUAP009","QURT004","QURS002","QURS004","QURS007","TR062"],agg=["AVG","MIN","MAX"])
            cu=sv(da,"CHANNEL_UTILIZATION"); cu_mx=sv(da,"CHANNEL_UTILIZATION","max")
            noise=sv(da,"NOISE"); pl=sv(da,"MOS_UPLOAD_PACKET_LOSS"); pl_mx=sv(da,"MOS_UPLOAD_PACKET_LOSS","max")
            jit=sv(da,"MOS_UPLOAD_JITTER"); mos=sv(da,"MOS_UPLOAD"); cong=sv(da,"CONGESTION")
            mos_dl_s=sv(ds,"QUAP005"); mos_ul_s=sv(ds,"QUAP006"); http_dl_s=sv(ds,"QUAP008"); http_ul_s=sv(ds,"QUAP009")
            rtt_s=sv(ds,"QURT004"); sig_s=sv(ds,"QURS002"); ap_ret_s=sv(ds,"QURS004"); cli_ret_s=sv(ds,"QURS007"); air_s=sv(ds,"TR062")
            ev: Set[str]=set(); cflags=[]
            if cu and float(cu)>TH["airtime_avg"]:
                ev.add("RF_CONGESTION")
                cflags.append({"Category":"Client","Finding":f"Channel utilization avg {cu}% (peak {cu_mx}%) — possible jamming off-hours","Evidence":"RF_CONGESTION","Severity":"LOW"})
            if noise and float(noise)>-85:
                ev.add("RF_CONGESTION")
                cflags.append({"Category":"Client","Finding":f"RF noise floor {noise} dBm — elevated noise can mask rogue activity","Evidence":"RF_CONGESTION","Severity":"LOW"})
            ux_pts,ux_f=ux_score(mos_dl_s,mos_ul_s,jit,pl,http_dl_s,http_ul_s)
            if ux_pts>=TH["ux_severe"]:
                ev.add("UX_IMPACT_SEVERE")
                cflags.append({"Category":"Client","Finding":f"SEVERE UX impact (score {ux_pts}): {'; '.join(ux_f)}","Evidence":"UX_IMPACT_SEVERE","Severity":"MED"})
            elif ux_pts>=TH["ux_moderate"]:
                ev.add("UX_IMPACT_MODERATE")
                cflags.append({"Category":"Client","Finding":f"Moderate UX impact (score {ux_pts}): {'; '.join(ux_f)}","Evidence":"UX_IMPACT_MODERATE","Severity":"LOW"})
            all_flags.extend(cflags)
            ts,hs=split_scores(ev); sev=severity(ts,hs)
            st.markdown(f"""<div class="kpi-row">
              <div class="kpi-card"><div class="kpi-label">Channel Utilization avg</div><div class="kpi-value">{cu or 'N/A'}%</div><div class="kpi-sub">Peak: {cu_mx}% · Threshold: {TH['airtime_avg']}%</div></div>
              <div class="kpi-card"><div class="kpi-label">Upload Packet Loss avg</div><div class="kpi-value">{pl or 'N/A'}%</div><div class="kpi-sub">Peak: {pl_mx}% · Severe>{TH['pkt_loss_severe']}%</div></div>
              <div class="kpi-card"><div class="kpi-label">Upload Jitter avg</div><div class="kpi-value">{jit or 'N/A'} ms</div><div class="kpi-sub">High>{TH['jitter_high']} ms</div></div>
              <div class="kpi-card"><div class="kpi-label">Upload MOS</div><div class="kpi-value">{mos or 'N/A'}</div><div class="kpi-sub">Poor&lt;{TH['mos_poor']}</div></div>
              <div class="kpi-card"><div class="kpi-label">RF Noise Floor</div><div class="kpi-value">{noise or 'N/A'} dBm</div><div class="kpi-sub">Elevated &gt;-85 dBm</div></div>
              <div class="kpi-card"><div class="kpi-label">VoIP MOS DL (sensor)</div><div class="kpi-value">{mos_dl_s or 'N/A'}</div><div class="kpi-sub">Poor&lt;{TH['mos_poor']}</div></div>
              <div class="kpi-card"><div class="kpi-label">VoIP MOS UL (sensor)</div><div class="kpi-value">{mos_ul_s or 'N/A'}</div><div class="kpi-sub">Poor&lt;{TH['mos_poor']}</div></div>
              <div class="kpi-card"><div class="kpi-label">HTTP DL Mbps (sensor)</div><div class="kpi-value">{http_dl_s or 'N/A'}</div><div class="kpi-sub">Low&lt;{TH['tput_low']} Mbps</div></div>
              <div class="kpi-card"><div class="kpi-label">UX Impact Score {sev_html(sev)}</div><div class="kpi-value">{ux_pts}</div><div class="kpi-sub">Moderate≥{int(TH['ux_moderate'])} Severe≥{int(TH['ux_severe'])}</div></div>
              <div class="kpi-card"><div class="kpi-label">Air Time (sensor TR062)</div><div class="kpi-value">{air_s or 'N/A'}%</div><div class="kpi-sub">Sensor-side</div></div>
            </div>""", unsafe_allow_html=True)
            if cflags:
                for f in cflags: st.warning(f"⚠️ [{f['Severity']}] {f['Finding']}")
            else:
                st.success("✅ No client behavior thresholds exceeded.")
            if ev: st.markdown(f"**Evidence:** {ev_html(ev)}", unsafe_allow_html=True)
            dcn=fetch_agent(token,s,e,["CHANNEL_UTILIZATION","MOS_UPLOAD_PACKET_LOSS","NOISE","RF_PROBLEM"],group_by="network",agg=["AVG","MAX"])
            df_cn=to_df(dcn,["CHANNEL_UTILIZATION","MOS_UPLOAD_PACKET_LOSS","NOISE","RF_PROBLEM"])
            if not df_cn.empty: st.caption("Client behavior by network"); st.dataframe(df_cn,use_container_width=True,hide_index=True)
            xls["Client & UX"]=df_cn if not df_cn.empty else pd.DataFrame({"Metric":["Ch Util avg%","Ch Util max%","Pkt Loss avg%","Pkt Loss max%","Jitter ms","MOS Upload","Noise dBm","UX Score","VoIP MOS DL","VoIP MOS UL","HTTP DL","HTTP UL","Ping RTT","AP Retries","Cli Retries","Air Time%"],"Value":[cu,cu_mx,pl,pl_mx,jit,mos,noise,ux_pts,mos_dl_s,mos_ul_s,http_dl_s,http_ul_s,rtt_s,ap_ret_s,cli_ret_s,air_s]})
        except Exception as ex:
            st.warning(f"Client/UX data unavailable: {ex}"); xls["Client & UX"]=pd.DataFrame()

    # ── Threat Summary ────────────────────────────────────────────────────
    st.markdown('<div class="section-heading">Threat Indicator Summary</div>', unsafe_allow_html=True)
    if all_flags:
        df_f=pd.DataFrame(all_flags)
        sr={"HIGH":3,"MED":2,"LOW":1,"OK":0}
        df_f["_r"]=df_f["Severity"].map(sr).fillna(0)
        df_f=df_f.sort_values("_r",ascending=False).drop(columns="_r")
        st.dataframe(df_f,use_container_width=True,hide_index=True)
        xls["Threat Summary"]=df_f
        all_ev_c: Set[str]={f["Evidence"] for f in all_flags}
        mdf=mitre_df(all_ev_c)
        if not mdf.empty:
            st.markdown("**MITRE ATT&CK techniques observed:**")
            st.dataframe(mdf,use_container_width=True,hide_index=True)
            xls["MITRE ATT&CK"]=mdf
    else:
        st.success("✅ No threat indicators flagged for this period.")
        xls["Threat Summary"]=pd.DataFrame({"Status":["No threat indicators flagged."]})

    st.divider()
    xb=build_excel(xls,account,"Wireless Threat Indicator Digest",sd,ed)
    st.download_button("📥 Download Threat Digest (.xlsx)",data=xb,
        file_name=f"7SIGNAL_ThreatDigest_{account.replace(' ','_')}_{sd}_{ed}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        use_container_width=True)


# ═══════════════════════════════════════════════════════════════
# SIDEBAR & MAIN
# ═══════════════════════════════════════════════════════════════

with st.sidebar:
    try:
        st.image("https://7signal.com/wp-content/uploads/2022/08/7SIGNAL-logo.png", use_container_width=True)
    except Exception:
        st.markdown("### 7SIGNAL")
    st.markdown("### Report Configuration")
    account_name  = st.text_input("Account Name",  placeholder="Acme Corporation")
    client_id     = st.text_input("Client ID",      placeholder="your-client-id")
    client_secret = st.text_input("Client Secret",  placeholder="your-client-secret", type="password")
    st.markdown("---")
    st.markdown("**Report Period** *(max 30 days)*")
    today=date.today(); ded=today-timedelta(days=1); dsd=ded-timedelta(days=6)
    start_date=st.date_input("From",value=dsd,max_value=today)
    end_date=st.date_input("To",value=ded,max_value=today)
    delta=(end_date-start_date).days
    if delta>30: st.error("⛔ Maximum 30 days.")
    elif delta<0: st.error("⛔ End must be after start.")
    st.markdown("---")
    report_type=st.radio("Report Type",options=["🔒 Security Posture Assessment","⚠️  Threat Indicator Digest","📊 Both Reports"])
    cfg_ok="✅ wids_config.yaml loaded" if CFG else "ℹ️ Using built-in defaults"
    st.caption(cfg_ok)
    run_btn=st.button("▶ Generate Report",type="primary",use_container_width=True,
        disabled=(not account_name or not client_id or not client_secret or delta>30 or delta<0))

if not run_btn:
    st.markdown("""
    <div style="text-align:center;padding:4rem 2rem;color:#6B7280;">
      <div style="font-size:3rem;">🔒</div>
      <h2 style="color:#1E2A3B;">7SIGNAL Wireless Security Reports</h2>
      <p>Enter credentials and date range in the sidebar, then click <strong>Generate Report</strong>.</p>
      <hr style="margin:2rem auto;width:60%;">
      <div style="display:flex;gap:2rem;justify-content:center;flex-wrap:wrap;text-align:left;max-width:720px;margin:auto;font-size:.9rem;">
        <div><strong>🔒 Posture Assessment</strong><br><small>Monthly · CISO / QBR ready<br>Evidence-scored · Composite posture score<br>MITRE ATT&amp;CK mapping</small></div>
        <div><strong>⚠️ Threat Digest</strong><br><small>Weekly · Security team operational<br>802.11 reason code taxonomy<br>Deauth storm detection · UX impact scoring</small></div>
      </div>
      <p style="font-size:.8rem;margin-top:2rem;color:#9ca3af;">Drop <code>wids_config.yaml</code> in the same folder to customise all thresholds.</p>
    </div>
    """, unsafe_allow_html=True)
else:
    with st.spinner("Authenticating with 7SIGNAL API…"):
        try:
            token=get_token(client_id,client_secret)
            st.success(f"✅ Authenticated — generating report for **{account_name}**")
        except Exception as ex:
            st.error(f"❌ Authentication failed: {ex}"); st.stop()
    if "Posture" in report_type or "Both" in report_type:
        report_posture(token,account_name,start_date,end_date)
    if "Threat" in report_type or "Both" in report_type:
        if "Both" in report_type: st.divider()
        report_digest(token,account_name,start_date,end_date)
