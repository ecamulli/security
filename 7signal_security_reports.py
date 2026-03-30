"""
7SIGNAL Wireless Security Reports
Generates two security reports using the 7SIGNAL API:
  1. Wireless Security Posture Assessment (Monthly)
  2. Wireless Threat Indicator Weekly Digest
"""

import io
import json
import requests
import streamlit as st
import pandas as pd
from datetime import date, timedelta, datetime, timezone

# ─────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="7SIGNAL Security Reports",
    page_icon="🔒",
    layout="wide",
)

# ─────────────────────────────────────────────────────────────
# 7SIGNAL brand colours (from brand guidelines)
# ─────────────────────────────────────────────────────────────
PRIMARY_RED  = "#E4002B"
DARK_NAVY    = "#1E2A3B"
MID_GREY     = "#6B7280"
LIGHT_BG     = "#F8F9FA"

st.markdown(f"""
<style>
  /* Header bar */
  .report-header {{
      background: {DARK_NAVY};
      color: #fff;
      padding: 1.2rem 1.6rem;
      border-radius: 8px;
      margin-bottom: 1.4rem;
  }}
  .report-header h1 {{ margin: 0; font-size: 1.6rem; }}
  .report-header p  {{ margin: 0.3rem 0 0; font-size: 0.9rem; color: #c0c8d4; }}

  /* Section headings inside reports */
  .section-heading {{
      font-size: 1.05rem;
      font-weight: 700;
      color: {DARK_NAVY};
      border-left: 4px solid {PRIMARY_RED};
      padding-left: 0.6rem;
      margin: 1.2rem 0 0.6rem;
  }}

  /* KPI cards */
  .kpi-row {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 1rem; }}
  .kpi-card {{
      background: #fff;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 0.8rem 1.1rem;
      min-width: 160px;
      flex: 1;
  }}
  .kpi-label  {{ font-size: 0.75rem; color: {MID_GREY}; margin-bottom: 4px; }}
  .kpi-value  {{ font-size: 1.4rem; font-weight: 700; color: {DARK_NAVY}; }}
  .kpi-sub    {{ font-size: 0.72rem; color: {MID_GREY}; }}

  /* Status badges */
  .badge-good    {{ background:#dcfce7; color:#166534; border-radius:4px; padding:2px 8px; font-size:0.78rem; font-weight:600; }}
  .badge-warn    {{ background:#fef9c3; color:#854d0e; border-radius:4px; padding:2px 8px; font-size:0.78rem; font-weight:600; }}
  .badge-bad     {{ background:#fee2e2; color:#991b1b; border-radius:4px; padding:2px 8px; font-size:0.78rem; font-weight:600; }}
  .badge-neutral {{ background:#e2e8f0; color:#374151; border-radius:4px; padding:2px 8px; font-size:0.78rem; font-weight:600; }}

  /* Sidebar inputs */
  .stTextInput > div > div > input {{ border-radius: 6px; }}
  .stDateInput  > div > div > input {{ border-radius: 6px; }}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# ── API helpers ──────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────
BASE_URL = "https://api-v2.7signal.com"

@st.cache_data(ttl=300, show_spinner=False)
def get_token(client_id: str, client_secret: str) -> str:
    """Exchange client credentials for a bearer token (OAuth2 form-encoded)."""
    url = f"{BASE_URL}/oauth2/token"
    payload = {
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
    }
    # OAuth2 token endpoints require application/x-www-form-urlencoded, not JSON
    r = requests.post(url, data=payload, timeout=15)
    r.raise_for_status()
    return r.json()["access_token"]


def api_get(token: str, path: str, params: dict = None) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{BASE_URL}{path}", headers=headers, params=params, timeout=30)
    r.raise_for_status()
    return r.json()


def api_post(token: str, path: str, body: dict) -> dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }
    r = requests.post(f"{BASE_URL}{path}", headers=headers, json=body, timeout=30)
    r.raise_for_status()
    return r.json()


def iso(d: date, end_of_day: bool = False) -> str:
    if end_of_day:
        return datetime(d.year, d.month, d.day, 23, 59, 59,
                        tzinfo=timezone.utc).isoformat()
    return datetime(d.year, d.month, d.day, 0, 0, 0,
                    tzinfo=timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────
# ── Data-fetch helpers ────────────────────────────────────────
# ─────────────────────────────────────────────────────────────

def fetch_agent_numeric(token, start_dt, end_dt, metrics, group_by=None,
                         agg=None):
    """Summary (no time-bucket) numeric agent data."""
    if agg is None:
        agg = ["AVG", "MIN", "MAX", "COUNT"]
    body = {
        "start":              start_dt,
        "end":                end_dt,
        "metrics":            metrics,
        "aggregate_functions": agg,
    }
    if group_by:
        body["group_by_dimension"] = group_by
    return api_post(token, "/v2/agents/time-series/numeric/summary", body)


def fetch_agent_discrete(token, start_dt, end_dt, metrics, group_by,
                          time_bucket="1_DAY", agg=None):
    """Time-bucketed discrete agent data."""
    if agg is None:
        agg = ["MODE", "COUNT"]
    body = {
        "start":               start_dt,
        "end":                 end_dt,
        "metrics":             metrics,
        "group_by_dimension":  group_by,
        "time_bucket":         time_bucket,
        "aggregate_functions": agg,
    }
    return api_post(token, "/v2/agents/time-series/discrete", body)


def fetch_sensor_numeric(token, start_dt, end_dt, metrics, group_by=None,
                          agg=None):
    """Summary (no time-bucket) numeric sensor data."""
    if agg is None:
        agg = ["AVG", "MIN", "MAX", "COUNT"]
    body = {
        "start":               start_dt,
        "end":                 end_dt,
        "metrics":             metrics,
        "aggregate_functions": agg,
    }
    if group_by:
        body["group_by_dimension"] = group_by
    return api_post(token, "/v2/sensors/time-series/numeric/summary", body)


def fetch_sensor_by_ap(token, start_dt, end_dt, metrics, agg=None):
    """Sensor data grouped by access point."""
    if agg is None:
        agg = ["AVG", "MIN", "MAX", "COUNT"]
    body = {
        "start":               start_dt,
        "end":                 end_dt,
        "metrics":             metrics,
        "group_by_dimension":  "accessPoint",
        "aggregate_functions": agg,
    }
    return api_post(token, "/v2/sensors/time-series/numeric/summary", body)


# ─────────────────────────────────────────────────────────────
# ── Utility: safe extraction from API results ─────────────────
# ─────────────────────────────────────────────────────────────

def safe_val(data: dict, metric: str, agg_key: str = "avg",
             default=None, precision: int = 1):
    """Pull a single aggregated value from a summary response."""
    try:
        rows = data.get("data") or data.get("results") or []
        if not rows:
            # flat structure
            val = (data.get(metric, {}) or {}).get(agg_key)
            return round(val, precision) if val is not None else default

        # single-row summary
        row = rows[0] if isinstance(rows, list) else rows
        val = (row.get(metric, {}) or {}).get(agg_key)
        return round(val, precision) if val is not None else default
    except Exception:
        return default


def rows_to_df(data: dict, metrics: list) -> pd.DataFrame:
    """Convert a grouped summary response into a flat DataFrame."""
    try:
        rows = data.get("data") or data.get("results") or []
        if not rows:
            return pd.DataFrame()
        records = []
        for row in rows:
            record = {"group": row.get("groupValue") or row.get("label", "—")}
            for m in metrics:
                m_data = row.get(m) or {}
                record[f"{m}_avg"] = m_data.get("avg")
                record[f"{m}_min"] = m_data.get("min")
                record[f"{m}_max"] = m_data.get("max")
                record[f"{m}_count"] = m_data.get("count")
            records.append(record)
        return pd.DataFrame(records)
    except Exception:
        return pd.DataFrame()


def status_badge(value, good_thresh, bad_thresh, higher_is_better=True,
                 suffix="") -> str:
    """Return an HTML badge string for a metric value."""
    if value is None:
        return '<span class="badge-neutral">N/A</span>'
    v = float(value)
    label = f"{v:.1f}{suffix}"
    if higher_is_better:
        cls = "badge-good" if v >= good_thresh else (
              "badge-warn" if v >= bad_thresh else "badge-bad")
    else:
        cls = "badge-good" if v <= good_thresh else (
              "badge-warn" if v <= bad_thresh else "badge-bad")
    return f'<span class="{cls}">{label}</span>'


# ─────────────────────────────────────────────────────────────
# ── Excel export helper ───────────────────────────────────────
# ─────────────────────────────────────────────────────────────

def build_excel(sheets: dict, account_name: str, report_title: str,
                start_date: date, end_date: date) -> bytes:
    """
    sheets = { "Sheet Name": pd.DataFrame, ... }
    Returns bytes of an .xlsx file.
    """
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="xlsxwriter") as writer:
        wb = writer.book

        # Formats
        hdr_fmt  = wb.add_format({"bold": True, "bg_color": "#1E2A3B",
                                   "font_color": "#FFFFFF", "border": 1})
        meta_fmt = wb.add_format({"bold": True, "font_size": 11})
        pct_fmt  = wb.add_format({"num_format": "0.0%"})
        num_fmt  = wb.add_format({"num_format": "0.0"})
        date_fmt = wb.add_format({"num_format": "yyyy-mm-dd"})

        for sheet_name, df in sheets.items():
            if df is None or df.empty:
                df = pd.DataFrame({"Note": ["No data available for this period."]})

            df.to_excel(writer, sheet_name=sheet_name[:31], index=False,
                        startrow=5)
            ws = writer.sheets[sheet_name[:31]]

            # Meta block
            ws.write("A1", "Account:",      meta_fmt)
            ws.write("B1", account_name)
            ws.write("A2", "Report:",       meta_fmt)
            ws.write("B2", report_title)
            ws.write("A3", "Period:",       meta_fmt)
            ws.write("B3", f"{start_date} → {end_date}")
            ws.write("A4", "Generated:",    meta_fmt)
            ws.write("B4", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))

            # Style header row (row index 5, 0-based)
            for col_num, col_name in enumerate(df.columns):
                ws.write(5, col_num, col_name, hdr_fmt)
                ws.set_column(col_num, col_num, max(len(str(col_name)) + 4, 14))

        # Cover sheet
        cover = wb.add_worksheet("Cover")
        cover.write("A1", "7SIGNAL Security Report", meta_fmt)
        cover.write("A2", f"Account: {account_name}")
        cover.write("A3", f"Report: {report_title}")
        cover.write("A4", f"Period: {start_date} → {end_date}")
        cover.write("A5",
                    f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")

    buf.seek(0)
    return buf.read()


# ─────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════
#  REPORT 1 — Wireless Security Posture Assessment
# ═══════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────

def render_posture_report(token: str, account_name: str,
                           start_date: date, end_date: date):
    s = iso(start_date)
    e = iso(end_date, end_of_day=True)

    st.markdown('<div class="report-header">'
                '<h1>🔒 Wireless Security Posture Assessment</h1>'
                f'<p>{account_name} &nbsp;|&nbsp; {start_date} → {end_date}</p>'
                '</div>', unsafe_allow_html=True)

    excel_sheets = {}

    # ── Section 1 ── Authentication & Access Control (Sensor) ─────────────
    st.markdown('<div class="section-heading">1 · Authentication & Access Control Health (Sensor)</div>',
                unsafe_allow_html=True)

    with st.spinner("Fetching sensor authentication data…"):
        try:
            sensor_auth = fetch_sensor_numeric(
                token, s, e,
                metrics=["AC001", "AC002", "AC004", "AC008",
                         "AC009", "RA103", "HC005", "HC006"],
                agg=["AVG", "MIN", "MAX", "COUNT"],
            )

            attach_sr  = safe_val(sensor_auth, "AC001", "avg")
            dhcp_sr    = safe_val(sensor_auth, "AC002", "avg")
            attach_ms  = safe_val(sensor_auth, "AC004", "avg")
            assoc_sr   = safe_val(sensor_auth, "AC008", "avg")
            assoc_ms   = safe_val(sensor_auth, "AC009", "avg")
            eap_sr     = safe_val(sensor_auth, "RA103", "avg")
            hc5        = safe_val(sensor_auth, "HC005", "avg")
            hc6        = safe_val(sensor_auth, "HC006", "avg")

            kpi_html = f"""
            <div class="kpi-row">
              <div class="kpi-card">
                <div class="kpi-label">Radio Attach Success</div>
                <div class="kpi-value">{attach_sr if attach_sr is not None else "N/A"}%</div>
                <div class="kpi-sub">Target ≥ 99%</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">DHCP Success Rate</div>
                <div class="kpi-value">{dhcp_sr if dhcp_sr is not None else "N/A"}%</div>
                <div class="kpi-sub">Target ≥ 99%</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Radio Attach Time</div>
                <div class="kpi-value">{attach_ms if attach_ms is not None else "N/A"} ms</div>
                <div class="kpi-sub">Avg over period</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">EAP Auth Success</div>
                <div class="kpi-value">{eap_sr if eap_sr is not None else "N/A"}%</div>
                <div class="kpi-sub">RADIUS health</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">HC005 Score</div>
                <div class="kpi-value">{hc5 if hc5 is not None else "N/A"}</div>
                <div class="kpi-sub">Connection success (Wi-Fi)</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">HC006 Score</div>
                <div class="kpi-value">{hc6 if hc6 is not None else "N/A"}</div>
                <div class="kpi-sub">Connection success (E2E)</div>
              </div>
            </div>"""
            st.markdown(kpi_html, unsafe_allow_html=True)

            # Per-AP breakdown
            sensor_auth_ap = fetch_sensor_by_ap(
                token, s, e,
                metrics=["AC001", "AC008", "RA103", "AC004"],
                agg=["AVG", "MIN", "COUNT"],
            )
            df_ap = rows_to_df(sensor_auth_ap,
                               ["AC001", "AC008", "RA103", "AC004"])
            if not df_ap.empty:
                df_ap.columns = df_ap.columns.str.replace(
                    "AC001_avg", "Attach SR %").str.replace(
                    "AC008_avg", "Assoc SR %").str.replace(
                    "RA103_avg", "EAP SR %").str.replace(
                    "AC004_avg", "Attach Time ms").str.replace(
                    "AC001_min", "Attach Min").str.replace(
                    "AC001_count", "Samples").str.replace(
                    "AC008_min", "Assoc Min").str.replace(
                    "AC008_count", "Assoc Samples").str.replace(
                    "RA103_min", "EAP Min").str.replace(
                    "RA103_count", "EAP Samples").str.replace(
                    "AC004_min", "Attach ms Min").str.replace(
                    "AC004_count", "Time Samples")
                st.dataframe(df_ap, use_container_width=True, hide_index=True)
                excel_sheets["Auth - Per AP"] = df_ap
            else:
                excel_sheets["Auth - Per AP"] = pd.DataFrame({
                    "Metric": ["Attach SR", "DHCP SR", "EAP SR",
                               "Attach Time ms", "HC005", "HC006"],
                    "Value":  [attach_sr, dhcp_sr, eap_sr,
                               attach_ms, hc5, hc6],
                })
        except Exception as ex:
            st.warning(f"Authentication data unavailable: {ex}")
            excel_sheets["Auth - Per AP"] = pd.DataFrame()

    # ── Section 2 ── Rogue & Neighbor Exposure (Agent) ────────────────────
    st.markdown('<div class="section-heading">2 · Rogue & Neighbor Device Exposure (Agent)</div>',
                unsafe_allow_html=True)

    with st.spinner("Fetching neighbor exposure data…"):
        try:
            agent_neighbor = fetch_agent_numeric(
                token, s, e,
                metrics=[
                    "NUMBER_OF_CLOSER_ACCESS_POINTS",
                    "NUMBER_OF_CLOSER_ACCESS_POINTS_PREFERRED_BAND",
                    "NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS",
                    "NUMBER_OF_CO_CHANNEL_OVERLAPPING_BSSIDS",
                    "OVERALL_BEST_NEIGHBOR_SIGNAL_STRENGTH",
                    "SIGNAL_STRENGTH",
                    "STICKY_FACTOR",
                    "CLASSIC_STICKY_FACTOR",
                ],
                agg=["AVG", "MAX", "COUNT"],
            )

            closer_aps    = safe_val(agent_neighbor, "NUMBER_OF_CLOSER_ACCESS_POINTS", "avg")
            adj_overlap   = safe_val(agent_neighbor, "NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS", "avg")
            co_overlap    = safe_val(agent_neighbor, "NUMBER_OF_CO_CHANNEL_OVERLAPPING_BSSIDS", "avg")
            best_nbr_rssi = safe_val(agent_neighbor, "OVERALL_BEST_NEIGHBOR_SIGNAL_STRENGTH", "avg")
            conn_rssi     = safe_val(agent_neighbor, "SIGNAL_STRENGTH", "avg")
            sticky        = safe_val(agent_neighbor, "STICKY_FACTOR", "avg")
            classic_sticky = safe_val(agent_neighbor, "CLASSIC_STICKY_FACTOR", "avg")

            # Rogue exposure risk = devices where best-neighbor RSSI > connected RSSI
            rssi_gap = None
            if best_nbr_rssi is not None and conn_rssi is not None:
                rssi_gap = round(best_nbr_rssi - conn_rssi, 1)

            kpi_html = f"""
            <div class="kpi-row">
              <div class="kpi-card">
                <div class="kpi-label">Avg Closer APs</div>
                <div class="kpi-value">{closer_aps if closer_aps is not None else "N/A"}</div>
                <div class="kpi-sub">Evil twin exposure risk</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Adj. Overlapping BSSIDs</div>
                <div class="kpi-value">{adj_overlap if adj_overlap is not None else "N/A"}</div>
                <div class="kpi-sub">Unmanaged AP density</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Co-Channel BSSIDs</div>
                <div class="kpi-value">{co_overlap if co_overlap is not None else "N/A"}</div>
                <div class="kpi-sub">Interference + rogue risk</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Best Neighbor RSSI Gap</div>
                <div class="kpi-value">{('+' if rssi_gap and rssi_gap > 0 else '')}{rssi_gap if rssi_gap is not None else "N/A"} dBm</div>
                <div class="kpi-sub">+dBm = neighbor stronger than connected AP</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Sticky Factor</div>
                <div class="kpi-value">{sticky if sticky is not None else "N/A"}</div>
                <div class="kpi-sub">Higher = more roaming risk</div>
              </div>
            </div>"""
            st.markdown(kpi_html, unsafe_allow_html=True)

            # By network
            neighbor_by_net = fetch_agent_numeric(
                token, s, e,
                metrics=["NUMBER_OF_CLOSER_ACCESS_POINTS",
                         "NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS",
                         "STICKY_FACTOR"],
                group_by="network",
                agg=["AVG", "MAX"],
            )
            df_net = rows_to_df(neighbor_by_net,
                                ["NUMBER_OF_CLOSER_ACCESS_POINTS",
                                 "NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS",
                                 "STICKY_FACTOR"])
            if not df_net.empty:
                st.caption("Neighbor exposure by network")
                st.dataframe(df_net, use_container_width=True, hide_index=True)
                excel_sheets["Rogue Exposure by Network"] = df_net
            else:
                excel_sheets["Rogue Exposure Summary"] = pd.DataFrame({
                    "Metric": ["Avg Closer APs", "Adj Overlapping BSSIDs",
                               "Co-Channel BSSIDs", "RSSI Gap (dBm)",
                               "Sticky Factor"],
                    "Value":  [closer_aps, adj_overlap, co_overlap,
                               rssi_gap, sticky],
                })
        except Exception as ex:
            st.warning(f"Neighbor exposure data unavailable: {ex}")
            excel_sheets["Rogue Exposure by Network"] = pd.DataFrame()

    # ── Section 3 ── Protocol & Encryption Posture (Agent) ────────────────
    st.markdown('<div class="section-heading">3 · Protocol & Encryption Posture (Agent)</div>',
                unsafe_allow_html=True)

    with st.spinner("Fetching protocol posture data…"):
        try:
            # Wi-Fi standard distribution by network
            wifi_std = fetch_agent_discrete(
                token, s, e,
                metrics=["WIFI_STANDARD", "BAND"],
                group_by="network",
                time_bucket="1_DAY",
                agg=["MODE", "COUNT"],
            )

            # MCS index summary (numeric)
            mcs_data = fetch_agent_numeric(
                token, s, e,
                metrics=["SEVEN_MCS", "INTERFERENCE",
                         "CO_CHANNEL_INTERFERENCE",
                         "ADJACENT_CHANNEL_INTERFERENCE"],
                agg=["AVG", "MIN", "MAX"],
            )

            mcs_avg  = safe_val(mcs_data, "SEVEN_MCS", "avg")
            intf_avg = safe_val(mcs_data, "INTERFERENCE", "avg")
            co_intf  = safe_val(mcs_data, "CO_CHANNEL_INTERFERENCE", "avg")
            adj_intf = safe_val(mcs_data, "ADJACENT_CHANNEL_INTERFERENCE", "avg")

            kpi_html = f"""
            <div class="kpi-row">
              <div class="kpi-card">
                <div class="kpi-label">Avg MCS Index (7SIGNAL)</div>
                <div class="kpi-value">{mcs_avg if mcs_avg is not None else "N/A"}</div>
                <div class="kpi-sub">Low MCS = weak signal / legacy mode</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Overall Interference</div>
                <div class="kpi-value">{intf_avg if intf_avg is not None else "N/A"} dB</div>
                <div class="kpi-sub">Avg across period</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Co-Channel Interference</div>
                <div class="kpi-value">{co_intf if co_intf is not None else "N/A"} dB</div>
                <div class="kpi-sub">Same-channel conflict</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Adjacent Channel Interference</div>
                <div class="kpi-value">{adj_intf if adj_intf is not None else "N/A"} dB</div>
                <div class="kpi-sub">Adjacent channel bleed</div>
              </div>
            </div>"""
            st.markdown(kpi_html, unsafe_allow_html=True)

            # Try to show discrete data
            rows = wifi_std.get("data") or wifi_std.get("results") or []
            if rows:
                df_proto = pd.json_normalize(rows)
                st.caption("Wi-Fi standard & band distribution by network")
                st.dataframe(df_proto, use_container_width=True, hide_index=True)
                excel_sheets["Protocol Posture"] = df_proto
            else:
                excel_sheets["Protocol Posture"] = pd.DataFrame({
                    "Metric": ["Avg MCS", "Interference dB",
                               "Co-Channel dB", "Adjacent dB"],
                    "Value":  [mcs_avg, intf_avg, co_intf, adj_intf],
                })
        except Exception as ex:
            st.warning(f"Protocol posture data unavailable: {ex}")
            excel_sheets["Protocol Posture"] = pd.DataFrame()

    # ── Section 4 ── Network Segmentation & Connectivity (Agent) ──────────
    st.markdown('<div class="section-heading">4 · Network Segmentation & Connectivity Integrity (Agent)</div>',
                unsafe_allow_html=True)

    with st.spinner("Fetching connectivity integrity data…"):
        try:
            agent_conn = fetch_agent_numeric(
                token, s, e,
                metrics=[
                    "VPN_CONNECTION",
                    "GATEWAY_PING_CONNECTIVITY",
                    "GATEWAY_PING_LATENCY",
                    "WEB_CONNECTIVITY",
                    "WEB_DURATION",
                    "PING_CONNECTIVITY",
                    "PING_LATENCY",
                    "APPLICATION_CONNECTIVITY",
                    "MOS_UPLOAD_PACKET_LOSS",
                    "MOS_UPLOAD_JITTER",
                ],
                agg=["AVG", "MIN", "MAX", "COUNT"],
            )

            vpn_pct    = safe_val(agent_conn, "VPN_CONNECTION", "avg")
            gw_conn    = safe_val(agent_conn, "GATEWAY_PING_CONNECTIVITY", "avg")
            gw_lat     = safe_val(agent_conn, "GATEWAY_PING_LATENCY", "avg")
            web_conn   = safe_val(agent_conn, "WEB_CONNECTIVITY", "avg")
            web_dur    = safe_val(agent_conn, "WEB_DURATION", "avg")
            ping_conn  = safe_val(agent_conn, "PING_CONNECTIVITY", "avg")
            ping_lat   = safe_val(agent_conn, "PING_LATENCY", "avg")
            app_conn   = safe_val(agent_conn, "APPLICATION_CONNECTIVITY", "avg")
            pkt_loss   = safe_val(agent_conn, "MOS_UPLOAD_PACKET_LOSS", "avg")
            jitter     = safe_val(agent_conn, "MOS_UPLOAD_JITTER", "avg")

            kpi_html = f"""
            <div class="kpi-row">
              <div class="kpi-card">
                <div class="kpi-label">VPN Session Rate</div>
                <div class="kpi-value">{vpn_pct if vpn_pct is not None else "N/A"}%</div>
                <div class="kpi-sub">% sessions with VPN active</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Gateway Ping Success</div>
                <div class="kpi-value">{gw_conn if gw_conn is not None else "N/A"}%</div>
                <div class="kpi-sub">ARP / gateway integrity</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Gateway Latency</div>
                <div class="kpi-value">{gw_lat if gw_lat is not None else "N/A"} ms</div>
                <div class="kpi-sub">Avg RTT to gateway</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Web Connectivity</div>
                <div class="kpi-value">{web_conn if web_conn is not None else "N/A"}%</div>
                <div class="kpi-sub">HTTP success rate</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Web Duration</div>
                <div class="kpi-value">{web_dur if web_dur is not None else "N/A"} ms</div>
                <div class="kpi-sub">Avg page-load time</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Upload Packet Loss</div>
                <div class="kpi-value">{pkt_loss if pkt_loss is not None else "N/A"}%</div>
                <div class="kpi-sub">Jamming / interference proxy</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Upload Jitter</div>
                <div class="kpi-value">{jitter if jitter is not None else "N/A"} ms</div>
                <div class="kpi-sub">Traffic stability</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">App Connectivity</div>
                <div class="kpi-value">{app_conn if app_conn is not None else "N/A"}%</div>
                <div class="kpi-sub">Named app availability</div>
              </div>
            </div>"""
            st.markdown(kpi_html, unsafe_allow_html=True)

            # By network breakdown
            conn_by_net = fetch_agent_numeric(
                token, s, e,
                metrics=["GATEWAY_PING_CONNECTIVITY", "WEB_CONNECTIVITY",
                         "VPN_CONNECTION", "APPLICATION_CONNECTIVITY"],
                group_by="network",
                agg=["AVG", "MIN"],
            )
            df_cn = rows_to_df(conn_by_net,
                               ["GATEWAY_PING_CONNECTIVITY",
                                "WEB_CONNECTIVITY",
                                "VPN_CONNECTION",
                                "APPLICATION_CONNECTIVITY"])
            if not df_cn.empty:
                st.caption("Connectivity integrity by network")
                st.dataframe(df_cn, use_container_width=True, hide_index=True)
                excel_sheets["Connectivity by Network"] = df_cn
            else:
                excel_sheets["Connectivity Summary"] = pd.DataFrame({
                    "Metric": ["VPN Rate %", "GW Ping %", "GW Latency ms",
                               "Web Conn %", "Web Duration ms",
                               "Packet Loss %", "Jitter ms", "App Conn %"],
                    "Value":  [vpn_pct, gw_conn, gw_lat, web_conn,
                               web_dur, pkt_loss, jitter, app_conn],
                })
        except Exception as ex:
            st.warning(f"Connectivity data unavailable: {ex}")
            excel_sheets["Connectivity by Network"] = pd.DataFrame()

    # ── Section 5 ── Composite Security Posture Score ─────────────────────
    st.markdown('<div class="section-heading">5 · Composite Wireless Security Posture Score</div>',
                unsafe_allow_html=True)

    # Build a simple composite score from the KPIs we retrieved
    scores = {}
    try:
        # Auth health (weight 35%)
        auth_inputs = [v for v in [attach_sr, dhcp_sr, eap_sr, assoc_sr]
                       if v is not None]
        if auth_inputs:
            scores["Authentication Health"] = round(
                sum(auth_inputs) / len(auth_inputs), 1)

        # Neighbor/rogue risk (weight 25%) — invert: fewer closer APs = better
        if closer_aps is not None:
            raw = max(0, 100 - (float(closer_aps) * 10))
            scores["Rogue Exposure Risk"] = round(raw, 1)

        # Connectivity integrity (weight 25%)
        conn_inputs = [v for v in [gw_conn, web_conn, ping_conn, app_conn]
                       if v is not None]
        if conn_inputs:
            scores["Connectivity Integrity"] = round(
                sum(conn_inputs) / len(conn_inputs), 1)

        # Protocol posture (weight 15%) — based on MCS
        if mcs_avg is not None:
            # MCS 0-11 scale: map to 0-100
            scores["Protocol Posture"] = round(min(100, float(mcs_avg) * 9), 1)

    except Exception:
        pass

    if scores:
        weights = {
            "Authentication Health":   0.35,
            "Rogue Exposure Risk":     0.25,
            "Connectivity Integrity":  0.25,
            "Protocol Posture":        0.15,
        }
        composite = round(
            sum(scores.get(k, 0) * w for k, w in weights.items()), 1)

        cols = st.columns([1, 3])
        with cols[0]:
            color = ("#166534" if composite >= 85
                     else "#854d0e" if composite >= 65
                     else "#991b1b")
            st.markdown(f"""
            <div style="background:#fff;border:2px solid {color};border-radius:12px;
                        padding:1.4rem;text-align:center;">
              <div style="font-size:0.85rem;color:{MID_GREY};margin-bottom:6px;">
                Composite Security Score
              </div>
              <div style="font-size:3rem;font-weight:800;color:{color};">
                {composite}
              </div>
              <div style="font-size:0.8rem;color:{MID_GREY};">/ 100</div>
            </div>""", unsafe_allow_html=True)

        with cols[1]:
            score_df = pd.DataFrame([
                {"Component": k, "Score": v,
                 "Weight": f"{int(weights[k]*100)}%",
                 "Weighted": round(v * weights[k], 1)}
                for k, v in scores.items()
            ])
            st.dataframe(score_df, use_container_width=True, hide_index=True)
            excel_sheets["Posture Score"] = score_df
    else:
        st.info("Insufficient data to calculate composite score.")

    # ── Download button ────────────────────────────────────────────────────
    st.divider()
    excel_bytes = build_excel(
        excel_sheets, account_name,
        "Wireless Security Posture Assessment",
        start_date, end_date,
    )
    filename = (f"7SIGNAL_SecurityPosture_{account_name.replace(' ','_')}"
                f"_{start_date}_{end_date}.xlsx")
    st.download_button(
        label="📥 Download Posture Assessment (.xlsx)",
        data=excel_bytes,
        file_name=filename,
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        use_container_width=True,
    )


# ─────────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════
#  REPORT 2 — Wireless Threat Indicator Weekly Digest
# ═══════════════════════════════════════════════════════════════
# ─────────────────────────────────────────────────────────────

def render_threat_digest(token: str, account_name: str,
                          start_date: date, end_date: date):
    s = iso(start_date)
    e = iso(end_date, end_of_day=True)

    st.markdown('<div class="report-header">'
                '<h1>⚠️ Wireless Threat Indicator Digest</h1>'
                f'<p>{account_name} &nbsp;|&nbsp; {start_date} → {end_date}</p>'
                '</div>', unsafe_allow_html=True)

    excel_sheets = {}

    # ── Category 1 ── Authentication Anomaly Events (Sensor) ─────────────
    st.markdown('<div class="section-heading">Category 1 · Authentication Anomaly Events (Sensor)</div>',
                unsafe_allow_html=True)

    with st.spinner("Fetching authentication anomaly data…"):
        try:
            # Overall stats
            auth_summary = fetch_sensor_numeric(
                token, s, e,
                metrics=["AC001", "AC002", "AC004", "AC008",
                         "AC009", "RA103"],
                agg=["AVG", "MIN", "MAX", "COUNT"],
            )

            attach_sr  = safe_val(auth_summary, "AC001", "avg")
            attach_min = safe_val(auth_summary, "AC001", "min")
            dhcp_sr    = safe_val(auth_summary, "AC002", "avg")
            dhcp_min   = safe_val(auth_summary, "AC002", "min")
            attach_ms  = safe_val(auth_summary, "AC004", "avg")
            attach_max = safe_val(auth_summary, "AC004", "max")
            assoc_sr   = safe_val(auth_summary, "AC008", "avg")
            assoc_min  = safe_val(auth_summary, "AC008", "min")
            eap_sr     = safe_val(auth_summary, "RA103", "avg")
            eap_min    = safe_val(auth_summary, "RA103", "min")

            # Flag anomalies
            flags = []
            if attach_sr is not None and attach_sr < 97:
                flags.append(f"⚠️ Radio attach success {attach_sr}% (threshold: 97%) — "
                             f"minimum observed: {attach_min}%")
            if dhcp_sr is not None and dhcp_sr < 97:
                flags.append(f"⚠️ DHCP success rate {dhcp_sr}% — "
                             f"minimum: {dhcp_min}% (possible DHCP exhaustion)")
            if assoc_sr is not None and assoc_sr < 97:
                flags.append(f"⚠️ Radio association success {assoc_sr}% — "
                             f"minimum: {assoc_min}%")
            if eap_sr is not None and eap_sr < 95:
                flags.append(f"⚠️ EAP authentication success {eap_sr}% — "
                             f"RADIUS server health concern")
            if attach_ms is not None and attach_ms > 2000:
                flags.append(f"⚠️ Average attach time {attach_ms} ms — "
                             f"peak: {attach_max} ms (slow auth may indicate attack traffic)")

            if flags:
                for f in flags:
                    st.warning(f)
            else:
                st.success("✅ No authentication anomaly thresholds exceeded during this period.")

            # Per-AP table with anomaly highlighting
            ap_auth = fetch_sensor_by_ap(
                token, s, e,
                metrics=["AC001", "AC002", "AC008", "RA103", "AC004"],
                agg=["AVG", "MIN", "MAX", "COUNT"],
            )
            df_ap = rows_to_df(ap_auth,
                               ["AC001", "AC002", "AC008", "RA103", "AC004"])
            if not df_ap.empty:
                # Rename for clarity
                rename_map = {
                    "group":         "Access Point",
                    "AC001_avg":     "Attach SR % (avg)",
                    "AC001_min":     "Attach SR % (min)",
                    "AC002_avg":     "DHCP SR % (avg)",
                    "AC002_min":     "DHCP SR % (min)",
                    "AC008_avg":     "Assoc SR % (avg)",
                    "AC008_min":     "Assoc SR % (min)",
                    "RA103_avg":     "EAP SR % (avg)",
                    "RA103_min":     "EAP SR % (min)",
                    "AC004_avg":     "Attach Time ms (avg)",
                    "AC004_max":     "Attach Time ms (max)",
                    "AC001_count":   "Samples",
                }
                df_ap = df_ap.rename(columns=rename_map)
                # Drop unmapped columns
                df_ap = df_ap[[c for c in rename_map.values() if c in df_ap.columns]]
                st.caption("Authentication metrics per Access Point")
                st.dataframe(df_ap, use_container_width=True, hide_index=True)
                excel_sheets["Auth Anomalies per AP"] = df_ap
            else:
                excel_sheets["Auth Anomalies Summary"] = pd.DataFrame({
                    "Metric": ["Attach SR avg", "Attach SR min",
                               "DHCP SR avg", "DHCP SR min",
                               "EAP SR avg", "EAP SR min",
                               "Attach ms avg", "Attach ms max"],
                    "Value":  [attach_sr, attach_min, dhcp_sr, dhcp_min,
                               eap_sr, eap_min, attach_ms, attach_max],
                    "Flag":   [
                        "WARN" if attach_sr and attach_sr < 97 else "OK",
                        "—",
                        "WARN" if dhcp_sr and dhcp_sr < 97 else "OK",
                        "—",
                        "WARN" if eap_sr and eap_sr < 95 else "OK",
                        "—",
                        "WARN" if attach_ms and attach_ms > 2000 else "OK",
                        "—",
                    ],
                })
        except Exception as ex:
            st.warning(f"Auth anomaly data unavailable: {ex}")
            excel_sheets["Auth Anomalies per AP"] = pd.DataFrame()

    # ── Category 2 ── Rogue & Impersonation Risk (Agent) ──────────────────
    st.markdown('<div class="section-heading">Category 2 · Rogue & Impersonation Risk Indicators (Agent)</div>',
                unsafe_allow_html=True)

    with st.spinner("Fetching rogue risk data…"):
        try:
            rogue_data = fetch_agent_numeric(
                token, s, e,
                metrics=[
                    "NUMBER_OF_CLOSER_ACCESS_POINTS",
                    "NUMBER_OF_CLOSER_ACCESS_POINTS_PREFERRED_BAND",
                    "OVERALL_BEST_NEIGHBOR_SIGNAL_STRENGTH",
                    "SIGNAL_STRENGTH",
                    "BEST_NEIGHBOR_SIGNAL_STRENGTH",
                    "STICKY_FACTOR",
                    "CLASSIC_STICKY_FACTOR",
                    "NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS",
                    "NUMBER_OF_CO_CHANNEL_OVERLAPPING_BSSIDS",
                ],
                agg=["AVG", "MAX", "COUNT"],
            )

            closer_aps     = safe_val(rogue_data, "NUMBER_OF_CLOSER_ACCESS_POINTS", "avg")
            max_closer     = safe_val(rogue_data, "NUMBER_OF_CLOSER_ACCESS_POINTS", "max")
            best_nbr       = safe_val(rogue_data, "OVERALL_BEST_NEIGHBOR_SIGNAL_STRENGTH", "avg")
            conn_sig       = safe_val(rogue_data, "SIGNAL_STRENGTH", "avg")
            sticky         = safe_val(rogue_data, "STICKY_FACTOR", "avg")
            max_sticky     = safe_val(rogue_data, "STICKY_FACTOR", "max")
            adj_bssids     = safe_val(rogue_data, "NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS", "avg")
            max_adj        = safe_val(rogue_data, "NUMBER_OF_ADJACENT_OVERLAPPING_BSSIDS", "max")

            rssi_gap = None
            if best_nbr is not None and conn_sig is not None:
                rssi_gap = round(float(best_nbr) - float(conn_sig), 1)

            rogue_flags = []
            if closer_aps is not None and float(closer_aps) > 1:
                rogue_flags.append(
                    f"⚠️ Average {closer_aps} APs closer than connected AP "
                    f"(max seen: {max_closer}) — elevated evil twin risk at "
                    f"multiple locations")
            if rssi_gap is not None and rssi_gap > 5:
                rogue_flags.append(
                    f"⚠️ Best neighbor RSSI is {rssi_gap} dBm stronger than "
                    f"connected AP on average — devices may be vulnerable to "
                    f"stronger rogue AP impersonation")
            if sticky is not None and float(sticky) > 3:
                rogue_flags.append(
                    f"⚠️ High average sticky factor ({sticky}, max {max_sticky}) "
                    f"— sticky clients won't roam away from a compromised AP")
            if adj_bssids is not None and float(adj_bssids) > 10:
                rogue_flags.append(
                    f"⚠️ {adj_bssids} adjacent overlapping BSSIDs on average "
                    f"(max: {max_adj}) — dense unmanaged AP environment increases "
                    f"impersonation risk")

            if rogue_flags:
                for f in rogue_flags:
                    st.warning(f)
            else:
                st.success("✅ No rogue or impersonation risk thresholds exceeded.")

            # By location
            rogue_by_loc = fetch_agent_numeric(
                token, s, e,
                metrics=["NUMBER_OF_CLOSER_ACCESS_POINTS",
                         "SIGNAL_STRENGTH",
                         "STICKY_FACTOR"],
                group_by="locationId",
                agg=["AVG", "MAX"],
            )
            df_rl = rows_to_df(rogue_by_loc,
                               ["NUMBER_OF_CLOSER_ACCESS_POINTS",
                                "SIGNAL_STRENGTH", "STICKY_FACTOR"])
            if not df_rl.empty:
                st.caption("Rogue risk indicators by location")
                st.dataframe(df_rl, use_container_width=True, hide_index=True)
                excel_sheets["Rogue Risk by Location"] = df_rl
            else:
                excel_sheets["Rogue Risk Summary"] = pd.DataFrame({
                    "Indicator": ["Avg Closer APs", "Max Closer APs",
                                  "RSSI Gap (dBm)", "Avg Sticky Factor",
                                  "Max Sticky Factor",
                                  "Avg Adj BSSIDs", "Max Adj BSSIDs"],
                    "Value":     [closer_aps, max_closer, rssi_gap,
                                  sticky, max_sticky, adj_bssids, max_adj],
                })
        except Exception as ex:
            st.warning(f"Rogue risk data unavailable: {ex}")
            excel_sheets["Rogue Risk by Location"] = pd.DataFrame()

    # ── Category 3 ── Client Behavior Anomalies (Agent) ───────────────────
    st.markdown('<div class="section-heading">Category 3 · Client Behavior Anomalies (Agent)</div>',
                unsafe_allow_html=True)

    with st.spinner("Fetching client behavior data…"):
        try:
            client_data = fetch_agent_numeric(
                token, s, e,
                metrics=[
                    "RF_PROBLEM",
                    "CHANNEL_UTILIZATION",
                    "CONGESTION",
                    "NOISE",
                    "INTERFERENCE",
                    "MOS_UPLOAD_PACKET_LOSS",
                    "MOS_UPLOAD_JITTER",
                    "MOS_UPLOAD",
                ],
                agg=["AVG", "MAX", "COUNT"],
            )

            rf_prob    = safe_val(client_data, "RF_PROBLEM", "avg")
            ch_util    = safe_val(client_data, "CHANNEL_UTILIZATION", "avg")
            ch_util_mx = safe_val(client_data, "CHANNEL_UTILIZATION", "max")
            noise      = safe_val(client_data, "NOISE", "avg")
            pkt_loss   = safe_val(client_data, "MOS_UPLOAD_PACKET_LOSS", "avg")
            pkt_mx     = safe_val(client_data, "MOS_UPLOAD_PACKET_LOSS", "max")
            jitter     = safe_val(client_data, "MOS_UPLOAD_JITTER", "avg")
            mos        = safe_val(client_data, "MOS_UPLOAD", "avg")
            congestion = safe_val(client_data, "CONGESTION", "avg")

            client_flags = []
            if ch_util is not None and float(ch_util) > 75:
                client_flags.append(
                    f"⚠️ Channel utilization averaging {ch_util}% "
                    f"(peak: {ch_util_mx}%) — unusually high off-hours "
                    f"utilization can indicate jamming or unauthorized traffic")
            if pkt_loss is not None and float(pkt_loss) > 3:
                client_flags.append(
                    f"⚠️ Upload packet loss at {pkt_loss}% avg "
                    f"(peak: {pkt_mx}%) — consistent loss may indicate "
                    f"interference-based jamming, not just RF conditions")
            if noise is not None and float(noise) > -85:
                client_flags.append(
                    f"⚠️ RF noise floor at {noise} dBm — "
                    f"elevated noise can mask rogue device activity")
            if rf_prob is not None and float(rf_prob) > 5:
                client_flags.append(
                    f"⚠️ RF problem score: {rf_prob} — review AP-level "
                    f"RF health for physical interference sources")

            if client_flags:
                for f in client_flags:
                    st.warning(f)
            else:
                st.success("✅ No client behavior anomaly thresholds exceeded.")

            kpi_html = f"""
            <div class="kpi-row">
              <div class="kpi-card">
                <div class="kpi-label">Channel Utilization</div>
                <div class="kpi-value">{ch_util if ch_util is not None else "N/A"}%</div>
                <div class="kpi-sub">Peak: {ch_util_mx}%</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Upload Packet Loss</div>
                <div class="kpi-value">{pkt_loss if pkt_loss is not None else "N/A"}%</div>
                <div class="kpi-sub">Peak: {pkt_mx}%</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Jitter</div>
                <div class="kpi-value">{jitter if jitter is not None else "N/A"} ms</div>
                <div class="kpi-sub">Upload stream stability</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Upload MOS</div>
                <div class="kpi-value">{mos if mos is not None else "N/A"}</div>
                <div class="kpi-sub">Voice quality proxy</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">RF Noise Floor</div>
                <div class="kpi-value">{noise if noise is not None else "N/A"} dBm</div>
                <div class="kpi-sub">Lower = better coverage for threats</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Congestion</div>
                <div class="kpi-value">{congestion if congestion is not None else "N/A"}%</div>
                <div class="kpi-sub">Network congestion level</div>
              </div>
            </div>"""
            st.markdown(kpi_html, unsafe_allow_html=True)

            # By network
            client_by_net = fetch_agent_numeric(
                token, s, e,
                metrics=["CHANNEL_UTILIZATION", "MOS_UPLOAD_PACKET_LOSS",
                         "NOISE", "RF_PROBLEM"],
                group_by="network",
                agg=["AVG", "MAX"],
            )
            df_cn = rows_to_df(client_by_net,
                               ["CHANNEL_UTILIZATION",
                                "MOS_UPLOAD_PACKET_LOSS",
                                "NOISE", "RF_PROBLEM"])
            if not df_cn.empty:
                st.caption("Client behavior anomalies by network")
                st.dataframe(df_cn, use_container_width=True, hide_index=True)
                excel_sheets["Client Behavior by Network"] = df_cn
            else:
                excel_sheets["Client Behavior Summary"] = pd.DataFrame({
                    "Metric": ["Ch Util avg %", "Ch Util max %",
                               "Pkt Loss avg %", "Pkt Loss max %",
                               "Jitter ms", "MOS Upload",
                               "Noise dBm", "Congestion %"],
                    "Value":  [ch_util, ch_util_mx, pkt_loss, pkt_mx,
                               jitter, mos, noise, congestion],
                })
        except Exception as ex:
            st.warning(f"Client behavior data unavailable: {ex}")
            excel_sheets["Client Behavior by Network"] = pd.DataFrame()

    # ── Category 4 ── Connectivity Integrity Check (Agent + Sensor) ────────
    st.markdown('<div class="section-heading">Category 4 · Connectivity Integrity Check (Agent + Sensor)</div>',
                unsafe_allow_html=True)

    with st.spinner("Fetching connectivity integrity data…"):
        try:
            # Agent-side
            int_agent = fetch_agent_numeric(
                token, s, e,
                metrics=[
                    "GATEWAY_PING_CONNECTIVITY",
                    "GATEWAY_PING_LATENCY",
                    "PING_CONNECTIVITY",
                    "PING_LATENCY",
                    "WEB_CONNECTIVITY",
                    "WEB_DURATION",
                    "WEB_THROUGHPUT",
                    "APPLICATION_CONNECTIVITY",
                    "NETWORK_CONNECTIVITY",
                    "MOS_UPLOAD_PACKET_LOSS",
                ],
                agg=["AVG", "MIN", "MAX", "COUNT"],
            )

            # Sensor-side: DNS + ping
            int_sensor = fetch_sensor_numeric(
                token, s, e,
                metrics=["DN002", "QURT007", "QURT004", "HC005",
                         "HC006", "HC007", "HC008"],
                agg=["AVG", "MIN", "MAX"],
            )

            gw_conn   = safe_val(int_agent,  "GATEWAY_PING_CONNECTIVITY", "avg")
            gw_lat    = safe_val(int_agent,  "GATEWAY_PING_LATENCY", "avg")
            gw_lat_mx = safe_val(int_agent,  "GATEWAY_PING_LATENCY", "max")
            web_conn  = safe_val(int_agent,  "WEB_CONNECTIVITY", "avg")
            web_dur   = safe_val(int_agent,  "WEB_DURATION", "avg")
            web_dur_mx= safe_val(int_agent,  "WEB_DURATION", "max")
            net_conn  = safe_val(int_agent,  "NETWORK_CONNECTIVITY", "avg")
            pkt_loss  = safe_val(int_agent,  "MOS_UPLOAD_PACKET_LOSS", "avg")
            dns_sr    = safe_val(int_sensor, "DN002", "avg")
            dns_min   = safe_val(int_sensor, "DN002", "min")
            ping_sr   = safe_val(int_sensor, "QURT007", "avg")
            ping_rtt  = safe_val(int_sensor, "QURT004", "avg")
            hc7       = safe_val(int_sensor, "HC007", "avg")
            hc8       = safe_val(int_sensor, "HC008", "avg")

            # Integrity flags
            int_flags = []
            if gw_conn is not None and float(gw_conn) < 95:
                int_flags.append(
                    f"⚠️ Gateway ping success {gw_conn}% — intermittent "
                    f"gateway failures may indicate ARP poisoning or "
                    f"gateway spoofing")
            if dns_sr is not None and float(dns_sr) < 97:
                int_flags.append(
                    f"⚠️ DNS resolution success {dns_sr}% (min: {dns_min}%) "
                    f"— DNS failures could indicate poisoning or interception")
            if web_dur is not None and float(web_dur) > 3000:
                int_flags.append(
                    f"⚠️ Average web duration {web_dur} ms (peak: {web_dur_mx} ms) "
                    f"— high load time without throughput degradation may "
                    f"indicate DNS manipulation or transparent proxy insertion")
            if gw_lat is not None and float(gw_lat) > 50:
                int_flags.append(
                    f"⚠️ Gateway latency averaging {gw_lat} ms "
                    f"(peak: {gw_lat_mx} ms) — unusually high gateway RTT")

            if int_flags:
                for f in int_flags:
                    st.warning(f)
            else:
                st.success(
                    "✅ No connectivity integrity anomalies detected during this period.")

            kpi_html = f"""
            <div class="kpi-row">
              <div class="kpi-card">
                <div class="kpi-label">Gateway Ping %</div>
                <div class="kpi-value">{gw_conn if gw_conn is not None else "N/A"}%</div>
                <div class="kpi-sub">ARP / layer 3 integrity</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">DNS Success Rate</div>
                <div class="kpi-value">{dns_sr if dns_sr is not None else "N/A"}%</div>
                <div class="kpi-sub">Min: {dns_min}%</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Sensor Ping SR</div>
                <div class="kpi-value">{ping_sr if ping_sr is not None else "N/A"}%</div>
                <div class="kpi-sub">RTT avg: {ping_rtt} ms</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Web Connectivity</div>
                <div class="kpi-value">{web_conn if web_conn is not None else "N/A"}%</div>
                <div class="kpi-sub">HTTP reachability</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">Web Duration</div>
                <div class="kpi-value">{web_dur if web_dur is not None else "N/A"} ms</div>
                <div class="kpi-sub">Peak: {web_dur_mx} ms</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">HC007</div>
                <div class="kpi-value">{hc7 if hc7 is not None else "N/A"}</div>
                <div class="kpi-sub">Connection quality (E2E)</div>
              </div>
              <div class="kpi-card">
                <div class="kpi-label">HC008</div>
                <div class="kpi-value">{hc8 if hc8 is not None else "N/A"}</div>
                <div class="kpi-sub">Connection quality (Wi-Fi)</div>
              </div>
            </div>"""
            st.markdown(kpi_html, unsafe_allow_html=True)

            # Breakdown by network
            int_by_net = fetch_agent_numeric(
                token, s, e,
                metrics=["GATEWAY_PING_CONNECTIVITY",
                         "WEB_CONNECTIVITY", "WEB_DURATION",
                         "PING_LATENCY"],
                group_by="network",
                agg=["AVG", "MIN", "MAX"],
            )
            df_in = rows_to_df(int_by_net,
                               ["GATEWAY_PING_CONNECTIVITY",
                                "WEB_CONNECTIVITY",
                                "WEB_DURATION", "PING_LATENCY"])
            if not df_in.empty:
                st.caption("Connectivity integrity by network")
                st.dataframe(df_in, use_container_width=True, hide_index=True)
                excel_sheets["Connectivity Integrity by Net"] = df_in
            else:
                excel_sheets["Connectivity Integrity"] = pd.DataFrame({
                    "Metric": ["GW Ping %", "GW Latency ms",
                               "GW Latency peak ms",
                               "DNS SR %", "DNS min %",
                               "Sensor Ping SR %", "Ping RTT ms",
                               "Web Conn %", "Web Duration ms",
                               "HC007", "HC008"],
                    "Value":  [gw_conn, gw_lat, gw_lat_mx,
                               dns_sr, dns_min, ping_sr, ping_rtt,
                               web_conn, web_dur, hc7, hc8],
                })
        except Exception as ex:
            st.warning(f"Connectivity integrity data unavailable: {ex}")
            excel_sheets["Connectivity Integrity"] = pd.DataFrame()

    # ── Threat Summary Table ───────────────────────────────────────────────
    st.markdown('<div class="section-heading">Threat Indicator Summary</div>',
                unsafe_allow_html=True)

    all_flags = []
    try:
        # Collect all flagged items across categories
        for cat_label, flag_list in [
            ("Authentication Anomaly", rogue_flags if 'rogue_flags' in dir() else []),
            ("Rogue / Impersonation",  client_flags if 'client_flags' in dir() else []),
            ("Connectivity Integrity", int_flags if 'int_flags' in dir() else []),
        ]:
            for f in flag_list:
                all_flags.append({"Category": cat_label, "Finding": f})
    except Exception:
        pass

    if all_flags:
        df_flags = pd.DataFrame(all_flags)
        st.dataframe(df_flags, use_container_width=True, hide_index=True)
        excel_sheets["Threat Summary"] = df_flags
    else:
        st.success("✅ No threat indicators flagged for this period.")
        excel_sheets["Threat Summary"] = pd.DataFrame(
            {"Status": ["No threat indicators flagged for this period."]})

    # ── Download ──────────────────────────────────────────────────────────
    st.divider()
    excel_bytes = build_excel(
        excel_sheets, account_name,
        "Wireless Threat Indicator Digest",
        start_date, end_date,
    )
    filename = (f"7SIGNAL_ThreatDigest_{account_name.replace(' ','_')}"
                f"_{start_date}_{end_date}.xlsx")
    st.download_button(
        label="📥 Download Threat Digest (.xlsx)",
        data=excel_bytes,
        file_name=filename,
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        use_container_width=True,
    )


# ─────────────────────────────────────────────────────────────
# ── Sidebar ──────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────

with st.sidebar:
    st.image("https://7signal.com/wp-content/uploads/2022/08/7SIGNAL-logo.png",
             use_container_width=True)
    st.markdown("### Report Configuration")

    account_name  = st.text_input("Account Name", placeholder="Acme Corporation")
    client_id     = st.text_input("Client ID",     placeholder="your-client-id")
    client_secret = st.text_input("Client Secret", placeholder="your-client-secret",
                                   type="password")

    st.markdown("---")
    st.markdown("**Report Period**")

    today       = date.today()
    default_end = today - timedelta(days=1)
    default_start = default_end - timedelta(days=6)  # 7-day default

    start_date = st.date_input("From", value=default_start,
                                max_value=today)
    end_date   = st.date_input("To",   value=default_end,
                                max_value=today)

    # Enforce 30-day max
    delta = (end_date - start_date).days
    if delta > 30:
        st.error("⛔ Maximum report window is 30 days. Please adjust your dates.")
    elif delta < 0:
        st.error("⛔ End date must be after start date.")

    st.markdown("---")
    report_type = st.radio(
        "Report Type",
        options=[
            "🔒 Security Posture Assessment",
            "⚠️  Threat Indicator Digest",
            "📊 Both Reports",
        ],
    )

    run_btn = st.button("▶ Generate Report", type="primary",
                         use_container_width=True,
                         disabled=(not account_name or not client_id
                                   or not client_secret or delta > 30
                                   or delta < 0))

# ─────────────────────────────────────────────────────────────
# ── Main area ─────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────

if not run_btn:
    st.markdown("""
    <div style="text-align:center;padding:4rem 2rem;color:#6B7280;">
      <div style="font-size:3rem;">🔒</div>
      <h2 style="color:#1E2A3B;">7SIGNAL Wireless Security Reports</h2>
      <p>Enter your account credentials and date range in the sidebar,<br>
         then click <strong>Generate Report</strong>.</p>
      <hr style="margin:2rem auto;width:60%;">
      <div style="display:flex;gap:2rem;justify-content:center;flex-wrap:wrap;
                  text-align:left;max-width:700px;margin:auto;">
        <div>
          <strong>🔒 Security Posture Assessment</strong><br>
          <small>Monthly · CISO / QBR ready<br>
          Authentication health, rogue exposure,<br>
          protocol posture, composite score</small>
        </div>
        <div>
          <strong>⚠️ Threat Indicator Digest</strong><br>
          <small>Weekly · Security team operational<br>
          Auth anomalies, rogue indicators,<br>
          client behavior, connectivity integrity</small>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

else:
    # Authenticate
    with st.spinner("Authenticating with 7SIGNAL API…"):
        try:
            token = get_token(client_id, client_secret)
            st.success(f"✅ Authenticated — generating report for **{account_name}**")
        except Exception as ex:
            st.error(f"❌ Authentication failed: {ex}")
            st.stop()

    # Render selected report(s)
    if "Posture" in report_type or "Both" in report_type:
        render_posture_report(token, account_name, start_date, end_date)

    if "Threat" in report_type or "Both" in report_type:
        if "Both" in report_type:
            st.divider()
        render_threat_digest(token, account_name, start_date, end_date)
