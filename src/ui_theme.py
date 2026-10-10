"""TunnelScope presentation layer: shared LinkLens tokens and VPN-specific cyan accent."""
from __future__ import annotations


def theme_css(accent: str = "#70d4e2", mode: str = "dark") -> str:
    if mode.lower() == "light":
        values = {
            "bg": "#f5f8fb", "surface": "#ffffff", "surface2": "#eef3f7",
            "text": "#152333", "muted": "#526477", "border": "#dbe4ec",
            "accent": accent, "accent_text": "#07313a", "danger": "#b42332",
            "warn": "#9a6200", "ok": "#176a4a", "hero": "#e8f6f8",
        }
    else:
        values = {
            "bg": "#0b0d14", "surface": "#141824", "surface2": "#10131d",
            "text": "#f4f5fb", "muted": "#9ba3bb", "border": "#282d40",
            "accent": accent, "accent_text": "#071317", "danger": "#e06b75",
            "warn": "#e2b15a", "ok": "#6fbfa0", "hero": "#152a34",
        }
    return f"""
<style>
:root {{
  --ts-bg:{values['bg']}; --ts-card:{values['surface']}; --ts-panel:{values['surface2']};
  --ts-line:{values['border']}; --ts-text:{values['text']}; --ts-muted:{values['muted']};
  --ts-accent:{values['accent']}; --ts-accent-text:{values['accent_text']};
  --ts-danger:{values['danger']}; --ts-warn:{values['warn']}; --ts-ok:{values['ok']};
  --ts-hero:{values['hero']};
}}
html,body,[data-testid="stAppViewContainer"],.stApp {{
  background:var(--ts-bg); color:var(--ts-text);
  font-family:Inter,"Segoe UI",system-ui,sans-serif;
}}
[data-testid="stHeader"] {{ background:transparent; }}
#MainMenu,footer {{ visibility:hidden; }}
[data-testid="stSidebar"] {{ background:var(--ts-panel); border-right:1px solid var(--ts-line); }}
.block-container {{ max-width:1440px; padding:1.1rem 1.35rem 3rem; }}
h1,h2,h3 {{ letter-spacing:-.035em; }}
.ts-topbar {{ display:flex; align-items:center; gap:14px; border:1px solid var(--ts-line);
  background:var(--ts-panel); border-radius:14px; padding:12px 16px; margin-bottom:16px; }}
.ts-brand {{ font-size:.8rem; font-weight:850; letter-spacing:.15em; color:var(--ts-accent); }}
.ts-topnote {{ color:var(--ts-muted); font-size:.8rem; }}
.ts-local {{ margin-left:auto; color:var(--ts-ok); font-size:.72rem; letter-spacing:.1em; }}
.ts-hero {{ padding:28px 30px; border:1px solid var(--ts-line); border-radius:20px;
  background:radial-gradient(circle at 92% 8%,color-mix(in srgb,var(--ts-accent) 19%,transparent),transparent 38%),linear-gradient(135deg,var(--ts-hero),var(--ts-panel) 78%);
  margin:4px 0 18px; }}
.ts-eyebrow {{ font-size:.72rem; letter-spacing:.16em; text-transform:uppercase;
  color:var(--ts-accent); font-weight:800; }}
.ts-hero h1 {{ font-size:2.4rem; margin:.4rem 0; line-height:1.1; }}
.ts-hero p {{ color:var(--ts-muted); font-size:1.02rem; max-width:820px; margin:.35rem 0 0; }}
.ts-chip {{ display:inline-block; padding:4px 9px; border-radius:999px; border:1px solid var(--ts-line);
  font-size:.72rem; color:var(--ts-muted); margin:8px 6px 0 0; }}
.ts-card {{ background:var(--ts-card); border:1px solid var(--ts-line); border-radius:16px;
  padding:18px 20px; min-height:112px; }}
.ts-label {{ font-size:.72rem; color:var(--ts-muted); letter-spacing:.09em; text-transform:uppercase; }}
.ts-value {{ font-size:1.9rem; font-weight:750; margin:5px 0; line-height:1.15; }}
.ts-help {{ font-size:.82rem; color:var(--ts-muted); }}
.ts-section {{ border-bottom:1px solid var(--ts-line); padding-bottom:9px; margin:26px 0 14px; }}
.ts-note {{ border-left:3px solid var(--ts-accent); background:var(--ts-panel); border-radius:8px;
  padding:10px 13px; margin:8px 0 14px; }}
.ts-note.warn {{ border-left-color:var(--ts-warn); }}
.ts-note.danger {{ border-left-color:var(--ts-danger); }}
.ts-badge {{ display:inline-block; padding:4px 9px; border-radius:999px; border:1px solid var(--ts-line);
  font-size:.72rem; color:var(--ts-muted); margin-right:5px; }}
.ts-muted {{ color:var(--ts-muted); font-size:.82rem; }}
.ts-flow {{ display:flex; flex-wrap:wrap; gap:8px; margin:12px 0 22px; }}
.ts-flow span {{ flex:1; min-width:125px; border:1px solid var(--ts-line); background:var(--ts-panel);
  padding:12px; border-radius:12px; text-align:center; font-weight:650; }}
.ts-flow small {{ display:block; color:var(--ts-muted); font-weight:400; margin-top:4px; }}
.ts-step {{ display:flex; gap:12px; align-items:flex-start; padding:12px 0; border-bottom:1px solid var(--ts-line); }}
.ts-step b {{ color:var(--ts-accent); font-size:.8rem; min-width:24px; }}
.stButton>button,.stDownloadButton>button {{ border-radius:10px; border:1px solid var(--ts-line);
  font-weight:650; min-height:2.55rem; }}
.stButton>button[kind="primary"] {{ background:var(--ts-accent); color:var(--ts-accent-text); border-color:var(--ts-accent); }}
[data-testid="stMetric"] {{ background:var(--ts-card); border:1px solid var(--ts-line); border-radius:14px; padding:14px; }}
[data-testid="stAlert"] {{ border-radius:12px; }}
[data-testid="stFileUploader"] {{ border:1px dashed var(--ts-line); border-radius:14px; padding:8px; }}
[data-testid="stExpander"] {{ border:1px solid var(--ts-line); border-radius:12px; }}
div[data-testid="stDataFrame"],div[data-testid="stPlotlyChart"] {{ border:1px solid var(--ts-line); border-radius:14px; overflow:hidden; }}
[data-testid="stRadio"] label {{ font-size:.9rem; }}
hr {{ border-color:var(--ts-line); }}
@media(max-width:760px) {{
  .block-container {{ padding:1rem .8rem 2rem; }}
  .ts-hero {{ padding:22px 18px; }}
  .ts-hero h1 {{ font-size:1.8rem; }}
  .ts-local {{ display:none; }}
}}
</style>
"""
