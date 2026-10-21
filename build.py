#!/usr/bin/env python3
"""Build script for Young Vault — 读取 subjects.json（科目配置）和 passwords.json（密码，不进 git），
生成单文件 index.html。有密码的科目，内容用 AES-256-GCM 加密后再嵌入。"""

import base64
import json
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PBKDF2_ITER = 200_000


def load_json(name, default=None):
    path = os.path.join(BASE_DIR, name)
    if not os.path.exists(path):
        if default is not None:
            return default
        sys.exit(f"❌ 找不到 {name}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def encrypt_modules(contents, password):
    """contents: {module_id: html}，返回前端可解密的 {salt, iv, iter, data}（base64）。"""
    salt, iv = os.urandom(16), os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITER)
    key = kdf.derive(password.encode("utf-8"))
    plain = json.dumps(contents, ensure_ascii=False).encode("utf-8")
    data = AESGCM(key).encrypt(iv, plain, None)  # 密文 + 16 字节 tag，WebCrypto 同格式
    b64 = lambda b: base64.b64encode(b).decode()
    return {"salt": b64(salt), "iv": b64(iv), "iter": PBKDF2_ITER, "data": b64(data)}


SUBJECT_DEFS = load_json("subjects.json")
PASSWORDS = load_json("passwords.json", default={})

# 校验
errors, seen_ids = [], set()
for subj in SUBJECT_DEFS:
    if not subj.get("modules"):
        errors.append(f"科目 {subj['id']} 没有模块")
    for m in subj["modules"]:
        mid = m["file"].replace(".html", "")
        if mid in seen_ids:
            errors.append(f"模块 id 重复：{mid}")
        seen_ids.add(mid)
        if not os.path.exists(os.path.join(BASE_DIR, m["file"])):
            errors.append(f"文件不存在：{m['file']}")
for sid in PASSWORDS:
    if sid not in {s["id"] for s in SUBJECT_DEFS}:
        errors.append(f"passwords.json 里的科目 {sid} 不在 subjects.json 中")
if errors:
    sys.exit("❌ 校验失败：\n  - " + "\n  - ".join(errors))

subjects = []
for subj in SUBJECT_DEFS:
    mods, contents = [], {}
    for m in subj["modules"]:
        with open(os.path.join(BASE_DIR, m["file"]), "r", encoding="utf-8") as f:
            content = f.read()
        mid = m["file"].replace(".html", "")
        contents[mid] = content
        mods.append({
            "id": mid,
            "subject_id": subj["id"],
            "week": m["week"],
            "title": m["title"],
            "subtitle": m["subtitle"],
            "color": m["color"],
        })
    entry = {k: subj[k] for k in ("id", "code", "name", "desc", "accent")}
    pw = PASSWORDS.get(subj["id"])
    if pw:
        entry["enc"] = encrypt_modules(contents, pw)
    else:
        for mod in mods:
            mod["content"] = contents[mod["id"]]
    entry["modules"] = mods
    subjects.append(entry)

subjects_json = (json.dumps(subjects, ensure_ascii=False)
    .replace('</script>', r'<\/script>')
    .replace('</style>', r'<\/style>')
)

html = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Young Vault — Your Personal Study Hub</title>
<style>
:root {
  --accent: #6366f1;
  --bg: #f3f5fa;
  --surface: #ffffff;
  --surface-2: #f1f4fa;
  --surface-3: #e7ecf5;
  --line: #e2e8f1;
  --line-2: #d3dbe8;
  --text: #0f172a;
  --muted: #55627c;
  --faint: #8591a8;
  --accent-ink: color-mix(in srgb, var(--accent) 72%, #000);
  --accent-strong: color-mix(in srgb, var(--accent) 74%, #000);
  --shadow-sm: 0 1px 2px rgba(15,23,42,.06), 0 1px 1px rgba(15,23,42,.04);
  --shadow-md: 0 10px 28px -10px rgba(15,23,42,.16), 0 2px 6px rgba(15,23,42,.05);
  --shadow-lg: 0 28px 56px -18px rgba(15,23,42,.28);
  --ease: cubic-bezier(.22,.8,.24,1);
  /* 模块（common.css）使用的变量 */
  --color-text-primary: var(--text);
  --color-text-secondary: var(--muted);
  --color-text-tertiary: var(--faint);
  --color-text-info: #1d4ed8;
  --color-text-success: #15803d;
  --color-text-warning: #92400e;
  --color-text-danger: #991b1b;
  --color-background-primary: var(--surface);
  --color-background-secondary: var(--surface-2);
  --color-background-info: #eff6ff;
  --color-background-success: #f0fdf4;
  --color-background-warning: #fffbeb;
  --color-background-danger: #fef2f2;
  --color-border-primary: #c8d3e0;
  --color-border-secondary: var(--line);
  --color-border-tertiary: var(--line);
  --color-border-info: #bfdbfe;
  --color-border-success: #bbf7d0;
  --color-border-warning: #fde68a;
  --color-border-danger: #fecaca;
  --font-sans: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', sans-serif;
  --font-mono: 'SF Mono', 'JetBrains Mono', 'Monaco', monospace;
  --border-radius-sm: 6px;
  --border-radius-md: 10px;
  --border-radius-lg: 16px;
  color-scheme: light;
}
html[data-theme="dark"] {
  --bg: #0a0f1e;
  --surface: #121a2f;
  --surface-2: #19223c;
  --surface-3: #212c4b;
  --line: #243050;
  --line-2: #2f3d63;
  --text: #e8ecf7;
  --muted: #a3aec8;
  --faint: #76829f;
  --accent-ink: color-mix(in srgb, var(--accent) 55%, #fff);
  --shadow-sm: 0 1px 2px rgba(0,0,0,.4);
  --shadow-md: 0 12px 30px -10px rgba(0,0,0,.55);
  --shadow-lg: 0 30px 60px -18px rgba(0,0,0,.7);
  --color-text-info: #9dbaff;
  --color-text-success: #6ee7a8;
  --color-text-warning: #fcd34d;
  --color-text-danger: #fca5a5;
  --color-background-info: #172554;
  --color-background-success: #10301f;
  --color-background-warning: #3a2c0e;
  --color-background-danger: #3a1717;
  --color-border-primary: #34426a;
  --color-border-info: #2d4a9a;
  --color-border-success: #1f6b3f;
  --color-border-warning: #7a5a14;
  --color-border-danger: #7f2a2a;
  color-scheme: dark;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; }
body {
  font-family: var(--font-sans);
  color: var(--text);
  background: var(--bg);
  display: flex; flex-direction: column; min-height: 100vh;
  -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility;
  transition: background .35s var(--ease), color .35s var(--ease);
}
body::before {
  content: ''; position: fixed; inset: 0; z-index: 0; pointer-events: none;
  background:
    radial-gradient(900px 480px at 88% -8%, color-mix(in srgb, var(--accent) 13%, transparent), transparent 70%),
    radial-gradient(700px 420px at -6% 108%, rgba(16,185,129,.09), transparent 70%);
  transition: background .6s var(--ease);
}
#header, #layout { position: relative; z-index: 1; }
.sr-only {
  position: absolute !important; width: 1px !important; height: 1px !important;
  padding: 0 !important; margin: -1px !important; overflow: hidden !important;
  clip: rect(0,0,0,0) !important; white-space: nowrap !important; border: 0 !important;
}
button { font-family: inherit; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 6px; }

/* ===== Header ===== */
#header {
  height: 60px; padding: 0 22px; display: flex; align-items: center; gap: 14px; flex-shrink: 0; z-index: 100;
  background: color-mix(in srgb, var(--surface) 78%, transparent);
  backdrop-filter: saturate(1.5) blur(16px); -webkit-backdrop-filter: saturate(1.5) blur(16px);
  border-bottom: 1px solid var(--line);
}
.logo { font-size: 18px; font-weight: 750; letter-spacing: -.02em; color: var(--text);
  display: flex; align-items: center; gap: 10px; flex-shrink: 0; }
.logo-icon { width: 30px; height: 30px; border-radius: 9px; color: #fff; font-weight: 800; font-size: 15px;
  background: linear-gradient(135deg, #10b981, #6366f1 60%, #ec4899);
  display: flex; align-items: center; justify-content: center;
  box-shadow: 0 6px 16px -4px rgba(99,102,241,.55); transition: transform .5s var(--ease); }
.logo:hover .logo-icon { transform: rotate(-8deg) scale(1.08); }
.logo-tagline { font-size: 12px; color: var(--faint); font-weight: 450; margin-left: 2px; }
.breadcrumb { display: flex; align-items: center; gap: 4px; font-size: 13px; color: var(--faint); flex: 1; min-width: 0; }
.breadcrumb-sep { color: var(--line-2); }
.breadcrumb-item { color: var(--muted); cursor: pointer; border: none; background: none; font-size: 13px;
  padding: 4px 8px; border-radius: 8px; transition: color .15s, background .15s; white-space: nowrap; }
.breadcrumb-item:hover { color: var(--text); background: var(--surface-2); }
.breadcrumb-item.active { color: var(--text); font-weight: 600; cursor: default; overflow: hidden; text-overflow: ellipsis; max-width: 40ch; }
.breadcrumb-item.active:hover { background: none; }
.icon-btn { width: 36px; height: 36px; display: flex; align-items: center; justify-content: center;
  background: none; border: none; cursor: pointer; color: var(--muted); border-radius: 10px; flex-shrink: 0;
  transition: background .15s, color .15s, transform .2s var(--ease); }
.icon-btn:hover { background: var(--surface-2); color: var(--text); }
.icon-btn:active { transform: scale(.92); }
.icon-btn svg { width: 19px; height: 19px; }
#theme-toggle .i-sun { display: none; }
html[data-theme="dark"] #theme-toggle .i-sun { display: block; }
html[data-theme="dark"] #theme-toggle .i-moon { display: none; }
#read-progress { position: absolute; left: 0; bottom: -1px; height: 3px; width: 0; background: linear-gradient(90deg, var(--accent), color-mix(in srgb, var(--accent) 50%, #ec4899));
  border-radius: 0 3px 3px 0; transition: width .12s linear; }

/* ===== Layout ===== */
#layout { display: flex; flex: 1; overflow: hidden; height: calc(100vh - 60px); }

/* ===== Sidebar ===== */
#sidebar { width: 256px; flex-shrink: 0; background: color-mix(in srgb, var(--surface) 86%, transparent);
  border-right: 1px solid var(--line); overflow-y: auto; overflow-x: hidden; padding: 14px 10px;
  transition: width .32s var(--ease), padding .32s var(--ease), opacity .25s; }
#sidebar.collapsed { width: 0; padding: 0; border-right: none; opacity: 0; }
html.sb-init #sidebar { width: 0; padding: 0; border-right: none; opacity: 0; transition: none; }
.sidebar-section-label { font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .1em; color: var(--faint); padding: 6px 12px 6px; }
.sidebar-home-btn { display: flex; align-items: center; gap: 8px; width: 100%; padding: 9px 12px; border: none; background: none;
  font-size: 13.5px; color: var(--muted); cursor: pointer; text-align: left; border-radius: 10px; transition: background .15s, color .15s; }
.sidebar-home-btn:hover { background: var(--surface-2); color: var(--text); }
.sidebar-home-btn.active { background: color-mix(in srgb, var(--accent) 12%, transparent); color: var(--accent-ink); font-weight: 600; }
.sidebar-subject-name { font-size: 11px; font-weight: 700; color: var(--accent-ink); padding: 16px 12px 6px; text-transform: uppercase; letter-spacing: .08em; }
.sidebar-week-header { padding: 10px 12px 4px; font-size: 10.5px; font-weight: 700; color: var(--faint); text-transform: uppercase; letter-spacing: .08em; }
.sidebar-module-btn { position: relative; display: flex; align-items: flex-start; gap: 8px; width: 100%;
  padding: 8px 10px 8px 14px; border: none; background: none; font-size: 13px; color: var(--muted); cursor: pointer;
  text-align: left; line-height: 1.3; border-radius: 10px; transition: background .15s, color .15s; }
.sidebar-module-btn::before { content: ''; position: absolute; left: 4px; top: 10px; bottom: 10px; width: 3px; border-radius: 3px;
  background: var(--accent); transform: scaleY(0); transition: transform .3s var(--ease); }
.sidebar-module-btn:hover { background: var(--surface-2); color: var(--text); }
.sidebar-module-btn.active { background: color-mix(in srgb, var(--accent) 11%, transparent); color: var(--text); }
.sidebar-module-btn.active::before { transform: scaleY(1); }
.sidebar-module-btn .sb-texts { display: flex; flex-direction: column; min-width: 0; }
.sidebar-module-btn .sb-en { font-size: 13px; font-weight: 550; color: inherit; line-height: 1.35; }
.sidebar-module-btn .sb-zh { font-size: 11px; color: var(--faint); line-height: 1.35; margin-top: 2px; }
.sb-done { margin-left: auto; padding-left: 6px; color: #10b981; font-size: 12px; font-weight: 700; }
.sidebar-forget { margin-top: 18px; font-size: 12px; color: var(--faint); }

/* ===== Main ===== */
#main { flex: 1; overflow-y: auto; overflow-x: hidden; position: relative; scroll-behavior: smooth; }
@keyframes fadeUp { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: none; } }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
@keyframes popIn { from { opacity: 0; transform: translateY(-4px) scale(.98); } to { opacity: 1; transform: none; } }
.view { display: none; }
.view.active { display: block; animation: fadeUp .5s var(--ease) both; }

/* ===== Home ===== */
#view-home { padding: 52px 56px 64px; }
.hero { max-width: 1040px; margin-bottom: 30px; }
.hero-eyebrow { font-size: 12px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; color: var(--accent-ink); margin-bottom: 10px; }
.home-title { font-size: 38px; font-weight: 800; letter-spacing: -.03em; line-height: 1.1; color: var(--text); margin-bottom: 8px; }
.home-title .wave { display: inline-block; transform-origin: 70% 70%; animation: wave 2.4s ease-in-out .6s 1; }
@keyframes wave { 0%,60%,100% { transform: rotate(0); } 10%,30% { transform: rotate(14deg); } 20%,40% { transform: rotate(-8deg); } 50% { transform: rotate(10deg); } }
.home-subtitle { font-size: 15.5px; color: var(--muted); margin-bottom: 22px; }
.home-stats { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 18px; }
.stat-chip { display: inline-flex; align-items: baseline; gap: 6px; background: var(--surface); border: 1px solid var(--line);
  border-radius: 999px; padding: 6px 14px; font-size: 12.5px; color: var(--muted); box-shadow: var(--shadow-sm); }
.stat-chip b { font-size: 15px; color: var(--text); font-variant-numeric: tabular-nums; }
.continue-card { display: flex; align-items: center; gap: 16px; width: 100%; max-width: 640px; text-align: left; cursor: pointer;
  background: linear-gradient(135deg, color-mix(in srgb, var(--cc, var(--accent)) 14%, var(--surface)), var(--surface));
  border: 1px solid color-mix(in srgb, var(--cc, var(--accent)) 35%, var(--line)); border-radius: 18px; padding: 16px 20px;
  box-shadow: var(--shadow-md); color: var(--text); transition: transform .3s var(--ease), box-shadow .3s var(--ease); }
.continue-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-lg); }
.continue-card .cc-play { width: 44px; height: 44px; border-radius: 14px; background: color-mix(in srgb, var(--cc, var(--accent)) 76%, #000); color: #fff;
  display: flex; align-items: center; justify-content: center; font-size: 16px; flex-shrink: 0; box-shadow: 0 8px 18px -6px var(--cc, var(--accent)); }
.continue-card .cc-label { font-size: 11px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; color: var(--faint); }
.continue-card .cc-title { font-size: 16px; font-weight: 700; line-height: 1.3; margin-top: 2px; }
.continue-card .cc-sub { font-size: 12.5px; color: var(--muted); margin-top: 2px; }
.continue-card .cc-go { margin-left: auto; font-size: 20px; color: var(--faint); transition: transform .3s var(--ease), color .2s; }
.continue-card:hover .cc-go { transform: translateX(5px); color: var(--text); }
.subjects-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(290px, 1fr)); gap: 20px; max-width: 1040px; }
.subject-card { position: relative; overflow: hidden; cursor: pointer; background: var(--surface); border: 1px solid var(--line);
  border-radius: 20px; padding: 24px 24px 20px; box-shadow: var(--shadow-sm);
  transition: transform .35s var(--ease), box-shadow .35s var(--ease), border-color .25s;
  animation: fadeUp .6s var(--ease) both; animation-delay: calc(var(--i, 0) * 70ms + 120ms); }
.subject-card::before { content: ''; position: absolute; inset: 0 0 auto 0; height: 5px; background: var(--card-accent); }
.subject-card::after { content: ''; position: absolute; right: -50px; top: -50px; width: 170px; height: 170px; border-radius: 50%;
  background: radial-gradient(circle, color-mix(in srgb, var(--card-accent) 22%, transparent), transparent 70%); transition: transform .6s var(--ease); pointer-events: none; }
.subject-card:hover { transform: translateY(-5px); box-shadow: var(--shadow-lg); border-color: color-mix(in srgb, var(--card-accent) 45%, var(--line)); }
.subject-card:hover::after { transform: scale(1.35); }
.sc-top { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; position: relative; z-index: 1; }
.subject-card-code { font-size: 11.5px; font-weight: 750; letter-spacing: .08em; color: color-mix(in srgb, var(--card-accent) 70%, var(--text));
  background: color-mix(in srgb, var(--card-accent) 13%, transparent); padding: 3px 10px; border-radius: 999px; }
.sc-lock { font-size: 13px; opacity: .75; }
.subject-card-name { font-size: 20px; font-weight: 750; letter-spacing: -.015em; line-height: 1.25; color: var(--text); margin-bottom: 6px; position: relative; z-index: 1; }
.subject-card-desc { font-size: 13px; color: var(--muted); margin-bottom: 18px; position: relative; z-index: 1; }
.sc-foot { position: relative; z-index: 1; }
.progress-row { display: flex; align-items: center; gap: 10px; }
.progress-bar { flex: 1; height: 6px; background: var(--surface-3); border-radius: 99px; overflow: hidden; }
.progress-bar > div, .progress-bar > i { display: block; height: 100%; border-radius: 99px; transition: width .8s var(--ease); }
.progress-text { font-size: 12px; color: var(--faint); white-space: nowrap; font-variant-numeric: tabular-nums; }
.sc-arrow { position: absolute; right: 22px; bottom: 18px; z-index: 1; font-size: 18px; color: var(--card-accent); opacity: 0; transform: translateX(-8px); transition: all .35s var(--ease); }
.subject-card:hover .sc-arrow { opacity: 1; transform: none; }

/* ===== Subject ===== */
#view-subject { padding: 40px 48px 64px; }
.subject-header { margin-bottom: 30px; max-width: 1040px; }
.subject-header-code { display: inline-block; font-size: 11.5px; font-weight: 750; letter-spacing: .08em; color: var(--accent-ink);
  background: color-mix(in srgb, var(--accent) 13%, transparent); padding: 3px 11px; border-radius: 999px; margin-bottom: 12px; }
.subject-header-name { font-size: 32px; font-weight: 800; letter-spacing: -.025em; color: var(--text); margin-bottom: 6px; }
.subject-header-desc { font-size: 14px; color: var(--muted); }
.subject-header .progress-row { max-width: 360px; margin-top: 16px; }
.week-group { margin-bottom: 30px; max-width: 1040px; }
.week-group-header { font-size: 11.5px; font-weight: 750; color: var(--faint); text-transform: uppercase; letter-spacing: .12em; margin-bottom: 12px; display: flex; align-items: center; gap: 12px; }
.week-group-header::after { content: ''; flex: 1; height: 1px; background: var(--line); }
.modules-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.module-card { position: relative; overflow: hidden; cursor: pointer; background: var(--surface); border: 1px solid var(--line);
  border-radius: 16px; padding: 18px 18px 16px; box-shadow: var(--shadow-sm);
  transition: transform .3s var(--ease), box-shadow .3s var(--ease), border-color .25s;
  animation: fadeUp .5s var(--ease) both; animation-delay: calc(var(--i, 0) * 45ms); }
.module-card::before { content: ''; position: absolute; left: 0; top: 0; bottom: 0; width: 4px; background: var(--card-color, var(--accent)); transition: width .3s var(--ease); }
.module-card:hover { transform: translateY(-4px); box-shadow: var(--shadow-md); border-color: color-mix(in srgb, var(--card-color) 40%, var(--line)); }
.module-card:hover::before { width: 7px; }
.module-card-week { font-size: 11px; font-weight: 750; text-transform: uppercase; letter-spacing: .08em; color: color-mix(in srgb, var(--card-color) 75%, var(--text)); margin-bottom: 8px; display: flex; align-items: center; }
.module-card-title { font-size: 15.5px; font-weight: 700; color: var(--text); margin-bottom: 6px; line-height: 1.3; letter-spacing: -.01em; }
.module-card-subtitle { font-size: 12.5px; color: var(--muted); line-height: 1.5; }
.card-done { margin-left: auto; color: #10b981; font-weight: 700; text-transform: none; letter-spacing: 0; font-size: 11.5px;
  background: color-mix(in srgb, #10b981 12%, transparent); padding: 2px 8px; border-radius: 99px; }

/* ===== Module view ===== */
#view-module.active { min-height: 100%; display: flex; justify-content: center; padding: 28px 24px 80px; }
.module-content-wrapper { width: 100%; max-width: 860px; background: var(--surface); border-radius: 22px;
  border: 1px solid var(--line); padding: 28px 30px 30px; box-shadow: var(--shadow-md);
  transform-origin: top center; align-self: flex-start; overflow-x: auto; transition: background .35s var(--ease); }
.module-content-wrapper.yv-std { overflow-x: clip; overflow-y: visible; }
/* 老模块（自带样式）在深色模式下保持浅色，避免错乱 */
html[data-theme="dark"] .module-content-wrapper:not(.yv-dark) {
  --text: #111827; --muted: #6b7280; --faint: #9ca3af; --surface: #ffffff; --surface-2: #eef2f7; --surface-3: #e2e8f0; --line: #dce4f0;
  --color-text-primary: #111827; --color-text-secondary: #6b7280; --color-text-tertiary: #9ca3af;
  --color-text-info: #1d4ed8; --color-text-success: #15803d; --color-text-warning: #92400e; --color-text-danger: #991b1b;
  --color-background-primary: #ffffff; --color-background-secondary: #eef2f7;
  --color-background-info: #eff6ff; --color-background-success: #f0fdf4; --color-background-warning: #fffbeb; --color-background-danger: #fef2f2;
  --color-border-primary: #c8d3e0; --color-border-secondary: #dde3ed; --color-border-tertiary: #dce4f0;
  --color-border-info: #bfdbfe; --color-border-success: #bbf7d0; --color-border-warning: #fde68a; --color-border-danger: #fecaca;
  color-scheme: light; color: #111827; background: #ffffff;
}

/* 模块内排版微调（仅新格式模块） */
.yv-std .wrap { padding: 0; }
.yv-std p { font-size: 14px; line-height: 1.78; }
.yv-std li { font-size: 14px; line-height: 1.75; }
.yv-std h3 { font-size: 16.5px; letter-spacing: -.01em; margin-bottom: 12px; }
.yv-std h4 { font-size: 13.5px; margin: 14px 0 6px; color: var(--text); }
.yv-std .card { border: 1px solid var(--line); border-radius: 18px; padding: 20px 22px; margin-bottom: 16px; background: var(--surface);
  transition: border-color .25s, box-shadow .3s var(--ease); }
.yv-std .card:hover { border-color: color-mix(in srgb, var(--accent) 28%, var(--line)); box-shadow: var(--shadow-sm); }
.yv-std .zh { color: var(--faint); }
.yv-std .formula { border-left-width: 3px; border-left-color: var(--accent); border-radius: 0 12px 12px 0; background: var(--surface-2); }
.yv-std .slide, .yv-std .tip, .yv-std .warn, .yv-std .danger { border-radius: 0 12px 12px 0; }
html[data-theme="dark"] .yv-std .slide { background: #1b1f45; color: #cfd3ff; border-left-color: #818cf8; }
html[data-theme="dark"] .yv-std .slide::before { color: #a5b4fc; }
html[data-theme="dark"] .yv-std .b-purple { background: #2e1d5a; color: #d8b4fe; }
html[data-theme="dark"] .yv-std .highlight { background: #4b3c0a; color: #fde68a; }

/* Section 切换动效 */
@keyframes secIn { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: none; } }
@keyframes cardIn { from { opacity: 0; transform: translateY(14px) scale(.985); } to { opacity: 1; transform: none; } }
.yv-std .sec.on { animation: secIn .4s var(--ease) both; }
.yv-std .sec.on > .card { animation: cardIn .55s var(--ease) both; }
.yv-std .sec.on > .card:nth-child(1) { animation-delay: .02s; }
.yv-std .sec.on > .card:nth-child(2) { animation-delay: .08s; }
.yv-std .sec.on > .card:nth-child(3) { animation-delay: .14s; }
.yv-std .sec.on > .card:nth-child(4) { animation-delay: .20s; }
.yv-std .sec.on > .card:nth-child(5) { animation-delay: .26s; }
.yv-std .sec.on > .card:nth-child(n+6) { animation-delay: .3s; }

/* 标签栏：可横向滑动 + 滑块指示器 + 吸顶 */
.yv-tabs { position: sticky; top: 10px; z-index: 40; display: flex !important; flex-wrap: nowrap !important; gap: 2px !important; padding: 5px;
  margin: 0 0 1.4rem !important; border-radius: 16px; overflow-x: auto; scrollbar-width: none; scroll-snap-type: x proximity;
  background: color-mix(in srgb, var(--surface-2) 84%, transparent); backdrop-filter: blur(14px) saturate(1.4); -webkit-backdrop-filter: blur(14px) saturate(1.4);
  border: 1px solid var(--line); box-shadow: var(--shadow-sm); }
.yv-tabs::-webkit-scrollbar { display: none; }
.yv-tabs.fade-l { -webkit-mask-image: linear-gradient(90deg, transparent 0, #000 28px); mask-image: linear-gradient(90deg, transparent 0, #000 28px); }
.yv-tabs.fade-r { -webkit-mask-image: linear-gradient(270deg, transparent 0, #000 28px); mask-image: linear-gradient(270deg, transparent 0, #000 28px); }
.yv-tabs.fade-l.fade-r { -webkit-mask-image: linear-gradient(90deg, transparent 0, #000 28px, #000 calc(100% - 28px), transparent 100%); mask-image: linear-gradient(90deg, transparent 0, #000 28px, #000 calc(100% - 28px), transparent 100%); }
.yv-tabs button { position: relative; z-index: 1; flex: 0 0 auto; scroll-snap-align: center; border: 0 !important; background: transparent !important;
  border-radius: 12px !important; padding: 9px 15px !important; font-size: 13px !important; font-weight: 560; color: var(--muted) !important;
  white-space: nowrap; cursor: pointer; transition: color .25s, transform .2s var(--ease) !important; }
.yv-tabs button:hover { color: var(--text) !important; }
.yv-tabs button:active { transform: scale(.96); }
.yv-tabs button.on { color: var(--accent-ink) !important; font-weight: 680; }
.yv-ind { position: absolute; left: 0; top: 5px; bottom: 5px; width: 0; border-radius: 12px; z-index: 0; pointer-events: none;
  background: var(--surface); box-shadow: 0 2px 8px -2px rgba(15,23,42,.18), 0 0 0 1px color-mix(in srgb, var(--accent) 30%, transparent);
  transition: transform .5s var(--ease), width .5s var(--ease); }
html[data-theme="dark"] .yv-ind { background: var(--surface-3); }

/* 表格 */
.tbl-scroll { overflow-x: auto; border: 1px solid var(--line); border-radius: 14px; margin: 12px 0; background: var(--surface); }
.tbl-scroll > table { margin: 0 !important; min-width: 100%; }
.yv-std table { font-size: 13.5px; }
.yv-std th { background: var(--surface-2); color: var(--muted); font-weight: 650; border-bottom: 1px solid var(--line); }
.yv-std td { border-bottom: 1px solid var(--line); line-height: 1.6; }
.yv-std tr:last-child td { border-bottom: none; }
.yv-std tbody tr { transition: background .15s; }
.yv-std tbody tr:hover td { background: color-mix(in srgb, var(--accent) 5%, transparent); }

/* 测验 */
.yv-std .qblock { background: var(--surface-2); border: 1px solid var(--line); border-radius: 18px; padding: 18px 18px 16px; margin-bottom: 14px;
  transition: border-color .3s, box-shadow .3s var(--ease); }
.yv-std .qblock.is-ok { border-color: color-mix(in srgb, #10b981 55%, var(--line)); box-shadow: 0 0 0 3px color-mix(in srgb, #10b981 12%, transparent); }
.yv-std .qblock.is-err { border-color: color-mix(in srgb, #ef4444 50%, var(--line)); box-shadow: 0 0 0 3px color-mix(in srgb, #ef4444 10%, transparent); }
.yv-std .q-text { font-size: 14px; font-weight: 600; line-height: 1.6; margin-bottom: 12px; color: var(--text); }
.yv-std .q-opts label { display: flex; align-items: flex-start; gap: 10px; font-size: 13.5px; line-height: 1.55; color: var(--muted);
  padding: 10px 13px; margin: 6px 0; cursor: pointer; background: var(--surface); border: 1px solid var(--line); border-radius: 12px;
  transition: border-color .18s, background .18s, transform .2s var(--ease), box-shadow .2s; }
.yv-std .q-opts label:hover { border-color: color-mix(in srgb, var(--accent) 55%, var(--line)); transform: translateX(3px); color: var(--text); }
.yv-std .q-opts label:has(input:checked) { border-color: var(--accent); color: var(--text); background: color-mix(in srgb, var(--accent) 9%, var(--surface));
  box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 16%, transparent); }
.yv-std .q-opts input { accent-color: var(--accent); margin-top: 3px; flex-shrink: 0; }
.yv-std .q-fb.ok, .yv-std .q-fb.err { animation: popIn .35s var(--ease); border-radius: 12px; padding: 10px 14px; line-height: 1.6; font-size: 13px; }
.yv-std .btn { border-radius: 11px; padding: 8px 20px; font-weight: 600; transition: transform .2s var(--ease), box-shadow .2s, opacity .15s, background .2s; }
.yv-std .btn-blue { background: var(--accent-strong); color: #fff; box-shadow: 0 6px 16px -6px var(--accent-strong); }
.yv-std .btn-blue:hover { opacity: 1; transform: translateY(-2px); box-shadow: 0 10px 22px -8px var(--accent-strong); }
.yv-std .btn-blue:active { transform: scale(.96); }
.quiz-bar { display: flex; align-items: center; gap: 12px; margin: 4px 0 16px; padding: 12px 14px; background: var(--surface-2); border: 1px solid var(--line); border-radius: 14px; }
.quiz-bar .qb-track { flex: 1; height: 8px; background: var(--surface-3); border-radius: 99px; overflow: hidden; position: relative; }
.quiz-bar .qb-ok, .quiz-bar .qb-err { position: absolute; top: 0; bottom: 0; transition: width .6s var(--ease), left .6s var(--ease); }
.quiz-bar .qb-ok { left: 0; background: linear-gradient(90deg, #10b981, #34d399); border-radius: 99px 0 0 99px; }
.quiz-bar .qb-err { background: #f87171; }
.quiz-bar .qb-text { font-size: 12.5px; color: var(--muted); white-space: nowrap; font-variant-numeric: tabular-nums; }
.quiz-bar .qb-text b { color: var(--text); }
.quiz-bar button { border: 1px solid var(--line-2); background: var(--surface); color: var(--muted); border-radius: 10px; padding: 5px 11px; font-size: 12px; cursor: pointer; transition: all .2s; }
.quiz-bar button:hover { color: var(--text); border-color: var(--accent); }
.quiz-bar.perfect { border-color: #10b981; background: color-mix(in srgb, #10b981 10%, var(--surface-2)); }
.quiz-bar.perfect .qb-text { color: #059669; font-weight: 700; }

/* 背诵模式（遮挡答案，点击揭晓） */
.recall-bar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; padding: 10px 14px; background: var(--surface-2); border: 1px solid var(--line); border-radius: 14px; font-size: 12.5px; color: var(--muted); }
.recall-bar .sw { position: relative; width: 38px; height: 22px; border-radius: 99px; background: var(--surface-3); border: none; cursor: pointer; transition: background .3s; flex-shrink: 0; }
.recall-bar .sw::after { content: ''; position: absolute; left: 3px; top: 3px; width: 16px; height: 16px; border-radius: 50%; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,.3); transition: transform .3s var(--ease); }
.recall-bar .sw.on { background: var(--accent); }
.recall-bar .sw.on::after { transform: translateX(16px); }
.recall-bar b { color: var(--text); }
.recall-bar button.lnk { margin-left: auto; border: 1px solid var(--line-2); background: var(--surface); color: var(--muted); border-radius: 9px; padding: 4px 10px; cursor: pointer; font-size: 12px; }
.recall-bar button.lnk:hover { color: var(--text); border-color: var(--accent); }
.cz { border-radius: 5px; transition: filter .3s var(--ease), background .3s, color .3s; }
.recall-on .cz:not(.rev) { filter: blur(7px); cursor: pointer; background: color-mix(in srgb, var(--accent) 14%, transparent); user-select: none; }
.recall-on .cz:not(.rev):hover { filter: blur(5px); }
.recall-on .cz.rev { cursor: pointer; background: color-mix(in srgb, #10b981 14%, transparent); }

/* 速记清单版式 */
.cs-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; }
.cs-block { background: var(--surface); border: 1px solid var(--line); border-radius: 16px; padding: 14px 16px 12px; }
.cs-block.wide { grid-column: 1 / -1; }
.cs-block h4 { display: flex; align-items: center; gap: 8px; margin: 0 0 8px; font-size: 13.5px; }
.cs-block h4 .wk { font-size: 10.5px; font-weight: 750; letter-spacing: .06em; color: var(--accent-ink); background: color-mix(in srgb, var(--accent) 13%, transparent); padding: 2px 8px; border-radius: 99px; }
.cs-block ul { padding-left: 16px; margin: 0; }
.cs-block li { font-size: 13px !important; line-height: 1.65 !important; margin-bottom: 4px; color: var(--muted); }
.cs-block li b, .cs-block p b { color: var(--text); }
.cs-block p { font-size: 13px !important; line-height: 1.65 !important; margin-bottom: 4px; }
.cs-h { font-size: 12px; font-weight: 750; letter-spacing: .1em; text-transform: uppercase; color: var(--faint); margin: 22px 0 10px; display: flex; align-items: center; gap: 12px; }
.cs-h::after { content: ''; flex: 1; height: 1px; background: var(--line); }

/* 闪卡牌组 */
.deck { max-width: 640px; margin: 0 auto; }
.deck > .fc { display: none; }
.dk-head { margin-bottom: 14px; }
.dk-prog { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.dk-bar { flex: 1; height: 8px; background: var(--surface-3); border-radius: 99px; overflow: hidden; position: relative; }
.dk-bar i { position: absolute; left: 0; top: 0; bottom: 0; background: linear-gradient(90deg, var(--accent), #10b981); border-radius: 99px; transition: width .6s var(--ease); }
.dk-count { font-size: 12.5px; color: var(--muted); white-space: nowrap; font-variant-numeric: tabular-nums; }
.dk-count b { color: var(--text); }
.dk-tools { display: flex; gap: 8px; flex-wrap: wrap; }
.dk-chip { border: 1px solid var(--line-2); background: var(--surface); color: var(--muted); border-radius: 99px; padding: 5px 13px; font-size: 12px; cursor: pointer; transition: all .2s var(--ease); }
.dk-chip:hover { color: var(--text); border-color: var(--accent); }
.dk-chip.on { background: var(--accent-strong); border-color: var(--accent-strong); color: #fff; box-shadow: 0 6px 14px -6px var(--accent-strong); }
.dk-chip.sp { margin-left: auto; }
.dk-stage { position: relative; perspective: 1400px; margin: 18px 0 16px; min-height: 280px; touch-action: pan-y; }
.dk-ghost { position: absolute; inset: 0; border-radius: 24px; background: var(--surface); border: 1px solid var(--line); transform: translateY(10px) scale(.95); opacity: .7; z-index: 0; }
.dk-ghost.g2 { transform: translateY(20px) scale(.9); opacity: .4; }
.dk-card { position: relative; z-index: 1; cursor: grab; user-select: none; -webkit-user-select: none; transition: transform .45s var(--ease), opacity .35s; will-change: transform; }
.dk-card.drag { transition: none; cursor: grabbing; }
.dk-card.enter { animation: dkIn .5s var(--ease) backwards; }
@keyframes dkIn { from { opacity: 0; transform: translateY(26px) scale(.94); } to { opacity: 1; transform: none; } }
.dk-inner { display: grid; transform-style: preserve-3d; transition: transform .6s var(--ease); }
.dk-card.flipped .dk-inner { transform: rotateY(180deg); }
.dk-face { grid-area: 1 / 1; min-height: 280px; border-radius: 24px; padding: 26px 28px; display: flex; flex-direction: column; justify-content: center;
  backface-visibility: hidden; -webkit-backface-visibility: hidden; border: 1px solid var(--line); box-shadow: var(--shadow-md); position: relative; overflow: hidden; }
.dk-front { background: var(--surface); }
.dk-back { background: linear-gradient(160deg, color-mix(in srgb, var(--accent) 12%, var(--surface)), var(--surface)); transform: rotateY(180deg);
  border-color: color-mix(in srgb, var(--accent) 35%, var(--line)); }
.dk-tag { position: absolute; top: 16px; left: 22px; font-size: 10.5px; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; color: var(--accent-ink);
  background: color-mix(in srgb, var(--accent) 13%, transparent); padding: 3px 10px; border-radius: 99px; }
.dk-hint { position: absolute; bottom: 14px; left: 0; right: 0; text-align: center; font-size: 11.5px; color: var(--faint); }
.dk-q { font-size: 19px; font-weight: 700; line-height: 1.5; color: var(--text); letter-spacing: -.01em; margin-top: 14px; }
.dk-q .zh { font-size: 14px; font-weight: 450; display: block; margin-top: 6px; }
.dk-a { font-size: 14.5px; line-height: 1.75; color: var(--text); margin-top: 14px; max-height: 420px; overflow-y: auto; }
.dk-a ul { padding-left: 18px; margin: 4px 0; }
.dk-a li, .dk-a p { font-size: 14.5px !important; color: var(--text) !important; line-height: 1.7 !important; margin-bottom: 3px; }
.dk-a .zh { color: var(--muted) !important; }
.dk-badge { position: absolute; top: 22px; z-index: 5; font-size: 13px; font-weight: 800; letter-spacing: .08em; padding: 6px 14px; border-radius: 10px; border: 2.5px solid; opacity: 0; pointer-events: none; transition: opacity .1s; }
.dk-badge.yes { right: 24px; color: #10b981; border-color: #10b981; transform: rotate(8deg); }
.dk-badge.no { left: 24px; color: #ef4444; border-color: #ef4444; transform: rotate(-8deg); }
.dk-actions { display: flex; gap: 12px; justify-content: center; align-items: center; margin-top: 12px; }
.dk-btn { border: 1px solid var(--line-2); background: var(--surface); color: var(--text); border-radius: 14px; padding: 12px 20px; font-size: 14px; font-weight: 650; cursor: pointer;
  transition: transform .2s var(--ease), box-shadow .2s, border-color .2s, background .2s; min-width: 120px; }
.dk-btn:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); }
.dk-btn:active { transform: scale(.96); }
.dk-btn.no { color: #dc2626; border-color: color-mix(in srgb, #ef4444 40%, var(--line)); }
.dk-btn.no:hover { background: color-mix(in srgb, #ef4444 9%, var(--surface)); }
.dk-btn.yes { color: #059669; border-color: color-mix(in srgb, #10b981 45%, var(--line)); }
.dk-btn.yes:hover { background: color-mix(in srgb, #10b981 10%, var(--surface)); }
.dk-btn.flip { min-width: 90px; background: var(--accent-strong); color: #fff; border-color: var(--accent-strong); box-shadow: 0 8px 18px -8px var(--accent-strong); }
.dk-keys { text-align: center; font-size: 11.5px; color: var(--faint); margin-top: 12px; }
.dk-keys kbd { font-family: var(--font-mono); font-size: 11px; background: var(--surface-2); border: 1px solid var(--line-2); border-bottom-width: 2px; border-radius: 5px; padding: 1px 6px; color: var(--muted); }
.dk-done { text-align: center; padding: 38px 20px 30px; background: var(--surface); border: 1px solid var(--line); border-radius: 24px; box-shadow: var(--shadow-md); animation: popIn .5s var(--ease); }
.dk-done .big { font-size: 46px; margin-bottom: 8px; }
.dk-done h3 { font-size: 20px; margin-bottom: 6px; }
.dk-done p { font-size: 14px; margin-bottom: 16px; }
.dk-done .row { display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }

/* 上一页 / 下一页 */
.mod-nav { display: flex; justify-content: space-between; gap: 14px; margin-top: 36px; padding-top: 22px; border-top: 1px solid var(--line); }
.mod-nav-btn { flex: 1; max-width: 49%; padding: 13px 16px; background: var(--surface-2); border: 1px solid var(--line); border-radius: 14px;
  font-size: 13px; font-weight: 550; color: var(--text); cursor: pointer; text-align: left; transition: transform .25s var(--ease), background .2s, border-color .2s, box-shadow .25s; }
.mod-nav-btn.next { text-align: right; margin-left: auto; }
.mod-nav-btn:hover { background: var(--surface); border-color: var(--accent); transform: translateY(-2px); box-shadow: var(--shadow-md); }

/* 浮动控件 */
#zoom-bar { display: none; position: fixed; bottom: 20px; right: 22px; background: color-mix(in srgb, var(--surface) 82%, transparent);
  backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px); border: 1px solid var(--line); border-radius: 99px; padding: 4px 6px; gap: 2px; align-items: center;
  box-shadow: var(--shadow-md); z-index: 200; }
#zoom-bar.visible { display: flex; animation: fadeUp .4s var(--ease); }
#zoom-bar button { width: 28px; height: 28px; border: none; background: none; color: var(--muted); font-size: 16px; cursor: pointer; border-radius: 50%;
  display: flex; align-items: center; justify-content: center; transition: background .15s, color .15s; line-height: 1; }
#zoom-bar button:hover { background: var(--surface-2); color: var(--text); }
#zoom-bar button:disabled { opacity: .3; cursor: default; }
#zoom-label { font-size: 12px; font-weight: 600; color: var(--muted); min-width: 40px; text-align: center; cursor: pointer; padding: 2px 4px; border-radius: 6px; }
#zoom-label:hover { color: var(--text); }
#to-top { position: fixed; right: 24px; bottom: 70px; width: 40px; height: 40px; border-radius: 50%; border: 1px solid var(--line); background: var(--surface);
  color: var(--text); box-shadow: var(--shadow-md); cursor: pointer; z-index: 190; display: flex; align-items: center; justify-content: center;
  opacity: 0; transform: translateY(12px) scale(.9); pointer-events: none; transition: all .35s var(--ease); }
#to-top.show { opacity: 1; transform: none; pointer-events: auto; }
#to-top:hover { background: var(--accent); color: #fff; border-color: var(--accent); }
#to-top svg { width: 18px; height: 18px; }

#sidebar::-webkit-scrollbar, #main::-webkit-scrollbar { width: 8px; }
#sidebar::-webkit-scrollbar-track, #main::-webkit-scrollbar-track { background: transparent; }
#sidebar::-webkit-scrollbar-thumb, #main::-webkit-scrollbar-thumb { background: var(--line-2); border-radius: 4px; border: 2px solid transparent; background-clip: content-box; }

/* ===== 密码弹窗 ===== */
#pw-overlay { display: none; position: fixed; inset: 0; background: rgba(8,12,24,.55); backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px); z-index: 500; align-items: center; justify-content: center; }
#pw-overlay.visible { display: flex; animation: fadeIn .25s; }
#pw-box { background: var(--surface); border: 1px solid var(--line); border-radius: 24px; padding: 38px 34px 30px; width: 360px; max-width: calc(100vw - 32px);
  box-shadow: var(--shadow-lg); text-align: center; animation: fadeUp .45s var(--ease); }
#pw-icon { font-size: 42px; margin-bottom: 12px; }
#pw-title { font-size: 19px; font-weight: 750; color: var(--text); margin-bottom: 6px; }
#pw-subtitle { font-size: 13px; color: var(--muted); margin-bottom: 22px; }
#pw-input { width: 100%; padding: 12px 16px; font-size: 15px; border: 1.5px solid var(--line-2); border-radius: 12px; outline: none; background: var(--surface-2); color: var(--text);
  letter-spacing: .08em; transition: border-color .2s, box-shadow .2s; }
#pw-input:focus { border-color: var(--accent); box-shadow: 0 0 0 4px color-mix(in srgb, var(--accent) 18%, transparent); }
#pw-input.error { border-color: #ef4444; animation: shake .3s; }
@keyframes shake { 0%,100%{transform:translateX(0)} 25%{transform:translateX(-6px)} 75%{transform:translateX(6px)} }
#pw-error-msg { font-size: 12px; color: #ef4444; margin-top: 6px; min-height: 18px; }
#pw-btn-row { display: flex; gap: 10px; margin-top: 18px; }
#pw-submit { flex: 1; padding: 11px; background: var(--accent-strong); color: #fff; border: none; border-radius: 12px; font-size: 14px; font-weight: 650; cursor: pointer;
  transition: transform .2s var(--ease), box-shadow .2s; box-shadow: 0 8px 18px -8px var(--accent); }
#pw-submit:hover { transform: translateY(-2px); }
#pw-cancel { padding: 11px 18px; background: none; border: 1.5px solid var(--line-2); border-radius: 12px; font-size: 14px; color: var(--muted); cursor: pointer; transition: border-color .2s, color .2s; }
#pw-cancel:hover { border-color: var(--faint); color: var(--text); }
#pw-remember-row { display: block; margin-top: 12px; font-size: 12px; color: var(--muted); cursor: pointer; text-align: left; }

/* ===== 搜索 ===== */
#search-wrap { position: relative; flex-shrink: 0; }
#search-input { width: 230px; padding: 8px 14px; border-radius: 12px; border: 1px solid var(--line); background: var(--surface-2); color: var(--text); font-size: 13px; outline: none;
  transition: width .35s var(--ease), border-color .2s, box-shadow .2s, background .2s; }
#search-input:focus { width: 300px; border-color: var(--accent); background: var(--surface); box-shadow: 0 0 0 4px color-mix(in srgb, var(--accent) 16%, transparent); }
#search-results { display: none; position: absolute; right: 0; top: 46px; width: 440px; max-width: calc(100vw - 24px); max-height: 70vh; overflow-y: auto;
  background: var(--surface); border-radius: 16px; z-index: 300; box-shadow: var(--shadow-lg); border: 1px solid var(--line); }
#search-results.visible { display: block; animation: popIn .25s var(--ease); }
.sr-item { padding: 11px 16px; cursor: pointer; border-bottom: 1px solid var(--line); transition: background .15s; }
.sr-item:last-child { border-bottom: none; }
.sr-item:hover { background: var(--surface-2); }
.sr-title { font-size: 14px; font-weight: 650; color: var(--text); }
.sr-tag { font-size: 11px; font-weight: 600; color: var(--accent-ink); margin-left: 6px; }
.sr-snip { font-size: 12.5px; color: var(--muted); margin-top: 3px; line-height: 1.55; }
.sr-snip mark { background: #fde68a; color: #422006; border-radius: 3px; padding: 0 2px; }
.sr-empty { padding: 16px; font-size: 13px; color: var(--muted); }

/* ===== 手机适配 ===== */
@media (max-width: 900px) { .modules-grid { grid-template-columns: repeat(2, 1fr); } .cs-grid { grid-template-columns: 1fr; } }
@media (max-width: 768px) {
  #header { padding: 0 12px; gap: 8px; }
  .logo-tagline { display: none; }
  #search-input, #search-input:focus { width: 140px; }
  #sidebar { position: fixed; top: 60px; left: 0; bottom: 0; z-index: 150; width: 280px; box-shadow: var(--shadow-lg); background: var(--surface); }
  #sidebar.collapsed { width: 0; }
  #view-home { padding: 28px 16px 56px; }
  .home-title { font-size: 30px; }
  #view-subject { padding: 22px 16px 56px; }
  .subjects-grid, .modules-grid { grid-template-columns: 1fr; }
  #view-module.active { padding: 10px 8px 70px; }
  .module-content-wrapper { padding: 16px 14px 20px; border-radius: 18px; }
  .yv-std .card { padding: 16px 15px; border-radius: 16px; }
  .breadcrumb { overflow: hidden; white-space: nowrap; }
  #search-results { position: fixed; left: 12px; right: 12px; top: 64px; width: auto; }
  .mod-nav { flex-direction: column; }
  .mod-nav-btn { max-width: 100%; }
  .dk-face { padding: 22px 20px; min-height: 300px; }
  .dk-q { font-size: 17px; }
  .dk-btn { min-width: 0; flex: 1; padding: 12px 10px; }
  .dk-keys { display: none; }
  #to-top { right: 14px; bottom: 64px; }
}
@media (max-width: 520px) { .breadcrumb { display: none; } #search-wrap { flex: 1; } #search-input, #search-input:focus { width: 100%; } }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; animation-delay: 0s !important; transition-duration: .001ms !important; scroll-behavior: auto !important; }
}
@media print { #header, #sidebar, #zoom-bar, #to-top, .yv-tabs { display: none !important; } .module-content-wrapper { box-shadow: none; border: none; } .yv-std .sec { display: block !important; } }

/* ===== v2：色彩层次（每个模块/标签/卡片不同色相，邻近渐变）===== */
.sidebar-module-btn::before { background: var(--mc, var(--accent)); transform: scaleY(.38); opacity: .7; transition: transform .3s var(--ease), opacity .2s; }
.sidebar-module-btn:hover::before { transform: scaleY(.7); opacity: 1; }
.sidebar-module-btn.active { background: color-mix(in srgb, var(--mc, var(--accent)) 12%, transparent); }
.sidebar-module-btn.active::before { transform: scaleY(1); opacity: 1; }
.module-card-week { color: color-mix(in srgb, var(--card-color) 70%, var(--text)); }
.module-card::after { content: ''; position: absolute; right: -30px; bottom: -30px; width: 110px; height: 110px; border-radius: 50%;
  background: radial-gradient(circle, color-mix(in srgb, var(--card-color) 20%, transparent), transparent 70%); pointer-events: none; transition: transform .5s var(--ease); }
.module-card:hover::after { transform: scale(1.4); }

.yv-std .sec { --tabc: var(--accent); }
.yv-std .card { position: relative; overflow: hidden; }
.yv-std .sec > .card::before, .cs-block::before {
  content: ''; position: absolute; left: 0; right: 0; top: 0; height: 4px; pointer-events: none;
  background: linear-gradient(90deg, var(--c1, var(--tabc)), var(--c2, var(--tabc))); }
.cs-block { position: relative; overflow: hidden; padding-top: 18px; }
.yv-std .card > h3:first-child::before { content: ''; display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 10px; position: relative; top: -1px;
  background: linear-gradient(135deg, var(--c1, var(--tabc)), var(--c2, var(--tabc)));
  box-shadow: 0 0 0 4px color-mix(in srgb, var(--c1, var(--tabc)) 16%, transparent); }
.yv-std h4 { color: color-mix(in srgb, var(--tabc) 62%, var(--text)); }
.cs-block h4 .wk { color: color-mix(in srgb, var(--c1, var(--tabc)) 65%, var(--text)); background: color-mix(in srgb, var(--c1, var(--tabc)) 14%, transparent); }

/* 标签栏：每个标签自己的颜色 */
.yv-tabs button.on { color: color-mix(in srgb, var(--tabc, var(--accent)) 70%, var(--text)) !important; }
.yv-tabs button::after { content: ''; position: absolute; left: 50%; bottom: 3px; width: 5px; height: 5px; margin-left: -2.5px; border-radius: 50%; background: var(--tabc, var(--accent)); opacity: .0; transform: scale(0); transition: all .35s var(--ease); }
.yv-tabs button:not(.on):hover::after { opacity: .7; transform: scale(1); }
.yv-ind { box-shadow: 0 2px 10px -3px color-mix(in srgb, var(--tabc, var(--accent)) 45%, transparent), 0 0 0 1.5px color-mix(in srgb, var(--tabc, var(--accent)) 55%, transparent);
  transition: transform .5s var(--ease), width .5s var(--ease), box-shadow .5s; }

/* 重点：加粗词带荧光笔底色 */
.yv-std p strong, .yv-std li strong, .yv-std td strong, .yv-std p b, .yv-std li b, .yv-std td b {
  color: var(--text); font-weight: 700; padding: 0 2px; border-radius: 3px;
  background-image: linear-gradient(transparent 58%, color-mix(in srgb, var(--tabc) 26%, transparent) 58%); }
html[data-theme="dark"] .yv-std p strong, html[data-theme="dark"] .yv-std li strong, html[data-theme="dark"] .yv-std td strong,
html[data-theme="dark"] .yv-std p b, html[data-theme="dark"] .yv-std li b, html[data-theme="dark"] .yv-std td b {
  background-image: linear-gradient(transparent 58%, color-mix(in srgb, var(--tabc) 38%, transparent) 58%); }

/* 中文辅助：青色，和英文一眼区分 */
.yv-std .zh, .yv-std span.zh { color: color-mix(in srgb, #0d9488 78%, var(--text)); font-weight: 450; }
html[data-theme="dark"] .yv-std .zh, html[data-theme="dark"] .yv-std span.zh { color: #5fd3c6; }
.yv-std .dk-q .zh { color: color-mix(in srgb, #0d9488 78%, var(--text)); }
html[data-theme="dark"] .yv-std .dk-q .zh { color: #5fd3c6; }

/* 提示框：各用各的语义色 */
.yv-std .slide { background: color-mix(in srgb, #3b82f6 8%, var(--surface)); color: var(--text); border-left: 4px solid #3b82f6; border-radius: 0 14px 14px 0; }
.yv-std .slide::before { color: #2563eb; }
.yv-std .slide strong, .yv-std .slide b { background-image: linear-gradient(transparent 58%, color-mix(in srgb, #3b82f6 28%, transparent) 58%); }
html[data-theme="dark"] .yv-std .slide { background: color-mix(in srgb, #3b82f6 14%, var(--surface)); color: var(--text); border-left-color: #60a5fa; }
html[data-theme="dark"] .yv-std .slide::before { color: #93c5fd; }
.yv-std .formula { background: color-mix(in srgb, #14b8a6 8%, var(--surface)); border-left: 4px solid #14b8a6; border-radius: 0 14px 14px 0; }
.yv-std .tip { background: color-mix(in srgb, #10b981 9%, var(--surface)); color: var(--text); border-left: 4px solid #10b981; border-radius: 0 14px 14px 0; }
.yv-std .tip::before { content: '💡 TIP'; display: block; font-size: 10px; font-weight: 750; letter-spacing: .08em; color: #059669; margin-bottom: 2px; }
.yv-std .warn { background: color-mix(in srgb, #f59e0b 11%, var(--surface)); color: var(--text); border-left: 4px solid #f59e0b; border-radius: 0 14px 14px 0; }
.yv-std .warn::before { content: '⚠️ NOTE'; display: block; font-size: 10px; font-weight: 750; letter-spacing: .08em; color: #d97706; margin-bottom: 2px; }
.yv-std .danger { background: color-mix(in srgb, #ef4444 9%, var(--surface)); color: var(--text); border-left: 4px solid #ef4444; border-radius: 0 14px 14px 0; }
.yv-std .danger::before { content: '❗ WARNING'; display: block; font-size: 10px; font-weight: 750; letter-spacing: .08em; color: #dc2626; margin-bottom: 2px; }
.yv-std .tip strong, .yv-std .warn strong, .yv-std .danger strong { background-image: none; }

/* 表格：表头按当前标签色着色，首列加粗 */
.yv-std th { background: color-mix(in srgb, var(--tabc) 13%, var(--surface-2)); color: color-mix(in srgb, var(--tabc) 62%, var(--text)); font-weight: 700; border-bottom: 2px solid color-mix(in srgb, var(--tabc) 35%, var(--line)); }
.yv-std td:first-child { font-weight: 600; }
.yv-std tbody tr:hover td { background: color-mix(in srgb, var(--tabc) 6%, transparent); }
.yv-std .badge, .yv-std .b-blue { font-weight: 650; }
.yv-std td:first-child strong, .yv-std td:first-child b { background-image: none !important; padding: 0; }
</style>
<script>(function(){try{var t=localStorage.getItem("yv-theme");if(!t)t=matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light";document.documentElement.setAttribute("data-theme",t);if(innerWidth<=768||localStorage.getItem("sb-collapsed")==="1")document.documentElement.classList.add("sb-init")}catch(e){}})()</script>
</head>
<body>

<header id="header">
  <button id="sb-toggle" class="icon-btn" onclick="toggleSidebar()" title="Toggle sidebar">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
      <line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/>
    </svg>
  </button>
  <div class="logo">
    <div class="logo-icon">Y</div>
    Young Vault
    <span class="logo-tagline">Your personal knowledge hub</span>
  </div>
  <nav class="breadcrumb" id="breadcrumb" aria-label="Navigation"></nav>
  <div id="search-wrap">
    <input id="search-input" type="search" placeholder="搜索  ( / )" autocomplete="off" aria-label="搜索">
    <div id="search-results"></div>
  </div>
  <button id="theme-toggle" class="icon-btn" onclick="toggleTheme()" title="深色 / 浅色" aria-label="切换主题">
    <svg class="i-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>
    <svg class="i-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
  </button>
  <div id="read-progress"></div>
</header>

<div id="layout">
  <aside id="sidebar">
    <div class="sidebar-section-label">Navigation</div>
    <button class="sidebar-home-btn" id="sb-home" onclick="goHome()">🏠 Home</button>
    <div id="sb-subject-section" style="display:none">
      <div class="sidebar-subject-name" id="sb-subject-label"></div>
      <div id="sb-week-list"></div>
    </div>
    <button class="sidebar-home-btn sidebar-forget" onclick="forgetPasswords()">🔑 清除已记住的密码</button>
  </aside>

  <!-- Password modal -->
  <div id="pw-overlay">
    <div id="pw-box">
      <div id="pw-icon">🔒</div>
      <div id="pw-title">访问受限</div>
      <div id="pw-subtitle"></div>
      <input id="pw-input" type="password" placeholder="请输入访问密码"
        onkeydown="if(event.key==='Enter')submitPassword()">
      <label id="pw-remember-row"><input type="checkbox" id="pw-remember"> 在此设备上记住密码</label>
      <div id="pw-error-msg"></div>
      <div id="pw-btn-row">
        <button id="pw-cancel" onclick="closePasswordModal()">取消</button>
        <button id="pw-submit" onclick="submitPassword()">进入 →</button>
      </div>
    </div>
  </div>

  <main id="main">
    <section id="view-home" class="view active">
      <div class="hero">
        <div class="hero-eyebrow" id="hero-eyebrow"></div>
        <h1 class="home-title">Welcome back <span class="wave">👋</span></h1>
        <p class="home-subtitle">Select a subject to start reviewing.</p>
        <div class="home-stats" id="home-stats"></div>
        <div id="continue-wrap"></div>
      </div>
      <div class="subjects-grid" id="subjects-grid"></div>
    </section>

    <section id="view-subject" class="view">
      <div class="subject-header">
        <div class="subject-header-code" id="subj-code"></div>
        <div class="subject-header-name" id="subj-name"></div>
        <div class="subject-header-desc" id="subj-desc"></div>
        <div class="progress-row" id="subj-progress"></div>
      </div>
      <div id="subject-module-list"></div>
    </section>

    <section id="view-module" class="view">
      <div class="module-content-wrapper" id="module-content"></div>
    </section>

    <button id="to-top" onclick="scrollToTop()" title="回到顶部" aria-label="回到顶部"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M5 12l7-7 7 7"/></svg></button>
    <div id="zoom-bar">
      <button id="zoom-out" onclick="adjustZoom(-1)" title="缩小">−</button>
      <span id="zoom-label" onclick="resetZoom()" title="点击还原100%">100%</span>
      <button id="zoom-in" onclick="adjustZoom(1)" title="放大">+</button>
    </div>
  </main>
</div>

<script>
const SUBJECTS = """ + subjects_json + r""";

// ===== 数据索引 =====
const subjectById = {};
const moduleById = {};
const contentCache = {};   // moduleId -> html（加密科目解锁后才有）
const unlocked = {};
for (const s of SUBJECTS) {
  subjectById[s.id] = s;
  for (const m of s.modules) {
    moduleById[m.id] = m;
    if (m.content != null) { contentCache[m.id] = m.content; delete m.content; }
  }
}
const isMobile = () => window.innerWidth <= 768;

// ===== 安全存储（隐私模式下可能抛错）=====
function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
function lsDel(k) { try { localStorage.removeItem(k); } catch (e) {} }
function ssGet(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } }
function ssSet(k, v) { try { sessionStorage.setItem(k, v); } catch (e) {} }

// ===== 解密 =====
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function tryUnlock(id, pw) {
  const e = subjectById[id].enc;
  try {
    const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: b64d(e.salt), iterations: e.iter, hash: 'SHA-256' },
      km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(e.iv) }, key, b64d(e.data));
    Object.assign(contentCache, JSON.parse(new TextDecoder().decode(buf)));
    unlocked[id] = true;
    return true;
  } catch (err) { return false; }
}
async function ensureUnlocked(id) {
  const s = subjectById[id];
  if (!s || !s.enc || unlocked[id]) return true;
  const saved = ssGet('yv-pw-' + id) || lsGet('yv-pw-' + id);
  if (saved && await tryUnlock(id, saved)) return true;
  return false;
}

// ===== 密码弹窗 =====
let _pendingSubjectId = null, _pendingAction = null;
function showPasswordModal(id, action) {
  _pendingSubjectId = id; _pendingAction = action || null;
  const s = subjectById[id];
  document.getElementById('pw-subtitle').textContent = s.code + ' — ' + s.name;
  const inp = document.getElementById('pw-input');
  inp.value = ''; inp.classList.remove('error');
  document.getElementById('pw-error-msg').textContent = '';
  document.getElementById('pw-overlay').classList.add('visible');
  setTimeout(() => inp.focus(), 80);
}
function closePasswordModal() {
  document.getElementById('pw-overlay').classList.remove('visible');
  _pendingSubjectId = null; _pendingAction = null;
}
async function submitPassword() {
  const inp = document.getElementById('pw-input');
  const pw = inp.value;
  if (!pw || !_pendingSubjectId) return;
  const id = _pendingSubjectId, action = _pendingAction;
  const btn = document.getElementById('pw-submit');
  btn.disabled = true; btn.textContent = '验证中…';
  const ok = await tryUnlock(id, pw);
  btn.disabled = false; btn.textContent = '进入 →';
  if (ok) {
    if (document.getElementById('pw-remember').checked) lsSet('yv-pw-' + id, pw);
    else ssSet('yv-pw-' + id, pw);
    closePasswordModal();
    renderHomeGrid();
    if (action) action(); else goSubject(id);
  } else {
    document.getElementById('pw-error-msg').textContent = '密码错误，请重试';
    inp.classList.add('error'); inp.value = ''; inp.focus();
    setTimeout(() => inp.classList.remove('error'), 400);
  }
}
document.getElementById('pw-overlay').addEventListener('click', function(e) {
  if (e.target === this) closePasswordModal();
});
// 忘记已保存的密码（换设备或改密码后用）
function forgetPasswords() {
  for (const s of SUBJECTS) { lsDel('yv-pw-' + s.id); try { sessionStorage.removeItem('yv-pw-' + s.id); } catch (e) {} }
  location.reload();
}

// ===== 已读进度 =====
let readSet = new Set();
try { readSet = new Set(JSON.parse(lsGet('yv-read') || '[]')); } catch (e) {}
function markRead(id) { if (!readSet.has(id)) { readSet.add(id); lsSet('yv-read', JSON.stringify([...readSet])); } }
const readCount = s => s.modules.filter(m => readSet.has(m.id)).length;

// ===== 缩放 =====
const ZOOM_STEPS = [50, 75, 100, 125, 150, 175, 200];
let zoomIdx = 2;
function applyZoom() {
  const z = ZOOM_STEPS[zoomIdx];
  const mc = document.getElementById('module-content');
  mc.style.transform = `scale(${z/100})`;
  mc.style.marginBottom = z > 100 ? `${(z-100)*3}px` : '0';
  document.getElementById('zoom-label').textContent = z + '%';
  document.getElementById('zoom-out').disabled = zoomIdx === 0;
  document.getElementById('zoom-in').disabled = zoomIdx === ZOOM_STEPS.length - 1;
}
function adjustZoom(dir) { zoomIdx = Math.max(0, Math.min(ZOOM_STEPS.length-1, zoomIdx+dir)); applyZoom(); }
function resetZoom() { zoomIdx = 2; applyZoom(); }
applyZoom();

// ===== 侧边栏 =====
function toggleSidebar() {
  const collapsed = document.getElementById('sidebar').classList.toggle('collapsed');
  if (!isMobile()) lsSet('sb-collapsed', collapsed ? '1' : '0');
}
(function() {
  if (isMobile() || lsGet('sb-collapsed') === '1')
    document.getElementById('sidebar').classList.add('collapsed');
  requestAnimationFrame(() => requestAnimationFrame(() => document.documentElement.classList.remove('sb-init')));
})();
document.getElementById('main').addEventListener('click', () => {
  const sb = document.getElementById('sidebar');
  if (isMobile() && !sb.classList.contains('collapsed')) sb.classList.add('collapsed');
});
function collapseSidebarOnMobile() {
  if (isMobile()) document.getElementById('sidebar').classList.add('collapsed');
}

// ===== 状态 =====
let currentView = 'home';
let currentSubjectId = null;
let currentModuleId = null;
let _navByCode = false;

function groupByWeek(mods) {
  const map = {}, order = [];
  for (const m of mods) {
    if (!map[m.week]) { map[m.week] = []; order.push(m.week); }
    map[m.week].push(m);
  }
  return order.map(w => ({ week: w, modules: map[w] }));
}
const esc = t => String(t).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

// ===== 渲染 =====
function renderHomeGrid() {
  let html = '', totalMods = 0, totalRead = 0;
  SUBJECTS.forEach((s, i) => {
    const done = readCount(s), total = s.modules.length;
    totalMods += total; totalRead += done;
    const lock = s.enc && !unlocked[s.id] ? '<span class="sc-lock" title="需要密码">🔒</span>' : '';
    html += `
      <div class="subject-card" style="--card-accent:${s.accent};--i:${i}" onclick="goSubject('${s.id}')" role="button" tabindex="0">
        <div class="sc-top"><span class="subject-card-code">${s.code}</span>${lock}</div>
        <div class="subject-card-name">${s.name}</div>
        <div class="subject-card-desc">${s.desc} · ${total} modules</div>
        <div class="sc-foot"><div class="progress-row">
          <div class="progress-bar"><i style="width:${total ? done/total*100 : 0}%;background:${s.accent}"></i></div>
          <span class="progress-text">已读 ${done}/${total}</span>
        </div></div>
        <span class="sc-arrow">→</span>
      </div>`;
  });
  document.getElementById('subjects-grid').innerHTML = html;
  document.getElementById('home-stats').innerHTML =
    `<span class="stat-chip"><b>${SUBJECTS.length}</b> subjects</span><span class="stat-chip"><b>${totalMods}</b> modules</span><span class="stat-chip"><b>${totalRead}</b> read 已读</span>`;
  const h = new Date().getHours();
  document.getElementById('hero-eyebrow').textContent =
    (h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening') + ' · ' +
    new Date().toLocaleDateString('en-AU', { weekday: 'long', day: 'numeric', month: 'long' });
  const last = lsGet('yv-last'), m = last && moduleById[last], wrap = document.getElementById('continue-wrap');
  if (m) {
    const s = subjectById[m.subject_id];
    wrap.innerHTML = `<button class="continue-card" style="--cc:${m.color || s.accent}" onclick="goModule('${m.id}')">
      <span class="cc-play">▶</span>
      <span><div class="cc-label">Continue · 继续学习</div><div class="cc-title">${esc(m.title)}</div><div class="cc-sub">${s.code} · ${esc(m.week)}</div></span>
      <span class="cc-go">→</span></button>`;
  } else wrap.innerHTML = '';
}

function renderBreadcrumb() {
  const bc = document.getElementById('breadcrumb');
  let html = '<button class="breadcrumb-item" onclick="goHome()">Young Vault</button>';
  if (currentView === 'subject' || currentView === 'module') {
    const s = subjectById[currentSubjectId];
    html += '<span class="breadcrumb-sep">›</span>';
    if (currentView === 'subject') {
      html += `<button class="breadcrumb-item active">${s ? s.code : ''}</button>`;
    } else {
      html += `<button class="breadcrumb-item" onclick="goSubject('${currentSubjectId}')">${s ? s.code : ''}</button>`;
      const mod = moduleById[currentModuleId];
      html += '<span class="breadcrumb-sep">›</span>';
      html += `<button class="breadcrumb-item active">${mod ? mod.title : ''}</button>`;
    }
  }
  bc.innerHTML = html;
}

function renderSidebar() {
  const sbHome = document.getElementById('sb-home');
  const sec = document.getElementById('sb-subject-section');
  if (currentView === 'home') {
    sbHome.className = 'sidebar-home-btn active';
    sec.style.display = 'none';
  } else {
    sbHome.className = 'sidebar-home-btn';
    sec.style.display = 'block';
    const s = subjectById[currentSubjectId];
    document.getElementById('sb-subject-label').textContent = s ? s.code : '';
    let html = '';
    for (const g of groupByWeek(s ? s.modules : [])) {
      html += `<div class="sidebar-week-header">${g.week}</div>`;
      for (const m of g.modules) {
        const active = m.id === currentModuleId ? ' active' : '';
        const done = readSet.has(m.id) ? '<span class="sb-done">✓</span>' : '';
        html += `<button class="sidebar-module-btn${active}" style="--mc:${m.color}" onclick="goModule('${m.id}')">
          <div class="sb-texts"><span class="sb-en">${m.title}</span><span class="sb-zh">${m.subtitle}</span></div>${done}
        </button>`;
      }
    }
    document.getElementById('sb-week-list').innerHTML = html;
  }
}

function renderSubjectModules() {
  const s = subjectById[currentSubjectId];
  if (!s) return;
  document.getElementById('subj-code').textContent = s.code;
  document.getElementById('subj-name').textContent = s.name;
  document.getElementById('subj-desc').textContent = s.desc;
  const done = readCount(s), total = s.modules.length;
  document.getElementById('subj-progress').innerHTML =
    `<div class="progress-bar"><i style="width:${total ? done/total*100 : 0}%;background:${s.accent}"></i></div><span class="progress-text">已读 ${done}/${total}</span>`;
  let html = '', n = 0;
  const groups = groupByWeek(s.modules), flat = groups.every(g => g.modules.length === 1);
  const card = m => {
    const dn = readSet.has(m.id) ? '<span class="card-done">✓ 已读</span>' : '';
    return `<div class="module-card" style="--card-color:${m.color};--i:${n++}" onclick="goModule('${m.id}')" role="button" tabindex="0">
        <div class="module-card-week">${m.week}${dn}</div>
        <div class="module-card-title">${m.title}</div>
        <div class="module-card-subtitle">${m.subtitle}</div>
      </div>`;
  };
  if (flat) html = `<div class="week-group"><div class="modules-grid">${s.modules.map(card).join('')}</div></div>`;
  else for (const g of groups) {
    html += `<div class="week-group"><div class="week-group-header">${g.week}</div><div class="modules-grid">${g.modules.map(card).join('')}</div></div>`;
  }
  document.getElementById('subject-module-list').innerHTML = html;
}

function updateTitle() {
  let t = 'Young Vault';
  const s = subjectById[currentSubjectId], m = moduleById[currentModuleId];
  if (currentView === 'module' && m) t = m.title + ' · ' + s.code + ' · Young Vault';
  else if (currentView === 'subject' && s) t = s.code + ' · Young Vault';
  document.title = t;
}

function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('view-' + name).classList.add('active');
  currentView = name;
  document.getElementById('main').scrollTo({ top: 0, behavior: 'instant' });
  document.getElementById('read-progress').style.width = '0';
  document.getElementById('to-top').classList.remove('show');
  setAccent();
  document.getElementById('zoom-bar').classList.toggle('visible', name === 'module');
  renderBreadcrumb(); renderSidebar(); updateTitle();
}

// ===== 导航 =====
function goHome() {
  currentSubjectId = null; currentModuleId = null;
  _navByCode = true; location.hash = ''; _navByCode = false;
  renderHomeGrid();
  showView('home');
  collapseSidebarOnMobile();
}

async function goSubject(id) {
  if (!subjectById[id]) { goHome(); return; }
  if (!(await ensureUnlocked(id))) { showPasswordModal(id, () => goSubject(id)); return; }
  currentSubjectId = id; currentModuleId = null;
  _navByCode = true; location.hash = 'subject/' + id; _navByCode = false;
  renderSubjectModules();
  showView('subject');
  collapseSidebarOnMobile();
}

async function goModule(id) {
  const mod = moduleById[id];
  if (!mod) { goHome(); return; }
  if (!(await ensureUnlocked(mod.subject_id))) { showPasswordModal(mod.subject_id, () => goModule(id)); return; }
  currentModuleId = id; currentSubjectId = mod.subject_id;
  _navByCode = true; location.hash = 'module/' + id; _navByCode = false;
  markRead(id);

  const mods = subjectById[mod.subject_id].modules;
  const i = mods.findIndex(m => m.id === id);
  const prev = mods[i-1], next = mods[i+1];
  const nav = `<div class="mod-nav">
    ${prev ? `<button class="mod-nav-btn" onclick="goModule('${prev.id}')">← ${esc(prev.week)} · ${esc(prev.title)}</button>` : '<span></span>'}
    ${next ? `<button class="mod-nav-btn next" onclick="goModule('${next.id}')">${esc(next.week)} · ${esc(next.title)} →</button>` : '<span></span>'}
  </div>`;

  const contentDiv = document.getElementById('module-content');
  contentDiv.innerHTML = contentCache[id] + nav;
  contentDiv.querySelectorAll('script').forEach(old => {
    const s = document.createElement('script');
    s.textContent = old.textContent;
    old.replaceWith(s);
  });
  enhanceModule(contentDiv, mod._h);
  contentDiv.classList.toggle('yv-dark', !!subjectById[mod.subject_id].enc);
  lsSet('yv-last', id);
  showView('module');
  collapseSidebarOnMobile();
}

function routeFromHash() {
  const hash = location.hash.slice(1);
  if (hash.startsWith('module/')) goModule(hash.slice(7));
  else if (hash.startsWith('subject/')) goSubject(hash.slice(8));
  else goHome();
}
window.addEventListener('hashchange', function() { if (!_navByCode) routeFromHash(); });

// ===== 搜索 =====
const searchText = {};   // moduleId -> 纯文本（懒加载）
function textOf(id) {
  if (searchText[id] != null) return searchText[id];
  const html = contentCache[id];
  if (html == null) return null;
  const doc = new DOMParser().parseFromString(html, 'text/html');
  doc.querySelectorAll('style,script').forEach(n => n.remove());
  return searchText[id] = doc.body.textContent.replace(/\s+/g, ' ').trim();
}
function runSearch(q) {
  q = q.trim().toLowerCase();
  const box = document.getElementById('search-results');
  if (!q) { box.classList.remove('visible'); return; }
  const hits = [];
  for (const s of SUBJECTS) {
    for (const m of s.modules) {
      const head = (m.title + ' ' + m.subtitle + ' ' + m.week).toLowerCase();
      const body = textOf(m.id);
      const inHead = head.includes(q);
      const pos = body ? body.toLowerCase().indexOf(q) : -1;
      if (!inHead && pos < 0) continue;
      let snip = '';
      if (pos >= 0) {
        const a = Math.max(0, pos - 30);
        snip = (a > 0 ? '…' : '') + body.slice(a, pos + q.length + 60) + '…';
      }
      hits.push({ m, s, score: inHead ? 0 : 1, snip, locked: s.enc && !unlocked[s.id] });
    }
  }
  hits.sort((a, b) => a.score - b.score);
  const re = new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'ig');
  let html = '';
  for (const h of hits.slice(0, 12)) {
    html += `<div class="sr-item" onclick="openSearchHit('${h.m.id}')">
      <div class="sr-title">${esc(h.m.title)} <span class="sr-tag">${h.s.code} · ${esc(h.m.week)}${h.locked ? ' 🔒' : ''}</span></div>
      ${h.snip ? `<div class="sr-snip">${esc(h.snip).replace(re, '<mark>$1</mark>')}</div>` : ''}
    </div>`;
  }
  if (!html) html = '<div class="sr-empty">没有找到匹配内容' + (SUBJECTS.some(s => s.enc && !unlocked[s.id]) ? '（未解锁科目只能搜标题）' : '') + '</div>';
  box.innerHTML = html;
  box.classList.add('visible');
}
function openSearchHit(id) {
  closeSearch();
  goModule(id);
}
function closeSearch() {
  document.getElementById('search-results').classList.remove('visible');
  document.getElementById('search-input').value = '';
}
document.getElementById('search-input').addEventListener('input', e => runSearch(e.target.value));
document.getElementById('search-input').addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeSearch(); e.target.blur(); }
  if (e.key === 'Enter') { const f = document.querySelector('#search-results .sr-item'); if (f) f.click(); }
});
document.addEventListener('click', e => {
  if (!e.target.closest('#search-wrap')) document.getElementById('search-results').classList.remove('visible');
});
document.addEventListener('keydown', e => {
  if (e.key === '/' && !/INPUT|TEXTAREA/.test(document.activeElement.tagName)) {
    e.preventDefault(); document.getElementById('search-input').focus();
  }
  if (e.key === 'Enter' && e.target.getAttribute && e.target.getAttribute('role') === 'button') e.target.click();
});

// ===== 主题（浅色 / 深色）=====
function toggleTheme() {
  const nx = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', nx);
  lsSet('yv-theme', nx);
}
function hexHue(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex || ''); if (!m) return 240;
  const n = parseInt(m[1], 16), r = (n >> 16) / 255, g = ((n >> 8) & 255) / 255, b = (n & 255) / 255;
  const mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn; if (!d) return 240;
  let h = mx === r ? ((g - b) / d) % 6 : mx === g ? (b - r) / d + 2 : (r - g) / d + 4;
  return (h * 60 + 360) % 360;
}
const hslc = (h, s = 66, l = 46) => 'hsl(' + (((h % 360) + 360) % 360).toFixed(0) + ' ' + s + '% ' + l + '%)';
// 同一科目内：模块颜色沿色相邻近渐变（科目主色 ±75°）
SUBJECTS.forEach(s => {
  const n = s.modules.length, h0 = hexHue(s.accent), span = Math.min(210, 20 * Math.max(n - 1, 1));
  s.modules.forEach((m, i) => { m._h = h0 + (n > 1 ? (i / (n - 1) - .5) * span : 0); m.color = hslc(m._h); });
});
function setAccent() {
  const s = subjectById[currentSubjectId], m = currentView === 'module' && moduleById[currentModuleId];
  document.documentElement.style.setProperty('--accent', m ? m.color : ((s && s.accent) || '#6366f1'));
}

// ===== 滚动：阅读进度条 + 回到顶部 =====
(function() {
  const main = document.getElementById('main'), bar = document.getElementById('read-progress'), top = document.getElementById('to-top');
  let tick = false;
  main.addEventListener('scroll', () => {
    if (tick) return; tick = true;
    requestAnimationFrame(() => {
      tick = false;
      const h = main.scrollHeight - main.clientHeight;
      bar.style.width = (currentView === 'module' && h > 0) ? (main.scrollTop / h * 100) + '%' : '0';
      top.classList.toggle('show', currentView === 'module' && main.scrollTop > 520);
    });
  }, { passive: true });
})();
function scrollToTop() { document.getElementById('main').scrollTo({ top: 0, behavior: 'smooth' }); }

// ===== 模块增强（新格式模块：滑块标签栏、测验计分、背诵模式、闪卡）=====
function colorizeModule(root, hue) {
  const secs = [...root.querySelectorAll('.sec')], n = secs.length, step = Math.min(18, 100 / Math.max(n - 1, 1));
  const navBtns = [...root.querySelectorAll('.nav button')];
  secs.forEach((sec, k) => {
    const h = hue + (k - (n - 1) / 2) * step;
    sec.style.setProperty('--tabc', hslc(h));
    if (navBtns.length === n) navBtns[k].style.setProperty('--tabc', hslc(h));
    [...sec.querySelectorAll(':scope > .card, .cs-block')].forEach((c, j) => {
      c.style.setProperty('--c1', hslc(h + j * 9, 68, 48)); c.style.setProperty('--c2', hslc(h + j * 9 + 34, 70, 52));
    });
  });
}
function enhanceModule(root, hue) {
  const std = !!root.querySelector('.sec .card');
  root.classList.toggle('yv-std', std);
  if (!std) return;
  colorizeModule(root, hue == null ? 240 : hue);
  root.querySelectorAll('table').forEach(t => {
    if (t.closest('.tbl-scroll')) return;
    const p = t.parentElement;
    if (p !== root && p.children.length === 1 && p.style.overflowX === 'auto') { p.classList.add('tbl-scroll'); return; }
    const w = document.createElement('div'); w.className = 'tbl-scroll';
    p.insertBefore(w, t); w.appendChild(t);
  });
  root.querySelectorAll('.nav').forEach(nav => setupTabs(nav, root));
  setupQuiz(root); setupRecall(root);
  root.querySelectorAll('.deck').forEach(buildDeck);
}

function scrollModuleTop(root) {
  const main = document.getElementById('main');
  const top = root.getBoundingClientRect().top - main.getBoundingClientRect().top + main.scrollTop;
  if (main.scrollTop > top + 8) main.scrollTo({ top: Math.max(0, top - 12), behavior: 'smooth' });
}

function setupTabs(nav, root) {
  nav.classList.add('yv-tabs');
  const ind = document.createElement('span'); ind.className = 'yv-ind';
  nav.insertBefore(ind, nav.firstChild);
  const place = first => {
    const b = nav.querySelector('button.on'); if (!b || !b.offsetWidth) return;
    if (first) ind.style.transition = 'none';
    ind.style.setProperty('--tabc', b.style.getPropertyValue('--tabc') || '');
    ind.style.width = b.offsetWidth + 'px';
    ind.style.transform = 'translateX(' + b.offsetLeft + 'px)';
    if (first) { void ind.offsetWidth; ind.style.transition = ''; }
    nav.scrollTo({ left: Math.max(0, b.offsetLeft - (nav.clientWidth - b.offsetWidth) / 2), behavior: first ? 'auto' : 'smooth' });
  };
  const fades = () => {
    nav.classList.toggle('fade-l', nav.scrollLeft > 4);
    nav.classList.toggle('fade-r', nav.scrollLeft + nav.clientWidth < nav.scrollWidth - 4);
  };
  nav.addEventListener('scroll', fades, { passive: true });
  let raf = 0;
  const mo = new MutationObserver(() => {
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(() => { place(false); fades(); scrollModuleTop(root); });
  });
  nav.querySelectorAll('button').forEach(b => mo.observe(b, { attributes: true, attributeFilter: ['class'] }));
  requestAnimationFrame(() => { place(true); fades(); });
  window.addEventListener('resize', () => { if (nav.isConnected) { place(true); fades(); } });
}

// 测验：进度条 + 计分 + 重做
function setupQuiz(root) {
  root.querySelectorAll('.sec').forEach(sec => {
    const blocks = [...sec.querySelectorAll('.qblock')];
    if (!blocks.length) return;
    const bar = document.createElement('div'); bar.className = 'quiz-bar';
    bar.innerHTML = '<div class="qb-track"><div class="qb-ok"></div><div class="qb-err"></div></div><span class="qb-text"></span><button type="button">↺ Reset 重做</button>';
    blocks[0].parentNode.insertBefore(bar, blocks[0]);
    const okEl = bar.querySelector('.qb-ok'), errEl = bar.querySelector('.qb-err'), txt = bar.querySelector('.qb-text');
    let wasPerfect = false;
    const upd = () => {
      let ok = 0, err = 0;
      blocks.forEach(b => {
        const f = b.querySelector('.q-fb');
        const isOk = !!f && f.classList.contains('ok'), isErr = !!f && f.classList.contains('err');
        b.classList.toggle('is-ok', isOk); b.classList.toggle('is-err', isErr);
        if (isOk) ok++; if (isErr) err++;
      });
      const n = blocks.length;
      okEl.style.width = ok / n * 100 + '%'; errEl.style.left = ok / n * 100 + '%'; errEl.style.width = err / n * 100 + '%';
      const perfect = ok === n;
      bar.classList.toggle('perfect', perfect);
      txt.innerHTML = perfect ? '🎉 <b>' + n + ' / ' + n + '</b> Perfect! 全对' : '<b>' + ok + '</b> / ' + n + ' correct 答对 · ' + (ok + err) + ' answered 已答';
      if (perfect && !wasPerfect) burst(bar);
      wasPerfect = perfect;
    };
    blocks.forEach(b => {
      const f = b.querySelector('.q-fb');
      if (f) new MutationObserver(upd).observe(f, { attributes: true, attributeFilter: ['class'] });
    });
    bar.querySelector('button').addEventListener('click', () => {
      blocks.forEach(b => {
        b.querySelectorAll('input').forEach(i => { i.checked = false; });
        const f = b.querySelector('.q-fb'); if (f) { f.className = 'q-fb'; f.textContent = ''; }
      });
      wasPerfect = false; upd();
    });
    upd();
  });
}

// 小彩带
function burst(el) {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches || !el.animate) return;
  const r = el.getBoundingClientRect(), cols = ['#10b981', '#6366f1', '#f59e0b', '#ec4899', '#0ea5e9'];
  for (let i = 0; i < 28; i++) {
    const d = document.createElement('i');
    d.style.cssText = 'position:fixed;z-index:999;pointer-events:none;width:8px;height:8px;border-radius:2px;left:' + (r.left + r.width / 2) + 'px;top:' + (r.top + r.height / 2) + 'px;background:' + cols[i % cols.length];
    document.body.appendChild(d);
    const a = Math.random() * Math.PI * 2, v = 90 + Math.random() * 150;
    d.animate([
      { transform: 'translate(0,0) rotate(0)', opacity: 1 },
      { transform: 'translate(' + Math.cos(a) * v + 'px,' + (Math.sin(a) * v + 90) + 'px) rotate(' + (Math.random() * 540) + 'deg)', opacity: 0 }
    ], { duration: 900 + Math.random() * 500, easing: 'cubic-bezier(.2,.7,.3,1)' }).onfinish = () => d.remove();
  }
}

// 背诵模式：.cz 关键词模糊遮挡，点击揭晓
function setupRecall(root) {
  root.querySelectorAll('.sec').forEach(sec => {
    if (!sec.querySelector('.cz')) return;
    const bar = document.createElement('div'); bar.className = 'recall-bar';
    bar.innerHTML = '<button type="button" class="sw" aria-label="背诵模式"></button><span><b>Recall mode 背诵模式</b> — key terms are blurred; tap to reveal 关键内容模糊，点一下显示</span><button type="button" class="lnk">👁 Reveal all 全部显示</button>';
    sec.insertBefore(bar, sec.firstChild);
    const sw = bar.querySelector('.sw');
    const set = on => { sw.classList.toggle('on', on); sec.classList.toggle('recall-on', on); if (!on) sec.querySelectorAll('.cz.rev').forEach(z => z.classList.remove('rev')); lsSet('yv-recall', on ? '1' : '0'); };
    sw.addEventListener('click', () => set(!sw.classList.contains('on')));
    bar.querySelector('.lnk').addEventListener('click', () => sec.querySelectorAll('.cz').forEach(z => z.classList.add('rev')));
    sec.addEventListener('click', e => { const z = e.target.closest('.cz'); if (z && sec.classList.contains('recall-on')) z.classList.toggle('rev'); });
    if (lsGet('yv-recall') === '1') set(true);
  });
}

// 闪卡牌组：翻面 / 拖动 / 键盘，进度自动保存
function hashStr(s) { let h = 5381; for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0; return (h >>> 0).toString(36); }
function buildDeck(deck) {
  const cards = [...deck.querySelectorAll(':scope > .fc')].map(el => ({
    id: hashStr(el.querySelector('.fq').textContent), tag: el.dataset.tag || '',
    q: el.querySelector('.fq').innerHTML, a: el.querySelector('.fa').innerHTML }));
  if (!cards.length) return;
  const key = 'yv-deck-' + (deck.dataset.key || 'x');
  let known = new Set(); try { known = new Set(JSON.parse(lsGet(key) || '[]')); } catch (e) {}
  const ids = new Set(cards.map(c => c.id)); known = new Set([...known].filter(x => ids.has(x)));
  let mode = 'todo', shuffled = false, queue = [], busy = false;
  const save = () => lsSet(key, JSON.stringify([...known]));
  const ui = document.createElement('div'); deck.appendChild(ui);
  ui.innerHTML = '<div class="dk-head"><div class="dk-prog"><div class="dk-bar"><i></i></div><span class="dk-count"></span></div>' +
    '<div class="dk-tools"><button class="dk-chip on" data-m="todo">To review 待复习</button><button class="dk-chip" data-m="all">All cards 全部</button>' +
    '<button class="dk-chip sp" data-a="shuffle">🔀 Shuffle 乱序</button><button class="dk-chip" data-a="reset">↺ Reset 清零</button></div></div>' +
    '<div class="dk-stage"></div>' +
    '<div class="dk-actions"><button class="dk-btn no" data-a="no">✗ Again 再看</button><button class="dk-btn flip" data-a="flip">Flip 翻面</button><button class="dk-btn yes" data-a="yes">✓ Got it 记住了</button></div>' +
    '<div class="dk-keys"><kbd>Space</kbd> flip 翻面 · <kbd>←</kbd> again 再看 · <kbd>→</kbd> got it 记住 · drag the card 拖动卡片</div>';
  const stage = ui.querySelector('.dk-stage'), actions = ui.querySelector('.dk-actions'), keys = ui.querySelector('.dk-keys');
  const barI = ui.querySelector('.dk-bar i'), count = ui.querySelector('.dk-count');
  const shuffle = a => { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } };
  const rebuild = () => {
    queue = cards.map((c, i) => i).filter(i => mode === 'all' || !known.has(cards[i].id));
    if (shuffled) shuffle(queue);
    ui.querySelectorAll('[data-m]').forEach(b => b.classList.toggle('on', b.dataset.m === mode));
    ui.querySelector('[data-a="shuffle"]').classList.toggle('on', shuffled);
    show();
  };
  const curCard = () => stage.querySelector('.dk-card');
  const flip = () => { const c = curCard(); if (c && !busy) c.classList.toggle('flipped'); };
  const answer = (yes, dir) => {
    const c = curCard(); if (!c || busy) return; busy = true;
    const d = dir || (yes ? 'right' : 'left');
    c.classList.remove('drag');
    c.style.transform = 'translateX(' + (d === 'right' ? 620 : -620) + 'px) rotate(' + (d === 'right' ? 24 : -24) + 'deg)';
    c.style.opacity = '0';
    setTimeout(() => {
      const idx = queue.shift();
      if (yes) { known.add(cards[idx].id); save(); } else queue.push(idx);
      busy = false; show();
    }, 260);
  };
  function show() {
    const n = cards.length, k = known.size;
    barI.style.width = (k / n * 100) + '%';
    count.innerHTML = '<b>' + k + '</b> / ' + n + ' known 已记住 · ' + queue.length + ' left 剩余';
    if (!queue.length) {
      actions.style.display = 'none'; keys.style.display = 'none';
      stage.style.minHeight = '0';
      stage.innerHTML = '<div class="dk-done"><div class="big">' + (k === n ? '🎉' : '👏') + '</div><h3>' + (k === n ? 'All ' + n + ' cards known! 全部记住了' : 'Round complete 本轮完成') + '</h3>' +
        '<p>' + k + ' / ' + n + ' known 已记住。Come back later — spaced review beats cramming. 隔一段时间再来一遍效果更好。</p>' +
        '<div class="row"><button class="dk-btn flip" data-a="reset">↺ Start over 重新开始</button><button class="dk-btn" data-a="all">Review all cards 复习全部</button></div></div>';
      return;
    }
    actions.style.display = ''; keys.style.display = ''; stage.style.minHeight = '';
    const c = cards[queue[0]];
    stage.innerHTML = (queue.length > 2 ? '<div class="dk-ghost g2"></div>' : '') + (queue.length > 1 ? '<div class="dk-ghost"></div>' : '') +
      '<div class="dk-card enter"><div class="dk-inner">' +
      '<div class="dk-face dk-front"><span class="dk-tag">' + c.tag + '</span><div class="dk-q">' + c.q + '</div><div class="dk-hint">Tap to flip 点击翻面</div></div>' +
      '<div class="dk-face dk-back"><span class="dk-tag">' + c.tag + '</span><div class="dk-a">' + c.a + '</div></div></div>' +
      '<span class="dk-badge yes">GOT IT ✓</span><span class="dk-badge no">AGAIN ✗</span></div>';
    attach(curCard());
  }
  function attach(card) {
    card.addEventListener('animationend', () => card.classList.remove('enter'), { once: true });
    const by = card.querySelector('.dk-badge.yes'), bn = card.querySelector('.dk-badge.no');
    let sx = 0, dx = 0, drag = false, moved = false;
    card.addEventListener('pointerdown', e => {
      if (busy || (e.pointerType === 'mouse' && e.button !== 0)) return;
      drag = true; moved = false; sx = e.clientX; dx = 0; card.classList.add('drag');
      try { card.setPointerCapture(e.pointerId); } catch (err) {}
    });
    card.addEventListener('pointermove', e => {
      if (!drag) return;
      dx = e.clientX - sx; if (Math.abs(dx) > 6) moved = true;
      card.style.transform = 'translateX(' + dx + 'px) rotate(' + (dx / 20) + 'deg)';
      by.style.opacity = Math.max(0, Math.min(1, dx / 90)); bn.style.opacity = Math.max(0, Math.min(1, -dx / 90));
    });
    const end = () => {
      if (!drag) return; drag = false; card.classList.remove('drag');
      if (dx > 110) answer(true, 'right');
      else if (dx < -110) answer(false, 'left');
      else { card.style.transform = ''; by.style.opacity = bn.style.opacity = 0; if (!moved) flip(); }
    };
    card.addEventListener('pointerup', end); card.addEventListener('pointercancel', end);
  }
  ui.addEventListener('click', e => {
    const b = e.target.closest('button'); if (!b) return;
    if (b.dataset.m) { mode = b.dataset.m; rebuild(); }
    else if (b.dataset.a === 'shuffle') { shuffled = !shuffled; rebuild(); }
    else if (b.dataset.a === 'reset') { known.clear(); save(); mode = 'todo'; rebuild(); }
    else if (b.dataset.a === 'all') { mode = 'all'; rebuild(); }
    else if (b.dataset.a === 'flip') flip();
    else if (b.dataset.a === 'yes') answer(true);
    else if (b.dataset.a === 'no') answer(false);
  });
  deck._api = { flip, answer };
  rebuild();
}

// ===== 键盘 / 滑动：切换标签页，闪卡快捷键 =====
document.addEventListener('keydown', e => {
  if (currentView !== 'module' || /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) || e.metaKey || e.ctrlKey || e.altKey) return;
  const mc = document.getElementById('module-content');
  const deck = mc.querySelector('.sec.on .deck');
  if (deck && deck._api) {
    if (e.key === ' ' || e.key === 'Enter') { if (document.activeElement.tagName === 'BUTTON') return; e.preventDefault(); deck._api.flip(); return; }
    if (e.key === 'ArrowRight') { e.preventDefault(); deck._api.answer(true); return; }
    if (e.key === 'ArrowLeft') { e.preventDefault(); deck._api.answer(false); return; }
  }
  if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
    const nav = mc.querySelector('.yv-tabs'); if (!nav) return;
    const btns = [...nav.querySelectorAll('button')], i = btns.findIndex(b => b.classList.contains('on'));
    const j = i + (e.key === 'ArrowRight' ? 1 : -1);
    if (j >= 0 && j < btns.length) { e.preventDefault(); btns[j].click(); }
  }
});
(function() {
  const mc = document.getElementById('module-content');
  let x0 = 0, y0 = 0, ok = false;
  mc.addEventListener('touchstart', e => {
    ok = e.touches.length === 1 && !e.target.closest('.tbl-scroll, .deck, .yv-tabs, .formula, input, textarea');
    x0 = e.touches[0].clientX; y0 = e.touches[0].clientY;
  }, { passive: true });
  mc.addEventListener('touchend', e => {
    if (!ok) return; ok = false;
    const dx = e.changedTouches[0].clientX - x0, dy = e.changedTouches[0].clientY - y0;
    if (Math.abs(dx) < 80 || Math.abs(dy) > 50) return;
    const nav = mc.querySelector('.yv-tabs'); if (!nav) return;
    const btns = [...nav.querySelectorAll('button')], i = btns.findIndex(b => b.classList.contains('on')), j = i + (dx < 0 ? 1 : -1);
    if (j >= 0 && j < btns.length) btns[j].click();
  }, { passive: true });
})();

// ===== 初始化 =====
renderHomeGrid();
renderBreadcrumb(); renderSidebar(); updateTitle();
if (location.hash.length > 1) routeFromHash();
</script>
</body>
</html>"""

out_path = os.path.join(BASE_DIR, "index.html")
with open(out_path, "w", encoding="utf-8") as f:
    f.write(html)

size_kb = os.path.getsize(out_path) / 1024
print(f"✅ Done! Written to {out_path}")
print(f"   File size: {size_kb:.1f} KB")
total_mods = sum(len(s["modules"]) for s in subjects)
print(f"   Subjects: {len(subjects)} | Total modules: {total_mods}")
