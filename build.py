#!/usr/bin/env python3
"""Build script for Young Vault — 读取 subjects.json（科目配置）和 passwords.json（密码，不进 git），
生成单文件 index.html。有密码的科目，内容用 AES-256-GCM 加密后再嵌入。"""

import base64
import hashlib
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


def subject_key(sid, password):
    """每个科目用固定的盐（由科目 id 算出）派生密钥，这样图片包不用每次 build 都重新加密。"""
    salt = hashlib.sha256(("young-vault:" + sid).encode()).digest()[:16]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITER)
    return salt, kdf.derive(password.encode("utf-8"))


FIG_DIR = os.path.join(BASE_DIR, "_figs")   # 明文图片（不进 git）
IMG_OUT = os.path.join(BASE_DIR, "img")     # 加密后的图片包（进 git）


def write_fig_bundle(mid, key):
    """把 _figs/<模块>/ 里的图片打成一个加密 JSON：img/<模块>.json。内容没变就不重写。"""
    src_dir, out = os.path.join(FIG_DIR, mid), os.path.join(IMG_OUT, mid + ".json")
    if not os.path.isdir(src_dir):
        if os.path.exists(out):
            os.remove(out)
        return 0
    imgs = {}
    for fn in sorted(os.listdir(src_dir)):
        ext = os.path.splitext(fn)[1].lower()
        mime = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp"}.get(ext)
        if mime:
            with open(os.path.join(src_dir, fn), "rb") as f:
                imgs[os.path.splitext(fn)[0]] = f"data:{mime};base64," + base64.b64encode(f.read()).decode()
    plain = json.dumps(imgs, sort_keys=True).encode("utf-8")
    h = hashlib.sha256(key + plain).hexdigest()[:24]
    if os.path.exists(out):
        try:
            with open(out, encoding="utf-8") as f:
                if json.load(f).get("h") == h:
                    return len(imgs)
        except (ValueError, OSError):
            pass
    iv = os.urandom(12)
    data = AESGCM(key).encrypt(iv, plain, None)
    os.makedirs(IMG_OUT, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"h": h, "iv": base64.b64encode(iv).decode(), "data": base64.b64encode(data).decode()}, f)
    return len(imgs)


def encrypt_modules(contents, password, sid):
    """contents: {module_id: html}，返回前端可解密的 {salt, iv, iter, data}（base64）。"""
    salt, key = subject_key(sid, password)
    iv = os.urandom(12)
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
        entry["enc"] = encrypt_modules(contents, pw, subj["id"])
        _, key = subject_key(subj["id"], pw)
        nfig = sum(write_fig_bundle(mid, key) for mid in contents)
        if nfig:
            print(f"   {subj['id']}: {nfig} figures encrypted into img/")
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
.view.active { display: block; animation: fadeUp .5s var(--ease) backwards; }

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

/* ===== 知识点跳转：相关知识点标签 / 悬停预览 / 右侧分屏 ===== */
.xrefs { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin: 10px 0 6px; }
.xrefs-l { font-size: 10.5px; font-weight: 750; letter-spacing: .07em; text-transform: uppercase; color: var(--faint); margin-right: 2px; }
.xref { display: inline-flex; align-items: center; gap: 6px; vertical-align: middle; font-size: 12px; font-weight: 600; line-height: 1.3; padding: 3px 10px 3px 4px; border-radius: 99px; cursor: pointer;
  color: color-mix(in srgb, var(--xc, var(--accent)) 68%, var(--text)); background: color-mix(in srgb, var(--xc, var(--accent)) 10%, var(--surface));
  border: 1px solid color-mix(in srgb, var(--xc, var(--accent)) 32%, var(--line)); transition: transform .2s var(--ease), box-shadow .2s, background .2s; user-select: none; white-space: nowrap; }
.xref:hover { transform: translateY(-1px); background: color-mix(in srgb, var(--xc, var(--accent)) 18%, var(--surface)); box-shadow: 0 6px 14px -8px var(--xc, var(--accent)); }
.xref.on { box-shadow: 0 0 0 2px var(--xc, var(--accent)); }
.xref .xw { font-size: 10px; font-weight: 800; letter-spacing: .02em; color: #fff; background: var(--xc, var(--accent)); border-radius: 99px; padding: 2px 7px; }
.xref .xa { font-size: 11px; opacity: .55; margin-left: -2px; }
h4 .xref { margin-left: auto; font-size: 11px; padding: 2px 8px 2px 3px; }
td .xref { margin-top: 6px; font-size: 11px; }

#yv-pop { position: fixed; z-index: 450; width: 400px; max-width: calc(100vw - 24px); max-height: 340px; overflow: hidden; pointer-events: none;
  background: var(--surface); border: 1px solid var(--line); border-radius: 18px; box-shadow: var(--shadow-lg);
  opacity: 0; transform: translateY(8px) scale(.97); transform-origin: top left; transition: opacity .18s, transform .25s var(--ease); }
#yv-pop.show { opacity: 1; transform: none; }
#yv-pop .pp-head { display: flex; align-items: center; gap: 8px; padding: 10px 14px; border-bottom: 1px solid var(--line); background: color-mix(in srgb, var(--pc) 9%, var(--surface)); font-size: 12px; font-weight: 650; color: var(--text); }
#yv-pop .pp-head b { color: #fff; background: var(--pc); border-radius: 99px; padding: 1px 8px; font-size: 10.5px; }
#yv-pop .pp-body { padding: 12px 16px 30px; font-size: 12.5px; zoom: .9; max-height: 290px; overflow: hidden;
  -webkit-mask-image: linear-gradient(#000 72%, transparent); mask-image: linear-gradient(#000 72%, transparent); }
#yv-pop .pp-body .card { border: none !important; padding: 0 !important; margin: 0 !important; box-shadow: none !important; animation: none !important; }
#yv-pop .pp-body .card::before { display: none; }
#yv-pop .pp-foot { position: absolute; left: 0; right: 0; bottom: 0; padding: 7px 14px; font-size: 11px; color: var(--muted); background: var(--surface); border-top: 1px solid var(--line); }

#view-module.split.active { justify-content: flex-start; gap: 18px; padding-right: 18px; }
#view-module.split #module-content { flex: 1 1 0; min-width: 0; }
#split-pane { display: none; }
#view-module.split #split-pane { display: flex; flex-direction: column; flex: 0 0 min(47%, 720px); position: sticky; top: 14px; align-self: flex-start;
  height: calc(100vh - 60px - 28px); background: var(--surface); border: 1px solid color-mix(in srgb, var(--accent) 35%, var(--line)); border-radius: 22px;
  box-shadow: var(--shadow-lg); overflow: hidden; animation: spIn .5s var(--ease); }
@keyframes spIn { from { opacity: 0; transform: translateX(46px); } to { opacity: 1; transform: none; } }
.sp-head { display: flex; align-items: center; gap: 10px; padding: 11px 12px 11px 16px; border-bottom: 1px solid var(--line); background: color-mix(in srgb, var(--accent) 9%, var(--surface)); flex-shrink: 0; }
.sp-week { font-size: 10.5px; font-weight: 800; color: #fff; background: var(--accent); border-radius: 99px; padding: 2px 9px; flex-shrink: 0; }
.sp-title { font-size: 14px; font-weight: 700; color: var(--text); min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.sp-btn { border: 1px solid var(--line-2); background: var(--surface); color: var(--muted); border-radius: 10px; padding: 6px 10px; font-size: 12px; cursor: pointer; transition: all .2s; white-space: nowrap; flex-shrink: 0; }
.sp-btn:hover { color: var(--text); border-color: var(--accent); }
.sp-btn.sp-open { margin-left: auto; }
.sp-btn.sp-close { width: 32px; padding: 6px 0; font-size: 14px; }
.sp-btn.sp-close:hover { background: #ef4444; border-color: #ef4444; color: #fff; }
#split-content { flex: 1 1 auto; min-height: 0; overflow-y: auto; overflow-x: hidden; max-width: none; border: none; border-radius: 0; box-shadow: none; padding: 16px 20px 40px; transform: none !important; scroll-behavior: smooth; }
#split-content .yv-tabs { top: 6px; }
.sp-flash { animation: spFlash 2.2s var(--ease); }
@keyframes spFlash { 0%, 30% { box-shadow: 0 0 0 3px var(--tabc), 0 0 0 9px color-mix(in srgb, var(--tabc) 22%, transparent); } 100% { box-shadow: 0 0 0 0 transparent; } }

#return-pill { position: fixed; left: 50%; bottom: 22px; transform: translate(-50%, 20px); opacity: 0; pointer-events: none; z-index: 210;
  display: flex; align-items: center; gap: 8px; padding: 10px 16px 10px 12px; border-radius: 99px; border: 1px solid var(--line);
  background: color-mix(in srgb, var(--surface) 88%, transparent); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
  box-shadow: var(--shadow-lg); font-size: 13px; font-weight: 600; color: var(--text); cursor: pointer; transition: all .4s var(--ease); }
#return-pill.show { opacity: 1; transform: translate(-50%, 0); pointer-events: auto; }
#return-pill .rp-ico { width: 26px; height: 26px; border-radius: 50%; background: var(--rc, var(--accent)); color: #fff; display: flex; align-items: center; justify-content: center; font-size: 13px; }
#return-pill:hover { transform: translate(-50%, -2px); }

/* 缩写悬停解释 */
.abbr { text-decoration: underline dotted color-mix(in srgb, var(--tabc, var(--accent)) 70%, transparent); text-underline-offset: 3px; text-decoration-thickness: 1.5px; cursor: help; }
#yv-tip { position: fixed; z-index: 460; max-width: 280px; padding: 7px 11px; border-radius: 10px; background: #0f172a; color: #f1f5f9; font-size: 12px; line-height: 1.5;
  box-shadow: 0 10px 24px -8px rgba(0,0,0,.4); pointer-events: none; opacity: 0; transform: translateY(4px); transition: opacity .15s, transform .2s var(--ease); }
#yv-tip.show { opacity: 1; transform: none; }
#yv-tip b { color: #fff; }
#yv-tip span { color: #94e2d5; }
html[data-theme="dark"] #yv-tip { background: #e8ecf7; color: #0f172a; }
html[data-theme="dark"] #yv-tip b { color: #0f172a; }
html[data-theme="dark"] #yv-tip span { color: #0f766e; }

@media (max-width: 900px) {
  #view-module.split #split-pane { position: fixed; left: 0; right: 0; bottom: 0; top: auto; height: 84vh; flex: none; border-radius: 22px 22px 0 0; z-index: 320; animation: sheetIn .45s var(--ease); }
  #view-module.split.active { padding-right: 8px; }
  @keyframes sheetIn { from { transform: translateY(60%); opacity: 0; } to { transform: none; opacity: 1; } }
}

/* ===== 期末复习计划 ===== */
#view-plan { padding: 44px 48px 80px; }
.plan-hero { max-width: 980px; margin-bottom: 26px; }
.exam-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 14px; margin: 6px 0 18px; }
.exam-card { position: relative; overflow: hidden; background: var(--surface); border: 1px solid color-mix(in srgb, var(--ec) 35%, var(--line)); border-radius: 18px; padding: 16px 16px 14px; box-shadow: var(--shadow-sm);
  animation: fadeUp .5s var(--ease) both; }
.exam-card::before { content: ''; position: absolute; inset: 0 0 auto 0; height: 4px; background: var(--ec); }
.exam-card.past { opacity: .55; }
.ec-top { display: flex; align-items: center; justify-content: space-between; gap: 6px; margin-bottom: 8px; }
.ec-code { font-size: 11px; font-weight: 800; letter-spacing: .06em; color: color-mix(in srgb, var(--ec) 70%, var(--text)); background: color-mix(in srgb, var(--ec) 13%, transparent); padding: 2px 8px; border-radius: 99px; }
.ec-left { font-size: 12px; font-weight: 750; color: var(--text); }
.ec-name { font-size: 15px; font-weight: 750; line-height: 1.3; color: var(--text); }
.ec-when { font-size: 13px; color: var(--muted); margin: 4px 0 10px; font-variant-numeric: tabular-nums; }
.ec-tags { display: flex; flex-wrap: wrap; gap: 5px; }
.ec-tags span { font-size: 10.5px; font-weight: 600; color: var(--muted); background: var(--surface-2); border: 1px solid var(--line); border-radius: 99px; padding: 2px 8px; }
.ec-tags span.hot { color: #b91c1c; background: color-mix(in srgb, #ef4444 10%, var(--surface)); border-color: color-mix(in srgb, #ef4444 35%, var(--line)); }
html[data-theme="dark"] .ec-tags span.hot { color: #fca5a5; }
.plan-total { max-width: 520px; }
.plan-legend { margin-top: 14px; font-size: 12.5px; color: var(--muted); background: var(--surface-2); border: 1px dashed var(--line-2); border-radius: 12px; padding: 10px 14px; max-width: 980px; }
.plan-phase { max-width: 980px; display: flex; align-items: center; gap: 10px; margin: 26px 0 10px; font-size: 11.5px; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; color: var(--pc); }
.plan-phase::after { content: ''; flex: 1; height: 2px; border-radius: 2px; background: linear-gradient(90deg, color-mix(in srgb, var(--pc) 45%, transparent), transparent); }
.plan-day { max-width: 980px; position: relative; background: var(--surface); border: 1px solid var(--line); border-left: 4px solid var(--pc); border-radius: 16px; padding: 12px 16px 10px; margin-bottom: 10px; box-shadow: var(--shadow-sm); transition: opacity .3s, box-shadow .3s, transform .3s var(--ease); }
.plan-day.past { opacity: .72; }
.plan-day.today { box-shadow: 0 0 0 3px color-mix(in srgb, var(--pc) 30%, transparent), var(--shadow-md); transform: translateX(4px); }
.plan-day.examday { background: color-mix(in srgb, #f59e0b 8%, var(--surface)); }
.plan-day.complete .pd-title { text-decoration: line-through; text-decoration-color: color-mix(in srgb, var(--text) 35%, transparent); color: var(--muted); }
.pd-head { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; flex-wrap: wrap; }
.pd-date { font-size: 12px; font-weight: 800; color: var(--pc); min-width: 92px; font-variant-numeric: tabular-nums; }
.pd-today { font-size: 10.5px; font-weight: 800; letter-spacing: .06em; color: #fff; background: var(--pc); padding: 2px 8px; border-radius: 99px; animation: popIn .5s var(--ease); }
.pd-title { font-size: 14px; font-weight: 700; color: var(--text); flex: 1; min-width: 180px; }
.pd-count { font-size: 12px; font-weight: 700; color: var(--faint); font-variant-numeric: tabular-nums; }
.plan-day.complete .pd-count { color: #10b981; }
.plan-task { display: flex; align-items: center; gap: 10px; padding: 7px 8px; border-radius: 10px; cursor: pointer; font-size: 13.5px; color: var(--text); transition: background .15s; }
.plan-task:hover { background: var(--surface-2); }
.pt-box { width: 18px; height: 18px; flex-shrink: 0; border-radius: 6px; border: 2px solid var(--line-2); background: var(--surface); position: relative; transition: all .25s var(--ease); }
.plan-task.done .pt-box { background: #10b981; border-color: #10b981; transform: scale(1.05); }
.plan-task.done .pt-box::after { content: ''; position: absolute; left: 4.5px; top: 1px; width: 5px; height: 9px; border: solid #fff; border-width: 0 2.5px 2.5px 0; transform: rotate(45deg); animation: popIn .25s var(--ease); }
.plan-task.done .pt-text { color: var(--faint); text-decoration: line-through; }
.pt-text { flex: 1; line-height: 1.5; }
.pt-open { flex-shrink: 0; border: 1px solid color-mix(in srgb, var(--mc) 35%, var(--line)); background: color-mix(in srgb, var(--mc) 9%, var(--surface)); color: color-mix(in srgb, var(--mc) 70%, var(--text)); border-radius: 99px; padding: 3px 10px; font-size: 11.5px; font-weight: 650; cursor: pointer; transition: all .2s var(--ease); white-space: nowrap; }
.pt-open:hover { transform: translateX(2px); background: color-mix(in srgb, var(--mc) 18%, var(--surface)); }
.home-plan-card { max-width: 640px; margin-top: 16px; background: var(--surface); border: 1px solid var(--line); border-radius: 18px; padding: 16px 18px; box-shadow: var(--shadow-md); }
.hp-head { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.hp-title { font-size: 14.5px; font-weight: 750; color: var(--text); }
.hp-open { margin-left: auto; border: 1px solid var(--line-2); background: var(--surface-2); color: var(--text); border-radius: 10px; padding: 5px 11px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all .2s; }
.hp-open:hover { border-color: var(--accent); transform: translateX(2px); }
.hp-exams { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
.hp-ex { font-size: 11.5px; color: var(--muted); background: color-mix(in srgb, var(--ec) 10%, var(--surface)); border: 1px solid color-mix(in srgb, var(--ec) 30%, var(--line)); border-radius: 99px; padding: 3px 10px; }
.hp-ex b { color: color-mix(in srgb, var(--ec) 70%, var(--text)); margin-right: 3px; }
.hp-day { border-top: 1px solid var(--line); padding-top: 8px; margin-bottom: 10px; }
.hp-dlabel { font-size: 12px; font-weight: 700; color: var(--muted); margin: 2px 0 4px; }

@media (max-width: 768px) { #view-plan { padding: 24px 14px 70px; } .plan-day.today { transform: none; } .pt-open { padding: 3px 8px; } }

/* ===== 计划编辑 ===== */
.plan-toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 14px 0 0; max-width: 980px; }
.pl-sp { flex: 1; }
.pl-btn { border: 1px solid var(--line-2); background: var(--surface); color: var(--text); border-radius: 10px; padding: 7px 12px; font-size: 12.5px; font-weight: 600; cursor: pointer; transition: all .2s var(--ease); display: inline-flex; align-items: center; gap: 4px; }
.pl-btn:hover { border-color: var(--accent); transform: translateY(-1px); }
.pl-btn.primary { background: var(--accent-strong); border-color: var(--accent-strong); color: #fff; box-shadow: 0 6px 14px -6px var(--accent-strong); }
#view-plan.editing .pl-btn.primary { background: #10b981; border-color: #10b981; box-shadow: 0 6px 14px -6px #10b981; }
.pl-tag { font-size: 11px; font-weight: 700; color: var(--accent-ink); background: color-mix(in srgb, var(--accent) 12%, transparent); padding: 3px 9px; border-radius: 99px; }
.plan-task { position: relative; }
.plan-task.mine .pt-text::after { content: '✦ mine'; font-size: 10px; font-weight: 700; color: #8b5cf6; margin-left: 8px; vertical-align: 1px; }
.plan-task.flash { animation: ptFlash 1.2s var(--ease); }
@keyframes ptFlash { 0%, 40% { background: color-mix(in srgb, #f59e0b 22%, transparent); } 100% { background: transparent; } }
.pt-grip { cursor: grab; color: var(--faint); font-size: 13px; letter-spacing: -2px; padding: 0 2px; user-select: none; }
.pt-grip:active { cursor: grabbing; }
.plan-task.dragging { opacity: .35; }
.pt-drop { height: 3px; border-radius: 3px; background: var(--accent); margin: 2px 8px; box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 20%, transparent); }
.pt-acts { display: inline-flex; gap: 3px; align-items: center; flex-shrink: 0; }
.pt-acts button, .pt-acts select { border: 1px solid var(--line); background: var(--surface-2); color: var(--muted); border-radius: 8px; height: 26px; min-width: 26px; padding: 0 6px; font-size: 12px; cursor: pointer; transition: all .15s; }
.pt-acts select { max-width: 120px; padding: 0 4px; }
.pt-acts button:hover, .pt-acts select:hover { color: var(--text); border-color: var(--accent); }
.pt-acts button[data-act="del"]:hover { background: #ef4444; border-color: #ef4444; color: #fff; }
.pt-edit { flex: 1; font: inherit; font-size: 13.5px; padding: 4px 8px; border: 1.5px solid var(--accent); border-radius: 8px; background: var(--surface); color: var(--text); outline: none; }
.pd-add input { width: 100%; margin-top: 4px; border: 1px dashed transparent; background: transparent; color: var(--text); font-size: 13px; padding: 6px 8px 6px 36px; border-radius: 10px; outline: none; transition: all .2s; }
.pd-add input::placeholder { color: var(--faint); }
.pd-add input:hover { border-color: var(--line-2); }
.pd-add input:focus { border: 1px solid var(--accent); background: var(--surface-2); padding-left: 10px; }
.pd-note-btn { border: none; background: none; cursor: pointer; font-size: 14px; opacity: .35; padding: 2px 4px; border-radius: 6px; transition: opacity .2s, background .2s; }
.pd-note-btn:hover, .pd-note-btn.has { opacity: 1; }
.pd-note-btn:hover { background: var(--surface-2); }
.pd-note { display: none; margin-top: 6px; }
.pd-note.open { display: block; animation: popIn .25s var(--ease); }
.pd-note textarea { width: 100%; resize: vertical; min-height: 54px; font: inherit; font-size: 13px; line-height: 1.6; padding: 8px 10px; border-radius: 10px; border: 1px solid var(--line-2); background: color-mix(in srgb, #f59e0b 5%, var(--surface)); color: var(--text); outline: none; }
.pd-note textarea:focus { border-color: var(--accent); }
#plan-toast { position: fixed; left: 50%; bottom: 24px; transform: translate(-50%, 20px); opacity: 0; pointer-events: none; z-index: 600; background: #0f172a; color: #f1f5f9; border-radius: 12px; padding: 10px 14px; font-size: 13px; box-shadow: var(--shadow-lg); transition: all .35s var(--ease); display: flex; gap: 10px; align-items: center; }
#plan-toast.show { opacity: 1; transform: translate(-50%, 0); pointer-events: auto; }
#plan-toast button { border: none; background: #6366f1; color: #fff; border-radius: 8px; padding: 4px 10px; font-size: 12px; font-weight: 700; cursor: pointer; }
html[data-theme="dark"] #plan-toast { background: #e8ecf7; color: #0f172a; }
@media (max-width: 768px) { .pt-acts { flex-wrap: wrap; } .plan-task { flex-wrap: wrap; } .pt-acts select { max-width: 96px; } }
.pt-zh { display: block; font-size: 12px; color: color-mix(in srgb, #0d9488 75%, var(--text)); line-height: 1.5; margin-top: 1px; }
html[data-theme="dark"] .pt-zh { color: #5fd3c6; }
.plan-task.done .pt-zh { color: var(--faint); }
.plan-task[data-id^="r:"] .pt-text { font-style: normal; }
.plan-task[data-id^="r:"] .pt-box { border-style: dashed; }
.yv-std .zh-line { display: block; margin-top: 3px; font-size: .93em; line-height: 1.6; }
.yv-std td .zh-line, .yv-std th .zh-line { font-size: 12.5px; }
.yv-std .slide .zh-line, .yv-std .tip .zh-line, .yv-std .warn .zh-line, .yv-std .formula .zh-line { margin-top: 6px; font-family: var(--font-sans); }
/* recall mode: hide the Chinese gloss of a line until its hidden terms are revealed */
.recall-on :is(li,td,p,div):has(> .cz:not(.rev), > b > .cz:not(.rev), > strong > .cz:not(.rev)) > .zh { filter: blur(6px); transition: filter .2s; cursor: pointer; }
.recall-on :is(li,td,p,div):has(> .cz:not(.rev), > b > .cz:not(.rev), > strong > .cz:not(.rev)) > .zh:hover { filter: none; }

/* ===== 课件配图（截图 + 重画的网页图） ===== */
.yv-fig { margin: 14px 0 16px; border: 1px solid var(--line); border-radius: 14px; overflow: hidden; background: var(--surface); }
.yv-fig .yv-shot { display: block; width: 100%; height: auto; min-height: 120px; aspect-ratio: 16 / 9; object-fit: contain; background: #fff; cursor: zoom-in; }
.yv-fig.ready .yv-shot { aspect-ratio: auto; min-height: 0; }
.yv-fig:not(.ready):not(.yv-dia) .yv-shot { background: linear-gradient(100deg, var(--surface-2) 30%, var(--surface-3) 50%, var(--surface-2) 70%) 0 0 / 300% 100%; animation: yvShimmer 1.4s linear infinite; }
.yv-fig.fail .yv-shot { animation: none; }
.yv-fig.fail .yv-shot::after { content: '图片加载失败，请刷新'; }
@keyframes yvShimmer { to { background-position: -300% 0; } }
.yv-fig figcaption { padding: 9px 13px 10px; font-size: 13px; line-height: 1.55; color: var(--muted); border-top: 1px solid var(--line); background: var(--surface-2); }
.yv-fig figcaption b { color: var(--text); font-weight: 600; }
.yv-fig figcaption .src { display: inline-block; margin-right: 8px; padding: 1px 8px; border-radius: 99px; font-size: 11.5px; font-weight: 600; color: #fff; background: var(--c1, #6366f1); }
.yv-std .yv-fig figcaption .zh { display: block; margin-top: 2px; }
.yv-dia > .dg { padding: 16px; }
.yv-dia { container-type: inline-size; }

/* 重画的图：通用节点 */
.dg { --dc: var(--c1, #6366f1); font-size: 13.5px; }
.dg .n { position: relative; background: color-mix(in srgb, var(--dc) 11%, var(--surface)); border: 1px solid color-mix(in srgb, var(--dc) 40%, transparent); border-radius: 12px; padding: 9px 10px; text-align: center; line-height: 1.35; min-width: 0; }
.dg .n b { display: block; color: var(--text); font-weight: 650; }
.dg .n small { display: block; color: var(--muted); font-size: 11.5px; margin-top: 3px; }
.yv-std .dg .n .zh { display: block; font-size: 12px; margin-top: 3px; }
.dg .n.hero { background: var(--dc); border-color: var(--dc); }
.dg .n.hero b, .dg .n.hero small { color: #fff; }
.yv-std .dg .n.hero .zh { color: #fff; opacity: .92; }
.dg .n.tot { border-width: 2px; }
.dg .ar { color: var(--muted); font-size: 17px; display: flex; align-items: center; justify-content: center; }
/* 流程（横向；手机和 .v 时竖向） */
.dg-flow { display: flex; align-items: stretch; }
.dg-flow > .n { flex: 1 1 0; }
.dg-flow > .ar { flex: 0 0 22px; }
.dg-flow.v, .dg-flow.v > .n { flex-direction: column; }
.dg-flow.v > .ar { flex-basis: 20px; transform: rotate(90deg); }
.dg-flow.v > .n { flex: none; max-width: 460px; width: 100%; margin: 0 auto; }
@container (max-width: 620px) {
  .dg-flow:not(.mini) { flex-direction: column; }
  .dg-flow:not(.mini) > .ar { flex-basis: 20px; transform: rotate(90deg); }
  .dg-flow:not(.mini) > .n { flex: none; }
}
/* 顾客让渡价值 */
.dg-cdv { display: grid; grid-template-columns: 1fr 26px minmax(130px, 170px); gap: 6px; align-items: center; }
.dg-cdv .rows { display: grid; gap: 7px; min-width: 0; }
.dg-cdv .lab { font-size: 12.5px; font-weight: 600; color: var(--text); }
.dg-cdv .lab small { display: block; font-weight: 400; color: var(--muted); }
.dg-flow.mini { gap: 0; }
.dg-flow.mini > .n { padding: 6px 4px; font-size: 11.5px; flex: 1 1 0; overflow-wrap: break-word; }
.dg-flow.mini > .n b { font-weight: 600; }
.dg-flow.mini > .ar { flex: 0 0 13px; font-size: 12px; }
.dg-cdv .ar.big { font-size: 26px; }
@container (max-width: 680px) { .dg-cdv { grid-template-columns: 1fr; } .dg-cdv .ar.big { transform: rotate(90deg); } }
@container (max-width: 480px) { .dg-flow.mini { flex-wrap: wrap; gap: 5px; } .dg-flow.mini > .ar { display: none; } .dg-flow.mini > .n { flex: 1 1 28%; } }
/* 循环（购买角色） */
.dg-cycle { display: grid; grid-template-columns: repeat(6, 1fr); gap: 8px; }
.dg-cycle .loop { grid-column: 1 / -1; text-align: center; font-size: 12.5px; color: var(--muted); }
@container (max-width: 560px) { .dg-cycle { grid-template-columns: repeat(3, 1fr); } }
/* 十字（五力、产品组合） */
.dg-cross { display: grid; grid-template-columns: 1fr 1.25fr 1fr; grid-template-areas: ". top ." "left mid right" ". bot ."; gap: 10px; align-items: center; max-width: 640px; margin: 0 auto; }
.dg-cross .top { grid-area: top; } .dg-cross .left { grid-area: left; } .dg-cross .mid { grid-area: mid; padding: 16px 10px; } .dg-cross .right { grid-area: right; } .dg-cross .bot { grid-area: bot; }
/* 2×2 矩阵（SWOT） */
.dg-mx { display: grid; grid-template-columns: auto 1fr 1fr; gap: 8px; max-width: 620px; margin: 0 auto; }
.dg-mx .h { font-size: 12.5px; font-weight: 650; text-align: center; align-self: end; color: var(--text); }
.dg-mx .h.side { align-self: center; text-align: right; max-width: 120px; }
.dg-mx .h small { display: block; font-weight: 400; color: var(--muted); }
.yv-std .dg-mx .h .zh { display: block; }
.dg-mx .n { padding: 22px 10px; font-size: 15px; }
/* 金字塔 */
.dg-pyr { display: grid; gap: 4px; max-width: 640px; margin: 0 auto; }
.dg-pyr .lv { width: var(--w); margin: 0 auto; display: flex; gap: 6px; }
.dg-pyr .lv .n { flex: 1; }
.dg-pyr .q { text-align: center; font-size: 12px; color: var(--muted); margin-bottom: 6px; }
@container (max-width: 520px) { .dg-pyr .lv { width: calc(46% + var(--w) * .54); } .dg-pyr .n { padding: 8px 5px; font-size: 12.5px; } }
.dg .n b { overflow-wrap: break-word; }
/* 树（定价方法） */
.dg-tree .root { max-width: 320px; margin: 0 auto 14px; }
.dg-tree .kids { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; position: relative; }
.dg-tree .kids::before { content: ''; position: absolute; left: 12%; right: 12%; top: -8px; border-top: 2px solid var(--line-2); }
@container (max-width: 560px) { .dg-tree .kids { grid-template-columns: 1fr 1fr; } }
/* 填空模板（定位声明） */
.dg-fill { display: grid; gap: 10px; font-size: 16px; line-height: 1.6; max-width: 620px; margin: 0 auto; color: var(--text); }
.dg-fill u { text-decoration: none; display: inline-block; min-width: 110px; border-bottom: 2px solid var(--c1, #6366f1); color: var(--muted); font-size: 12.5px; text-align: center; }
.yv-std .dg-fill .zh { font-size: 12.5px; }
/* SVG 图（韦恩图、三角形） */
.dg-svg { display: block; width: 100%; max-width: 520px; height: auto; margin: 0 auto; }
.dg-svg circle, .dg-svg polygon { stroke-width: 1.5; }
.dg-svg text { text-anchor: middle; }
.dg-svg .ven { fill: var(--text); font-size: 14px; font-weight: 700; }
.dg-svg .ven.sm { font-size: 12.5px; }
.dg-svg .ven.hot { fill: #c2410c; font-size: 15px; }
.dg-svg .vzh { fill: #0d9488; font-size: 12px; }
html[data-theme="dark"] .dg-svg .vzh { fill: #5fd3c6; }
.dg-svg .vsub { fill: var(--muted); font-size: 10.5px; font-style: italic; }
.dg-svg .vbox { fill: var(--surface); stroke: var(--line-2); stroke-width: 1.5; }

/* 图片放大查看 */
#yv-lightbox { position: fixed; inset: 0; z-index: 9999; display: none; flex-direction: column; background: rgba(8, 10, 20, .88); backdrop-filter: blur(4px); }
#yv-lightbox.open { display: flex; animation: yvFade .2s ease; }
@keyframes yvFade { from { opacity: 0; } }
#yv-lightbox .lb-scroll { flex: 1; overflow: auto; display: flex; align-items: center; justify-content: center; padding: 48px 16px 8px; }
#yv-lightbox img { max-width: 100%; max-height: 100%; object-fit: contain; background: #fff; border-radius: 8px; cursor: zoom-in; box-shadow: 0 10px 40px rgba(0,0,0,.5); }
#yv-lightbox.zoom .lb-scroll { align-items: flex-start; justify-content: flex-start; }
#yv-lightbox.zoom img { max-width: none; max-height: none; width: min(2200px, 220vw); cursor: zoom-out; }
#yv-lightbox .lb-cap { max-width: 900px; margin: 0 auto; padding: 8px 18px 16px; color: #e5e7eb; font-size: 13px; line-height: 1.55; }
#yv-lightbox .lb-cap .src { display: inline-block; margin-right: 8px; padding: 1px 8px; border-radius: 99px; background: #6366f1; color: #fff; font-size: 11.5px; font-weight: 600; }
#yv-lightbox .lb-cap .zh { display: block; color: #5fd3c6; }
#yv-lightbox .lb-x { position: absolute; top: 10px; right: 12px; width: 36px; height: 36px; border-radius: 50%; border: 0; background: rgba(255,255,255,.15); color: #fff; font-size: 16px; cursor: pointer; }
html.lb-lock, html.lb-lock body { overflow: hidden; }

/* ===== 测验：锁定后的对错显示、错题标记 ===== */
.yv-std .qblock.locked .q-opts label { cursor: default; transform: none; }
.yv-std .qblock.locked .q-opts label:hover { border-color: var(--line); color: var(--muted); }
.yv-std .qblock.locked .q-opts label.opt-right { border-color: #10b981; color: var(--text); background: color-mix(in srgb, #10b981 13%, var(--surface)); }
.yv-std .qblock.locked .q-opts label.opt-wrong { border-color: #ef4444; color: var(--text); background: color-mix(in srgb, #ef4444 12%, var(--surface)); }
.yv-std .qblock.locked .q-opts label.opt-right::after { content: '✓ 正确答案'; margin-left: auto; padding-left: 10px; color: #059669; font-weight: 700; font-size: 12px; white-space: nowrap; }
.yv-std .qblock.locked .q-opts label.opt-wrong::after { content: '✗ 你的选择'; margin-left: auto; padding-left: 10px; color: #dc2626; font-weight: 700; font-size: 12px; white-space: nowrap; }
.yv-std .q-fb.warn { border-radius: 12px; padding: 8px 12px; font-size: 13px; color: #92400e; background: #fef3c7; }
.yv-std .q-fb .q-expl { margin-top: 5px; color: var(--text); opacity: .9; }
.yv-std .q-wrongtag { display: inline-block; margin-bottom: 8px; padding: 2px 10px; border-radius: 99px; font-size: 11.5px; font-weight: 700; color: #b91c1c; background: color-mix(in srgb, #ef4444 14%, var(--surface)); }
.yv-std .qb-wrong { color: #dc2626; font-weight: 700; }
.sb-wrong { margin-left: auto; padding-left: 6px; color: #ef4444; font-size: 11.5px; font-weight: 700; white-space: nowrap; }
.sb-wrong + .sb-done { margin-left: 0; padding-left: 5px; }
.card-wrong { float: right; margin-left: 8px; color: #dc2626; font-weight: 700; text-transform: none; letter-spacing: 0; }

/* ===== 课堂活动完整参考答案 ===== */
.yv-std .model-ans { margin-top: 18px; padding: 16px 18px 6px; border: 1.5px dashed color-mix(in srgb, var(--tabc) 45%, var(--line)); border-radius: 16px; background: color-mix(in srgb, var(--tabc) 4%, var(--surface)); }
.yv-std .model-ans .ma-head { font-size: 15px; font-weight: 750; margin-bottom: 10px; color: color-mix(in srgb, var(--tabc) 65%, var(--text)); }
.yv-std .model-ans .ma-head .zh { font-weight: 600; margin-left: 4px; }
.yv-std .model-ans .ma-fmt { font-size: 13px; color: var(--muted); }
.yv-std .model-ans h4 { margin-top: 20px; padding-top: 12px; border-top: 1px solid var(--line); }

/* ===== "蒙的"标记（答对但没把握，算第二遍复习） ===== */
.yv-std .q-wrongtag.guess { color: #b45309; background: color-mix(in srgb, #f59e0b 16%, var(--surface)); }
.yv-std .qb-guess { color: #d97706; font-weight: 700; }
.sb-wrong.sb-guess { color: #d97706; }
.sb-wrong + .sb-guess { margin-left: 0; padding-left: 5px; }
.card-wrong.card-guess { color: #d97706; }
.yv-std .q-guess { display: inline-block; margin-top: 10px; padding: 5px 12px; border-radius: 99px; border: 1px dashed color-mix(in srgb, #f59e0b 60%, var(--line)); background: transparent; color: #b45309; font: inherit; font-size: 12.5px; font-weight: 650; cursor: pointer; }
.yv-std .q-guess:hover { background: color-mix(in srgb, #f59e0b 10%, var(--surface)); }
.yv-std .q-guess.on { border-style: solid; background: color-mix(in srgb, #f59e0b 14%, var(--surface)); }
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
  <form id="search-wrap" role="search" autocomplete="off" onsubmit="return false">
    <input id="search-input" type="search" name="yv-search" placeholder="搜索  ( / )" autocomplete="off" autocorrect="off" spellcheck="false" data-lpignore="true" data-1p-ignore aria-label="搜索">
    <div id="search-results"></div>
  </form>
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
    <button class="sidebar-home-btn" id="sb-plan" onclick="goPlan()">📅 Exam Plan 复习计划</button>
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
      <form id="pw-form" onsubmit="event.preventDefault(); submitPassword();">
      <input type="text" name="username" autocomplete="username" value="Young Vault" tabindex="-1" aria-hidden="true" readonly
        style="position:absolute;width:1px;height:1px;opacity:0;pointer-events:none">
      <input id="pw-input" type="password" name="password" autocomplete="current-password" placeholder="请输入访问密码">
      <label id="pw-remember-row"><input type="checkbox" id="pw-remember"> 在此设备上记住密码</label>
      <div id="pw-error-msg"></div>
      <div id="pw-btn-row">
        <button type="button" id="pw-cancel" onclick="closePasswordModal()">取消</button>
        <button type="submit" id="pw-submit">进入 →</button>
      </div>
      </form>
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
        <div id="home-plan"></div>
      </div>
      <div class="subjects-grid" id="subjects-grid"></div>
    </section>

    <section id="view-plan" class="view">
      <div class="plan-hero">
        <div class="hero-eyebrow">Final exams · Semester 2, 2026</div>
        <h1 class="home-title">Exam Plan 期末复习计划</h1>
        <p class="home-subtitle">Tick each task when it is done — progress is saved on this device. 每完成一项就打勾（进度只保存在本机浏览器）。</p>
        <div class="exam-grid" id="plan-exams"></div>
        <div class="progress-row plan-total"><div class="progress-bar"><i class="plan-prog-fill" style="background:linear-gradient(90deg,#6366f1,#10b981)"></i></div><span class="progress-text plan-prog-text"></span></div>
        <div class="plan-toolbar">
          <button type="button" id="plan-edit-btn" class="pl-btn primary" onclick="togglePlanEdit()">✏️ Edit plan 编辑计划</button>
          <span id="plan-custom-tag" class="pl-tag" style="display:none">customised 已自定义</span>
          <span class="pl-sp"></span>
          <button type="button" class="pl-btn" onclick="exportPlan()" title="Download a backup file 下载备份">⬇ Export 导出</button>
          <label class="pl-btn" title="Load a backup file 导入备份">⬆ Import 导入<input type="file" accept="application/json,.json" hidden onchange="if(this.files[0])importPlan(this.files[0]);this.value=''"></label>
          <button type="button" class="pl-btn" onclick="resetPlan()" title="Back to the default plan 恢复默认">↺ Reset 恢复默认</button>
        </div>
        <div class="plan-legend"><b>Edit mode 编辑模式:</b> drag ⋮⋮ to move a task to any day (computer) · ↑ ↓ / “Move to…” (phone) · ✎ rename · 🗑 delete · type in “+ Add” to add your own tasks · 📝 notes per day. Saved on this device only — use Export/Import to copy it to another device. 拖动 ⋮⋮ 可把任务移到任意一天（手机用 ↑↓ 或"Move to…"），✎ 改名，🗑 删除，"+ Add" 加自己的任务，📝 写当天笔记；只保存在本机，换设备用导出/导入。<br>How to study one module (≈ 1 hour): read every tab → do the quiz until all correct → write 3 lines in your own words. Behind? Do today’s list first, push the rest to the buffer. 学一个模块：读完所有标签 → 测验全对 → 用自己的话写 3 行。落后了就先做"今天"，其余往后挪。</div>
      </div>
      <div id="plan-days"></div>
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
      <aside id="split-pane" aria-label="相关知识点"></aside>
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
const figKeys = {};
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
    figKeys[id] = key;
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
let quizState = {};
try { quizState = JSON.parse(lsGet('yv-quiz') || '{}') || {}; } catch (e) {}
const saveQuiz = () => lsSet('yv-quiz', JSON.stringify(quizState));
function quizInfo(id) {
  const st = quizState[id]; if (!st || !st.n) return null;
  const w = Object.values(st.w || {});
  return { n: st.n, done: Object.keys(st.a || {}).length, wrong: w.filter(v => v !== 'g').length, guess: w.filter(v => v === 'g').length };
}
function isDone(id) {
  const q = quizInfo(id); if (q) return q.done >= q.n;
  const m = moduleById[id], s = m && subjectById[m.subject_id];
  if (s && s.enc) return false;          // 加密科目的模块都有测验：没做完就不算完成
  return readSet.has(id);
}
const readCount = s => s.modules.filter(m => isDone(m.id)).length;
function sbMarks(id) {
  const q = quizInfo(id); let h = '';
  if (q && q.wrong) h += '<span class="sb-wrong" title="' + q.wrong + ' 道错题待复习">✗' + q.wrong + '</span>';
  if (q && q.guess) h += '<span class="sb-wrong sb-guess" title="' + q.guess + ' 道蒙对的题待复习">🎲' + q.guess + '</span>';
  if (isDone(id)) h += '<span class="sb-done" title="测验已全部完成">✓</span>';
  return h;
}
function cardMarks(id) {
  const q = quizInfo(id); let h = '';
  if (isDone(id)) h += '<span class="card-done">✓ 已完成</span>';
  if (q && q.wrong) h += '<span class="card-wrong">✗ ' + q.wrong + ' 错题</span>';
  if (q && q.guess) h += '<span class="card-wrong card-guess">🎲 ' + q.guess + ' 蒙的</span>';
  return h;
}

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
          <span class="progress-text">完成 ${done}/${total}</span>
        </div></div>
        <span class="sc-arrow">→</span>
      </div>`;
  });
  document.getElementById('subjects-grid').innerHTML = html;
  document.getElementById('home-stats').innerHTML =
    `<span class="stat-chip"><b>${SUBJECTS.length}</b> subjects</span><span class="stat-chip"><b>${totalMods}</b> modules</span><span class="stat-chip"><b>${totalRead}</b> done 已完成</span>`;
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
  renderHomePlan();
}

function renderBreadcrumb() {
  const bc = document.getElementById('breadcrumb');
  let html = '<button class="breadcrumb-item" onclick="goHome()">Young Vault</button>';
  if (currentView === 'plan') html += '<span class="breadcrumb-sep">›</span><button class="breadcrumb-item active">Exam Plan 复习计划</button>';
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
  document.getElementById('sb-plan').className = 'sidebar-home-btn' + (currentView === 'plan' ? ' active' : '');
  if (currentView === 'home' || currentView === 'plan') {
    sbHome.className = 'sidebar-home-btn' + (currentView === 'home' ? ' active' : '');
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
        const done = sbMarks(m.id);
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
    `<div class="progress-bar"><i style="width:${total ? done/total*100 : 0}%;background:${s.accent}"></i></div><span class="progress-text">完成 ${done}/${total}</span>`;
  let html = '', n = 0;
  const groups = groupByWeek(s.modules), flat = groups.every(g => g.modules.length === 1);
  const card = m => {
    const dn = cardMarks(m.id);
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
  if (currentView === 'plan') t = 'Exam Plan · Young Vault';
  else if (currentView === 'module' && m) t = m.title + ' · ' + s.code + ' · Young Vault';
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
  if (name !== 'module' && typeof closeSplit === 'function') { closeSplit(); rpill.classList.remove('show'); }
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
  closeSplit();
  glossify(contentDiv, mod.subject_id);
  enhanceModule(contentDiv, mod._h);
  contentDiv.classList.toggle('yv-dark', !!subjectById[mod.subject_id].enc);
  lsSet('yv-last', id);
  showView('module');
  updateReturnPill();
  collapseSidebarOnMobile();
}

function routeFromHash() {
  const hash = location.hash.slice(1);
  if (hash === 'plan') goPlan();
  else if (hash.startsWith('module/')) goModule(hash.slice(7));
  else if (hash.startsWith('subject/')) goSubject(hash.slice(8));
  else goHome();
}
window.addEventListener('hashchange', function() {
  if (_navByCode) return;
  const h = location.hash.slice(1);
  const cur = currentView === 'module' ? 'module/' + currentModuleId : currentView === 'subject' ? 'subject/' + currentSubjectId : currentView === 'plan' ? 'plan' : '';
  if (h === cur) return;
  routeFromHash();
});

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
  setupQuiz(root); setupRecall(root); setupXrefs(root);
  root.querySelectorAll('.deck').forEach(buildDeck);
  setupFigs(root);
}

// ===== 课件配图：打开模块时才下载该模块的加密图片包（img/<模块>.json），用科目密钥解密 =====
const figBundles = {};
function loadFigBundle(mid) {
  if (figBundles[mid]) return figBundles[mid];
  const mod = moduleById[mid], key = mod && figKeys[mod.subject_id];
  if (!key) return Promise.resolve(null);
  figBundles[mid] = fetch('img/' + mid + '.json', { cache: 'no-cache' })
    .then(r => r.ok ? r.json() : null)
    .then(async e => {
      if (!e) return null;
      const buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64d(e.iv) }, key, b64d(e.data));
      return JSON.parse(new TextDecoder().decode(buf));
    })
    .catch(() => { delete figBundles[mid]; return null; });
  return figBundles[mid];
}
function setupFigs(root) {
  root.querySelectorAll('img.yv-shot[data-fig]').forEach(async img => {
    const fig = img.closest('.yv-fig');
    img.onclick = () => img.src && openLightbox(img);
    if (img.getAttribute('src')) return;
    const [mid, name] = img.dataset.fig.split('/');
    const b = await loadFigBundle(mid);
    if (b && b[name]) { img.src = b[name]; img.onload = () => fig && fig.classList.add('ready'); }
    else if (fig) fig.classList.add('fail');
  });
}
// 点击图片放大查看；再点一下切换"原始大小"，Esc 或点背景关闭
const lb = document.createElement('div'); lb.id = 'yv-lightbox';
lb.innerHTML = '<button class="lb-x" aria-label="Close">✕</button><div class="lb-scroll"><img alt=""></div><div class="lb-cap"></div>';
document.body.appendChild(lb);
function openLightbox(img) {
  const big = lb.querySelector('img'); big.src = img.src; big.alt = img.alt;
  lb.classList.remove('zoom');
  const cap = img.closest('.yv-fig') && img.closest('.yv-fig').querySelector('figcaption');
  lb.querySelector('.lb-cap').innerHTML = cap ? cap.innerHTML : '';
  lb.classList.add('open'); document.documentElement.classList.add('lb-lock');
}
function closeLightbox() { lb.classList.remove('open', 'zoom'); document.documentElement.classList.remove('lb-lock'); }
lb.addEventListener('click', e => {
  if (e.target.tagName === 'IMG') { lb.classList.toggle('zoom'); return; }
  if (e.target.closest('.lb-cap')) return;
  closeLightbox();
});
document.addEventListener('keydown', e => { if (e.key === 'Escape' && lb.classList.contains('open')) { e.stopPropagation(); closeLightbox(); } }, true);

function scrollModuleTop(root) {
  if (root.dataset.noTop) return;
  if (root.id === 'split-content') { if (root.scrollTop > 0) root.scrollTo({ top: 0, behavior: 'smooth' }); return; }
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
// ===== 测验：每题只能答一次；答完锁定并显示正确答案和解析；状态保存在本机；答错的题记入错题 =====
function parseCheck(btn) {
  const code = btn.getAttribute('onclick') || '';
  if (!/^\s*\w+_check\(/.test(code)) return null;
  let out = null;
  try { new Function('__c', code.replace(/^\s*\w+_check\(/, '__c('))((q, c, e) => { out = { q, c, e: e || '' }; }); } catch (err) {}
  return out;
}
function setupQuiz(root) {
  const mid = root.id === 'split-content' ? root.dataset.mid : currentModuleId;
  const all = [...root.querySelectorAll('.qblock')];
  if (!all.length) return;
  const st = (mid && (quizState[mid] = quizState[mid] || {})) || {};
  st.a = st.a || {}; st.w = st.w || {}; st.n = all.length;
  const persist = () => { if (mid) { saveQuiz(); renderSidebar(); } };
  persist();
  const labelOf = (b, v) => { const i = b.querySelector('input[value="' + v + '"]'); return i && i.closest('label'); };
  // 标签：w[qid] = 1 是错题，'g' 是蒙对的（都算第二遍要复习）
  const tagWrong = (b, mark) => {
    let t = b.querySelector('.q-wrongtag');
    if (mark && !t) { t = document.createElement('div'); b.insertBefore(t, b.firstChild); }
    if (!mark) { if (t) t.remove(); return; }
    t.className = 'q-wrongtag' + (mark === 'g' ? ' guess' : '');
    t.textContent = mark === 'g' ? '🎲 蒙对的 · 第二遍重点复习' : '✗ 错题 · 第二遍重点复习';
  };
  const lock = (b, info, pick) => {
    const ok = pick === info.c;
    b.querySelectorAll('input').forEach(i => { i.disabled = true; i.checked = i.value === pick; });
    const right = labelOf(b, info.c), mine = labelOf(b, pick);
    if (right) right.classList.add('opt-right');
    if (!ok && mine) mine.classList.add('opt-wrong');
    const fb = b.querySelector('.q-fb');
    const ans = right ? right.textContent.trim() : info.c;
    fb.className = 'q-fb ' + (ok ? 'ok' : 'err');
    fb.innerHTML = (ok ? '✅ Correct! 答对了' : '❌ Not quite. 答错了 — Correct answer 正确答案：<b>' + esc(ans) + '</b>') +
      (info.e ? '<div class="q-expl">' + esc(info.e) + '</div>' : '') +
      (ok ? '<button type="button" class="q-guess"></button>' : '');
    b.classList.add('locked');
    const btn = b.querySelector('.q-check'); if (btn) btn.hidden = true;
  };
  const unlock = b => {
    b.classList.remove('locked');
    b.querySelectorAll('input').forEach(i => { i.disabled = false; i.checked = false; });
    b.querySelectorAll('.opt-right, .opt-wrong').forEach(l => l.classList.remove('opt-right', 'opt-wrong'));
    const fb = b.querySelector('.q-fb'); if (fb) { fb.className = 'q-fb'; fb.textContent = ''; }
    const btn = b.querySelector('.q-check'); if (btn) btn.hidden = false;
  };
  // 答对的题可以手动标成"蒙的"，再点一次取消
  const guessBtn = (b, inf) => {
    const g = b.querySelector('.q-guess'); if (!g) return;
    const on = st.w[inf.q] === 'g';
    g.classList.toggle('on', on);
    g.textContent = on ? '↩ 取消"蒙的"标记' : '🎲 这题是蒙的（标记复习）';
    g.onclick = () => {
      if (st.w[inf.q] === 'g') delete st.w[inf.q]; else st.w[inf.q] = 'g';
      tagWrong(b, st.w[inf.q]); guessBtn(b, inf);
      persist(); b.dispatchEvent(new Event('yv-answer', { bubbles: true }));
    };
  };
  const info = new Map();
  all.forEach(b => {
    const btn = [...b.querySelectorAll('button')].find(x => /_check\(/.test(x.getAttribute('onclick') || ''));
    const inf = btn && parseCheck(btn);
    if (!inf) return;
    info.set(b, inf);
    btn.removeAttribute('onclick'); btn.classList.add('q-check');
    btn.addEventListener('click', () => {
      const sel = b.querySelector('input:checked');
      const fb = b.querySelector('.q-fb');
      if (!sel) { fb.className = 'q-fb warn'; fb.textContent = 'Please select an answer first. 请先选择一个答案。'; return; }
      st.a[inf.q] = sel.value;
      if (sel.value === inf.c) delete st.w[inf.q]; else st.w[inf.q] = 1;
      lock(b, inf, sel.value); tagWrong(b, st.w[inf.q]); guessBtn(b, inf);
      persist(); b.dispatchEvent(new Event('yv-answer', { bubbles: true }));
    });
    if (st.a[inf.q] != null) lock(b, inf, st.a[inf.q]);
    tagWrong(b, st.w[inf.q]);
    guessBtn(b, inf);
  });
  root.querySelectorAll('.sec').forEach(sec => {
    const blocks = [...sec.querySelectorAll('.qblock')].filter(b => info.has(b));
    if (!blocks.length) return;
    const bar = document.createElement('div'); bar.className = 'quiz-bar';
    bar.innerHTML = '<div class="qb-track"><div class="qb-ok"></div><div class="qb-err"></div></div><span class="qb-text"></span><button type="button">↺ Redo 重做</button>';
    blocks[0].parentNode.insertBefore(bar, blocks[0]);
    const okEl = bar.querySelector('.qb-ok'), errEl = bar.querySelector('.qb-err'), txt = bar.querySelector('.qb-text');
    let wasPerfect = null;
    const upd = () => {
      let ok = 0, err = 0, wrongTotal = 0, guessTotal = 0;
      blocks.forEach(b => {
        const inf = info.get(b), pick = st.a[inf.q];
        const isOk = pick != null && pick === inf.c, isErr = pick != null && pick !== inf.c;
        b.classList.toggle('is-ok', isOk); b.classList.toggle('is-err', isErr);
        if (isOk) ok++; if (isErr) err++; if (st.w[inf.q] === 'g') guessTotal++; else if (st.w[inf.q]) wrongTotal++;
      });
      const n = blocks.length;
      okEl.style.width = ok / n * 100 + '%'; errEl.style.left = ok / n * 100 + '%'; errEl.style.width = err / n * 100 + '%';
      const perfect = ok === n;
      bar.classList.toggle('perfect', perfect);
      txt.innerHTML = (perfect ? '🎉 <b>' + n + ' / ' + n + '</b> Perfect! 全对' : '<b>' + ok + '</b> / ' + n + ' correct 答对 · ' + (ok + err) + ' answered 已答') +
        (wrongTotal ? ' · <span class="qb-wrong">✗ ' + wrongTotal + ' 错题待复习</span>' : '') +
        (guessTotal ? ' · <span class="qb-guess">🎲 ' + guessTotal + ' 蒙的</span>' : '');
      if (perfect && wasPerfect === false) burst(bar);
      wasPerfect = perfect;
    };
    sec.addEventListener('yv-answer', upd);
    bar.querySelector('button').addEventListener('click', () => {
      if (!blocks.some(b => st.a[info.get(b).q] != null)) return;
      if (!confirm('重做这一组测验？已答记录会清空；错题和"蒙的"标记会保留，直到你重新答对。')) return;
      blocks.forEach(b => { delete st.a[info.get(b).q]; unlock(b); });
      persist(); wasPerfect = false; upd();
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
    setTimeout(() => d.remove(), 1700);
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

// ===== 缩写词典（悬停显示全称 + 中文）=====
const GLOSS = { mgmt90032: {
  'O&PM': 'Operations & Process Management｜运营与流程管理', 'OM': 'Operations Management｜运营管理',
  'EOQ': 'Economic Order Quantity｜经济订货量', 'ROP': 'Reorder Point｜再订货点', 'AP': 'Aggregate Planning｜综合生产计划',
  'MS': 'Master Scheduling｜主计划编制', 'MPS': 'Master Production Schedule｜主生产计划', 'ATP': 'Available-to-Promise｜可承诺量',
  'MRP': 'Material Requirements Planning｜物料需求计划', 'MRP II': 'Manufacturing Resource Planning｜制造资源计划',
  'ERP': 'Enterprise Resource Planning｜企业资源计划', 'BOM': 'Bill of Materials｜物料清单', 'JIT': 'Just-in-Time｜准时制',
  'WIP': 'Work-in-Process｜在制品', 'SMED': 'Single Minute Exchange of Die｜单分钟换模', 'QFD': 'Quality Function Deployment｜质量功能展开（质量屋）',
  'DFM': 'Design for Manufacture｜面向制造的设计', 'DFA': 'Design for Assembly｜面向装配的设计', 'PLC': 'Product Life Cycle｜产品生命周期',
  'SCM': 'Supply Chain Management｜供应链管理', 'SC': 'Supply Chain｜供应链', 'VSM': 'Value Stream Mapping｜价值流图',
  'SCOR': 'Supply Chain Operations Reference model｜供应链运营参考模型', 'QC': 'Quality Control｜质量控制', 'QA': 'Quality Assurance｜质量保证',
  'QM': 'Quality Management｜质量管理', 'TQM': 'Total Quality Management｜全面质量管理', 'COQ': 'Cost of Quality｜质量成本',
  'SPC': 'Statistical Process Control｜统计过程控制', 'UCL': 'Upper Control Limit｜控制上限', 'LCL': 'Lower Control Limit｜控制下限',
  'DPMO': 'Defects Per Million Opportunities｜每百万机会缺陷数', 'DMAIC': 'Define · Measure · Analyze · Improve · Control｜六西格玛五步法',
  'MNCs': 'Multinational Corporations｜跨国公司', 'MNC': 'Multinational Corporation｜跨国公司', 'LT': 'Lead Time｜提前期',
  'ISO': 'International Organization for Standardization｜国际标准化组织', 'MBNQA': 'Malcolm Baldrige National Quality Award｜美国国家质量奖',
  'MAD': 'Mean Absolute Deviation｜平均绝对偏差', 'MSE': 'Mean Squared Error｜均方误差', 'MAPE': 'Mean Absolute Percentage Error｜平均绝对百分比误差',
  'VMI': 'Vendor-Managed Inventory｜供应商管理库存', 'POS': 'Point of Sale｜销售点（终端）数据', 'MRO': 'Maintenance, Repair & Operations｜维护维修与运营物料',
  'EDLP': 'Everyday Low Pricing｜天天低价', 'CPFR': 'Collaborative Planning, Forecasting & Replenishment｜协同计划预测与补货', 'ROI': 'Return on Investment｜投资回报率'
}, mgmt90030: {
  'TCE': 'Transaction Cost Economics｜交易成本经济学（Williamson）', 'EO': 'Entrepreneurial Orientation｜创业导向（Lumpkin & Dess）',
  'OPP': 'Obligatory Passage Point｜必经之点（Callon）', 'ILs': 'Institutional Logics｜制度逻辑', 'PLC': 'Product Life Cycle｜产品生命周期',
  'TQM': 'Total Quality Management｜全面质量管理', 'ISO': 'International Organization for Standardization｜国际标准化组织',
  'nAch': 'Need for Achievement｜成就需要（McClelland）', 'A&R': 'Artists & Repertoire｜唱片公司的艺人与曲目部门', 'MTV': 'Music Television｜音乐电视台',
  'T&A': 'Tushman & Anderson (1986)｜技术断裂理论', 'ASCAP': 'American Society of Composers, Authors and Publishers｜美国作曲家作家出版商协会',
  'EPA': 'Environmental Protection Agency｜美国环保署', 'FDA': 'Food and Drug Administration｜美国食品药品监督管理局', 'UX': 'User Experience｜用户体验',
  'AI': 'Artificial Intelligence｜人工智能', 'CEO': 'Chief Executive Officer｜首席执行官'
} };
function glossify(root, sid) {
  const g = GLOSS[sid]; if (!g) return;
  const keys = Object.keys(g).sort((a, b) => b.length - a.length);
  const re = new RegExp('(?<![A-Za-z0-9&])(' + keys.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')(?![A-Za-z0-9])', 'g');
  const nodes = [];
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, { acceptNode: n => {
    if (!n.nodeValue.trim() || n.parentElement.closest('script,style,.nav,button,input,.abbr,.xref,.xrefs,h2,.dk-ui,.sp-head')) return NodeFilter.FILTER_REJECT;
    re.lastIndex = 0; return re.test(n.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT; } });
  while (w.nextNode()) nodes.push(w.currentNode);
  nodes.forEach(n => {
    const f = document.createDocumentFragment(); let last = 0, t = n.nodeValue; re.lastIndex = 0; let m;
    while ((m = re.exec(t))) {
      if (m.index > last) f.appendChild(document.createTextNode(t.slice(last, m.index)));
      const s = document.createElement('span'); s.className = 'abbr'; s.dataset.t = g[m[1]]; s.textContent = m[1]; f.appendChild(s);
      last = m.index + m[1].length;
    }
    if (last < t.length) f.appendChild(document.createTextNode(t.slice(last)));
    n.parentNode.replaceChild(f, n);
  });
}

// ===== 相关知识点：芯片 / 预览 / 分屏 =====
const _docCache = {};
function moduleDoc(id) {
  if (_docCache[id]) return _docCache[id];
  if (contentCache[id] == null) return null;
  return _docCache[id] = new DOMParser().parseFromString(contentCache[id], 'text/html');
}
function findTarget(scope, secId, find) {
  const sec = scope.querySelector('#' + CSS.escape(secId)); if (!sec) return null;
  const f = (find || '').toLowerCase();
  if (!f) return sec.querySelector('.card') || sec;
  const cards = [...sec.querySelectorAll('.card')];
  return cards.find(c => [...c.querySelectorAll('h3')].some(h => h.textContent.toLowerCase().includes(f)))
      || cards.find(c => c.textContent.toLowerCase().includes(f)) || cards[0] || sec;
}
function setupXrefs(root) {
  root.querySelectorAll('.xref').forEach(x => {
    const m = moduleById[x.dataset.mod]; if (!m) return;
    x.style.setProperty('--xc', m.color);
    if (!x.querySelector('.xw')) x.insertAdjacentHTML('afterbegin', '<span class="xw">' + m.week.replace('Week ', 'W') + '</span>');
    if (!x.querySelector('.xa')) x.insertAdjacentHTML('beforeend', '<span class="xa">↗</span>');
    x.setAttribute('role', 'button'); x.tabIndex = 0;
    x.title = '';
  });
}
const pop = document.createElement('div'); pop.id = 'yv-pop'; document.body.appendChild(pop);
const tip = document.createElement('div'); tip.id = 'yv-tip'; document.body.appendChild(tip);
let popTimer = 0, popFor = null;
const canHover = matchMedia('(hover: hover)').matches;
function placeFloat(el, anchor, gap) {
  const r = anchor.getBoundingClientRect(), w = el.offsetWidth, h = el.offsetHeight;
  let left = Math.min(Math.max(12, r.left), innerWidth - w - 12);
  let top = r.bottom + gap; if (top + h > innerHeight - 12) top = Math.max(12, r.top - h - gap);
  el.style.left = left + 'px'; el.style.top = top + 'px';
}
function showPreview(x) {
  const m = moduleById[x.dataset.mod], doc = m && moduleDoc(m.id); if (!doc) return;
  const t = findTarget(doc, x.dataset.sec, x.dataset.find); if (!t) return;
  const clone = t.cloneNode(true); clone.querySelectorAll('script,input,button,.qblock').forEach(n => n.remove());
  pop.style.setProperty('--pc', m.color);
  pop.innerHTML = '<div class="pp-head"><b>' + esc(m.week.replace('Week ', 'W')) + '</b>' + esc(m.title) + '</div><div class="pp-body yv-std" style="--tabc:' + m.color + '"></div><div class="pp-foot">Click to open on the right 点击在右侧打开 →</div>';
  pop.querySelector('.pp-body').appendChild(clone);
  placeFloat(pop, x, 8); pop.classList.add('show'); popFor = x;
}
function hidePreview() { clearTimeout(popTimer); pop.classList.remove('show'); popFor = null; }
document.addEventListener('mouseover', e => {
  if (!canHover) return;
  const x = e.target.closest && e.target.closest('.xref');
  if (x && x !== popFor) { clearTimeout(popTimer); popTimer = setTimeout(() => showPreview(x), 260); }
  else if (!x && popFor) hidePreview();
  const a = e.target.closest && e.target.closest('.abbr');
  if (a) { const [en, zh] = a.dataset.t.split('｜'); tip.innerHTML = '<b>' + esc(a.textContent) + '</b> = ' + esc(en) + (zh ? '<br><span>' + esc(zh) + '</span>' : ''); placeFloat(tip, a, 6); tip.classList.add('show'); }
  else tip.classList.remove('show');
});
document.addEventListener('scroll', () => { hidePreview(); tip.classList.remove('show'); }, true);
document.addEventListener('click', e => {
  const a = e.target.closest('.abbr');
  if (a && !canHover) { const [en, zh] = a.dataset.t.split('｜'); tip.innerHTML = '<b>' + esc(a.textContent) + '</b> = ' + esc(en) + (zh ? '<br><span>' + esc(zh) + '</span>' : ''); placeFloat(tip, a, 6); tip.classList.add('show'); setTimeout(() => tip.classList.remove('show'), 2600); }
  const x = e.target.closest('.xref'); if (!x) return;
  e.preventDefault(); e.stopPropagation(); hidePreview();
  openSplit(x.dataset.mod, x.dataset.sec, x.dataset.find, x);
});
document.addEventListener('keydown', e => { if ((e.key === 'Enter') && e.target.classList && e.target.classList.contains('xref')) e.target.click(); if (e.key === 'Escape') closeSplit(); });

let splitMod = null, sbAutoCollapsed = false;
function openSplit(modId, secId, find, chip) {
  const m = moduleById[modId]; if (!m || contentCache[modId] == null) return;
  document.querySelectorAll('.xref.on').forEach(c => c.classList.remove('on')); if (chip) chip.classList.add('on');
  if (modId === currentModuleId) { gotoTarget(document.getElementById('module-content'), secId, find, document.getElementById('main')); return; }
  const view = document.getElementById('view-module'), pane = document.getElementById('split-pane');
  pane.style.setProperty('--accent', m.color);
  pane.style.setProperty('--accent-ink', 'color-mix(in srgb, ' + m.color + ' 70%, var(--text))');
  pane.style.setProperty('--accent-strong', 'color-mix(in srgb, ' + m.color + ' 74%, #000)');
  if (splitMod !== modId) {
    pane.innerHTML = '<div class="sp-head"><span class="sp-week">' + esc(m.week) + '</span><span class="sp-title">' + esc(m.title) + '</span>' +
      '<button class="sp-btn sp-open" title="在完整页面打开（之后可一键返回）">⤢ Full page 完整页面</button><button class="sp-btn sp-close" title="关闭 (Esc)">✕</button></div>' +
      '<div class="module-content-wrapper" id="split-content"></div>';
    const body = pane.querySelector('#split-content');
    body.innerHTML = contentCache[modId];
    body.querySelectorAll('script').forEach(old => { const s = document.createElement('script'); s.textContent = old.textContent; old.replaceWith(s); });
    glossify(body, m.subject_id);
    body.dataset.mid = modId;
    enhanceModule(body, m._h);
    body.classList.toggle('yv-dark', !!subjectById[m.subject_id].enc);
    pane.querySelector('.sp-close').onclick = closeSplit;
    pane.querySelector('.sp-open').onclick = () => {
      const left = document.getElementById('module-content'), btns = [...left.querySelectorAll('.nav button')];
      returnTo = { id: currentModuleId, tab: btns.findIndex(b => b.classList.contains('on')), scroll: document.getElementById('main').scrollTop };
      const sb = [...body.querySelectorAll('.nav button')].findIndex(b => b.classList.contains('on'));
      goModule(modId).then(() => { const b = document.querySelectorAll('#module-content .nav button')[sb]; if (b) b.click(); });
    };
    splitMod = modId;
  }
  if (!view.classList.contains('split')) {
    view.classList.add('split');
    const sb = document.getElementById('sidebar');
    if (!isMobile() && innerWidth < 1500 && !sb.classList.contains('collapsed')) { sb.classList.add('collapsed'); sbAutoCollapsed = true; }
  }
  gotoTarget(pane.querySelector('#split-content'), secId, find, pane.querySelector('#split-content'));
}
function gotoTarget(body, secId, find, scroller) {
  const key = secId.split('sec-')[1];
  const btn = [...body.querySelectorAll('.nav button')].find(b => (b.getAttribute('onclick') || '').includes("'" + key + "'"));
  if (btn && !btn.classList.contains('on')) { body.dataset.noTop = '1'; btn.click(); }
  setTimeout(() => {
    delete body.dataset.noTop;
    const card = findTarget(body, secId, find); if (!card) return;
    const f = (find || '').toLowerCase();
    const hd = f && [...card.querySelectorAll('h3')].find(h => h.textContent.toLowerCase().includes(f));
    const t = hd && hd !== card.querySelector('h3') ? hd : card;
    const sr = scroller.getBoundingClientRect(), tr = t.getBoundingClientRect();
    const nav = body.querySelector('.yv-tabs'), off = nav ? nav.offsetHeight + 24 : 16;
    scroller.scrollTo({ top: scroller.scrollTop + tr.top - sr.top - off, behavior: 'smooth' });
    card.classList.remove('sp-flash'); void card.offsetWidth; card.classList.add('sp-flash');
  }, 220);
}
function closeSplit() {
  const view = document.getElementById('view-module'); if (!view.classList.contains('split')) return;
  view.classList.remove('split'); document.getElementById('split-pane').innerHTML = ''; splitMod = null;
  document.querySelectorAll('.xref.on').forEach(c => c.classList.remove('on'));
  if (sbAutoCollapsed) { document.getElementById('sidebar').classList.remove('collapsed'); sbAutoCollapsed = false; }
}

// 从"完整页面"返回原来的考试复习页
let returnTo = null;
const rpill = document.createElement('button'); rpill.id = 'return-pill'; document.body.appendChild(rpill);
function updateReturnPill() {
  const r = returnTo && moduleById[returnTo.id];
  if (r && currentView === 'module' && currentModuleId !== returnTo.id) {
    rpill.style.setProperty('--rc', r.color);
    rpill.innerHTML = '<span class="rp-ico">↩</span>Back to ' + esc(r.title) + ' 返回';
    rpill.classList.add('show');
  } else rpill.classList.remove('show');
}
rpill.addEventListener('click', async () => {
  const r = returnTo; if (!r) return; returnTo = null;
  await goModule(r.id);
  const b = document.querySelectorAll('#module-content .nav button')[r.tab]; if (b) b.click();
  setTimeout(() => document.getElementById('main').scrollTo({ top: r.scroll, behavior: 'instant' }), 60);
  updateReturnPill();
});


// ===== 期末复习计划（打勾进度只存在本机浏览器）=====
const PLAN_EXAMS = [
  { sid: 'mktg90004', code: 'MKTG90004', name: 'Marketing Management', date: '2026-11-11', time: '08:30', fmt: 'LMS quiz · LockDown Browser 机考', rule: '2 × A4 notes, double sided 两张双面 A4', weight: '50% · 25 MCQ + 3 short + 1 long 选择+简答+长答' },
  { sid: 'mgmt90030', code: 'MGMT90030', name: 'Managing Innovation', date: '2026-11-11', time: '16:30', fmt: 'Digital exam · typed 机考打字', rule: 'Open book · paper limit TBC 开卷，带纸限制待定', weight: '40%' },
  { sid: 'mgmt90032', code: 'MGMT90032', name: 'Operations & Process Mgmt', date: '2026-11-13', time: '16:30', fmt: 'Written exam · paper 纸笔考试', rule: 'Closed book — memorise! 闭卷，要背', weight: '50%' },
  { sid: 'mgmt90025', code: 'MGMT90025', name: 'People & Change', date: '2026-11-16', time: '08:30', fmt: 'Digital exam · typed 机考打字', rule: 'Max two A4 cheat sheets 最多两张 A4', weight: '50%' }
];
const PLAN_PHASES = {
  start: { label: 'Start 起步', color: '#64748b' },
  p1: { label: 'First pass 第一遍', color: '#6366f1' },
  p2: { label: 'Exam prep 冲刺', color: '#ef4444' },
  exam: { label: 'EXAM 考试', color: '#f59e0b' },
  p3: { label: 'Final sprint 最后冲刺', color: '#10b981' }
};
const PLAN_DAYS = [
  { d: 'start', ph: 'start', title: 'Start 起步 — see what each exam looks like first 先看清每门考什么', tasks: [
    { t: 'Check outstanding assignments: MKTG90004 Part B & MGMT90030 group video (both due Sun 25 Oct) — finish those first', zh: '先确认作业：MKTG90004 Part B 和 MGMT90030 小组视频（都是 10/25 截止），没交的先做' },
    { t: 'Read MGMT90032 W12 “Exam Format” tab (closed book, 8 of 10 + 2 calc questions)', zh: '读 MGMT90032 第 12 周"考试形式"（闭卷，10 选 8 + 2 道计算题）', m: 'mgmt90032_w12_exam_review' },
    { t: 'Read MGMT90025 W12 “Exam Info & Tips” tab (4 questions × ~500 words, 2 × A4)', zh: '读 MGMT90025 第 12 周"考试信息"（4 题 × 约 500 词，两张 A4）', m: 'mgmt90025_w12_review' },
    { t: 'Read MGMT90030 W12 “Exam & Plan” + “Practice Exam” tabs', zh: '读 MGMT90030 第 12 周"考试"和"练习题"两页', m: 'mgmt90030_w12_exam_review' },
    { t: 'Read MKTG90004 W12 “Exam Structure” + “What’s Examinable” (skip the 🚫 parts while studying)', zh: '读 MKTG90004 第 12 周"考试结构"和"考与不考"（学习时跳过 🚫 部分）', m: 'mktg90004_w12_exam_review' } ] },
  { d: '2026-10-23', ph: 'p1', title: 'MKTG90004 · W1–W4 营销第 1–4 周', tasks: [
    { t: 'MKTG90004 W1 · read + quiz all correct', zh: '学第 1 周：读完所有标签 + 测验全对', m: 'mktg90004_w1_what_is_marketing' },
    { t: 'MKTG90004 W2', zh: '学第 2 周：读完所有标签 + 测验全对', m: 'mktg90004_w2_consumers' }, { t: 'MKTG90004 W3 (MCQ only — read quickly)', zh: '学第 3 周（只考选择题，快速看）', m: 'mktg90004_w3_environment' }, { t: 'MKTG90004 W4', zh: '学第 4 周：读完所有标签 + 测验全对', m: 'mktg90004_w4_stp' }, { id: 'r:2026-10-23', t: 'Review & sort (10 min): put today’s key points into your MKTG90004 cheat-sheet draft', zh: '复盘整理（10 分钟）：把今天的要点记进 MKTG90004 cheat sheet 草稿' } ] },
  { d: '2026-10-24', ph: 'p1', title: 'MKTG90004 · W5–W7 营销第 5–7 周', tasks: [
    { t: 'MKTG90004 W5 (assessment week, quick)', zh: '学第 5 周（作业周，快速看）', m: 'mktg90004_w5_assessment' },
    { t: 'MKTG90004 W6', zh: '学第 6 周：读完所有标签 + 测验全对', m: 'mktg90004_w6_product_brand' }, { t: 'MKTG90004 W7', zh: '学第 7 周：读完所有标签 + 测验全对', m: 'mktg90004_w7_services' }, { id: 'r:2026-10-24', t: 'Review & sort (10 min): put today’s key points into your MKTG90004 cheat-sheet draft', zh: '复盘整理（10 分钟）：把今天的要点记进 MKTG90004 cheat sheet 草稿' } ] },
  { d: '2026-10-25', ph: 'p1', title: 'MKTG90004 · W8–W9 (deadline day) 营销第 8–9 周（作业截止日）', tasks: [
    { t: 'Submit any assignment due today first', zh: '先交今天截止的作业' },
    { t: 'MKTG90004 W8', zh: '学第 8 周：读完所有标签 + 测验全对', m: 'mktg90004_w8_communication' }, { t: 'MKTG90004 W9', zh: '学第 9 周：读完所有标签 + 测验全对', m: 'mktg90004_w9_pricing' }, { id: 'r:2026-10-25', t: 'Review & sort (10 min): put today’s key points into your MKTG90004 cheat-sheet draft', zh: '复盘整理（10 分钟）：把今天的要点记进 MKTG90004 cheat sheet 草稿' } ] },
  { d: '2026-10-26', ph: 'p1', title: 'MKTG90004 · W10–W11 + quiz redo 营销第 10–11 周 + 重做测验', tasks: [
    { t: 'MKTG90004 W10', zh: '学第 10 周：读完所有标签 + 测验全对', m: 'mktg90004_w10_distribution' }, { t: 'MKTG90004 W11 (MCQ only — research part, skip metrics)', zh: '学第 11 周（只考选择题：看市场调研部分，跳过指标）', m: 'mktg90004_w11_research_metrics' },
    { t: 'Redo every MKTG90004 quiz once (use ↺ Reset); note the ones you got wrong', zh: '把 MKTG90004 每个测验重做一遍（点 ↺ 重做），记下做错的' }, { id: 'r:2026-10-26', t: 'Review & sort (10 min): put today’s key points into your MKTG90004 cheat-sheet draft', zh: '复盘整理（10 分钟）：把今天的要点记进 MKTG90004 cheat sheet 草稿' } ] },
  { d: '2026-10-27', ph: 'p1', title: 'MGMT90032 · W1–W3 (+ EOQ, AP, MPS calcs) 运营第 1–3 周 + 计算题（闭卷，早学）', tasks: [
    { t: '90032 W1 — Planned vs Lean big picture', zh: '学第 1 周：计划型 vs 精益型大图', m: 'mgmt90032_w1_intro' },
    { t: '90032 W2 — do the EOQ example by hand', zh: '学第 2 周，并手算一遍 EOQ 例题', m: 'mgmt90032_w2_forecast_inventory' },
    { t: '90032 W3 — do the AP + MPS tables by hand', zh: '学第 3 周，并手算综合计划（AP）和主生产计划（MPS）表', m: 'mgmt90032_w3_aggregate_mps' }, { id: 'r:2026-10-27', t: 'Review & sort (10 min): write today’s formulas and lists into your 90032 summary; redo one example from memory', zh: '复盘整理（10 分钟）：把今天的公式和清单整理进 90032 总结，凭记忆重做一道例题' } ] },
  { d: '2026-10-28', ph: 'p1', title: 'MGMT90032 · W4–W6 (+ MRP) 运营第 4–6 周 + MRP', tasks: [
    { t: '90032 W4 — do the MRP component J table by hand', zh: '学第 4 周，并手算 MRP 零件 J 那张表', m: 'mgmt90032_w4_mrp_erp' },
    { t: '90032 W5', zh: '学第 5 周：读完所有标签 + 测验全对', m: 'mgmt90032_w5_jit_lean' }, { t: '90032 W6', zh: '学第 6 周：读完所有标签 + 测验全对', m: 'mgmt90032_w6_strategy' }, { id: 'r:2026-10-28', t: 'Review & sort (10 min): write today’s formulas and lists into your 90032 summary; redo one example from memory', zh: '复盘整理（10 分钟）：把今天的公式和清单整理进 90032 总结，凭记忆重做一道例题' } ] },
  { d: '2026-10-29', ph: 'p1', title: 'MGMT90032 · W7–W8 (+ line balancing) 运营第 7–8 周 + 生产线平衡', tasks: [
    { t: '90032 W7 — do a line-balancing question by hand', zh: '学第 7 周，并手算一道生产线平衡题', m: 'mgmt90032_w7_process_layout' },
    { t: '90032 W8', zh: '学第 8 周：读完所有标签 + 测验全对', m: 'mgmt90032_w8_scm' }, { id: 'r:2026-10-29', t: 'Review & sort (10 min): write today’s formulas and lists into your 90032 summary; redo one example from memory', zh: '复盘整理（10 分钟）：把今天的公式和清单整理进 90032 总结，凭记忆重做一道例题' } ] },
  { d: '2026-10-30', ph: 'p1', title: 'MGMT90032 · W9–W10 (+ SPC) 运营第 9–10 周 + 控制图，开始闪卡', tasks: [
    { t: '90032 W9', zh: '学第 9 周：读完所有标签 + 测验全对', m: 'mgmt90032_w9_quality' }, { t: '90032 W10 — do the X̄/R chart question by hand', zh: '学第 10 周，并手算一遍 X̄/R 控制图题', m: 'mgmt90032_w10_spc_sixsigma' },
    { t: '90032 W12 — read “Section 1 Answers” and do the Flashcards once (from now on 30 min every day)', zh: '读第 12 周"Section 1 参考答案"，过一遍闪卡（从今天起每天 30 分钟）', m: 'mgmt90032_w12_exam_review' }, { id: 'r:2026-10-30', t: 'Review & sort (10 min): write today’s formulas and lists into your 90032 summary; redo one example from memory', zh: '复盘整理（10 分钟）：把今天的公式和清单整理进 90032 总结，凭记忆重做一道例题' } ] },
  { d: '2026-10-31', ph: 'p1', title: 'MGMT90030 · W1–W3 创新第 1–3 周', tasks: [
    { t: '90030 W1 (course framework!)', zh: '学第 1 周（全课框架，最重要！）', m: 'mgmt90030_w1_intro' }, { t: '90030 W2', zh: '学第 2 周：读完所有标签 + 测验全对', m: 'mgmt90030_w2_creativity' }, { t: '90030 W3', zh: '学第 3 周：读完所有标签 + 测验全对', m: 'mgmt90030_w3_paradigm_change' },
    { t: '90032 flashcards / one calc question — 30 min (spaced review)', zh: '90032 闪卡或一道计算题，30 分钟（间隔复习）', m: 'mgmt90032_w12_exam_review' }, { id: 'r:2026-10-31', t: 'Review & sort (10 min): put today’s key points into your MGMT90030 notes draft (author → concept → example)', zh: '复盘整理（10 分钟）：把今天的要点记进 MGMT90030 笔记草稿（作者 → 概念 → 例子）' } ] },
  { d: '2026-11-01', ph: 'p1', title: 'MGMT90030 · W4–W5 (core theories) 创新第 4–5 周（核心理论）', tasks: [
    { t: '90030 W4 — selection systems (Wijnberg)', zh: '学第 4 周：选择系统（Wijnberg），核心理论', m: 'mgmt90030_w4_value' }, { t: '90030 W5 — Abrahamson four perspectives', zh: '学第 5 周：Abrahamson 四种视角，核心理论', m: 'mgmt90030_w5_diffusion' },
    { t: '90032 flashcards / one calc question — 30 min (spaced review)', zh: '90032 闪卡或一道计算题，30 分钟（间隔复习）', m: 'mgmt90032_w12_exam_review' }, { id: 'r:2026-11-01', t: 'Review & sort (10 min): put today’s key points into your MGMT90030 notes draft (author → concept → example)', zh: '复盘整理（10 分钟）：把今天的要点记进 MGMT90030 笔记草稿（作者 → 概念 → 例子）' } ] },
  { d: '2026-11-02', ph: 'p1', title: 'MGMT90030 · W6–W8 创新第 6–8 周', tasks: [
    { t: '90030 W6–7 institutions', zh: '学第 6–7 周：制度与制度逻辑', m: 'mgmt90030_w6_institutions' }, { t: '90030 W8 agents of change', zh: '学第 8 周：创业者与变革推动者', m: 'mgmt90030_w8_agents_of_change' },
    { t: '90032 flashcards / one calc question — 30 min (spaced review)', zh: '90032 闪卡或一道计算题，30 分钟（间隔复习）', m: 'mgmt90032_w12_exam_review' }, { id: 'r:2026-11-02', t: 'Review & sort (10 min): put today’s key points into your MGMT90030 notes draft (author → concept → example)', zh: '复盘整理（10 分钟）：把今天的要点记进 MGMT90030 笔记草稿（作者 → 概念 → 例子）' } ] },
  { d: '2026-11-03', ph: 'p1', title: 'MGMT90030 · W9–W11 创新第 9–11 周', tasks: [
    { t: '90030 W9', zh: '学第 9 周：读完所有标签 + 测验全对', m: 'mgmt90030_w9_exploration_exploitation' }, { t: '90030 W10', zh: '学第 10 周：读完所有标签 + 测验全对', m: 'mgmt90030_w10_resource_deployment' }, { t: '90030 W11', zh: '学第 11 周：读完所有标签 + 测验全对', m: 'mgmt90030_w11_networks_classification' },
    { t: '90032 flashcards / one calc question — 30 min (spaced review)', zh: '90032 闪卡或一道计算题，30 分钟（间隔复习）', m: 'mgmt90032_w12_exam_review' }, { id: 'r:2026-11-03', t: 'Review & sort (10 min): put today’s key points into your MGMT90030 notes draft (author → concept → example)', zh: '复盘整理（10 分钟）：把今天的要点记进 MGMT90030 笔记草稿（作者 → 概念 → 例子）' } ] },
  { d: '2026-11-04', ph: 'p1', title: 'MGMT90025 · W1–W4 变革第 1–4 周（开始写两页 cheat sheet）', tasks: [
    { t: '90025 W1', zh: '学第 1 周：读完所有标签 + 测验全对', m: 'mgmt90025_w1_overview' }, { t: '90025 W2', zh: '学第 2 周：读完所有标签 + 测验全对', m: 'mgmt90025_w2_why_how_change' }, { t: '90025 W3', zh: '学第 3 周：读完所有标签 + 测验全对', m: 'mgmt90025_w3_culture_teams' }, { t: '90025 W4', zh: '学第 4 周：读完所有标签 + 测验全对', m: 'mgmt90025_w4_it_innovation' },
    { t: 'Copy each week’s key frameworks + authors into the A4 cheat-sheet draft', zh: '把每周的关键框架和作者抄进 A4 cheat sheet 草稿' },
    { t: '90032 flashcards / one calc question — 30 min (spaced review)', zh: '90032 闪卡或一道计算题，30 分钟（间隔复习）', m: 'mgmt90032_w12_exam_review' }, { id: 'r:2026-11-04', t: 'Review & sort (10 min): put today’s key points into your MGMT90025 cheat-sheet draft', zh: '复盘整理（10 分钟）：把今天的要点记进 MGMT90025 cheat sheet 草稿' } ] },
  { d: '2026-11-05', ph: 'p1', title: 'MGMT90025 · W5–W8 变革第 5–8 周', tasks: [
    { t: '90025 W5', zh: '学第 5 周：读完所有标签 + 测验全对', m: 'mgmt90025_w5_mna_downsizing' }, { t: '90025 W6', zh: '学第 6 周：读完所有标签 + 测验全对', m: 'mgmt90025_w6_communication' }, { t: '90025 W7', zh: '学第 7 周：读完所有标签 + 测验全对', m: 'mgmt90025_w7_strategy' }, { t: '90025 W8', zh: '学第 8 周：读完所有标签 + 测验全对', m: 'mgmt90025_w8_leadership' },
    { t: 'Add to the A4 cheat-sheet draft', zh: '继续往 A4 cheat sheet 草稿里加内容' },
    { t: '90032 flashcards / one calc question — 30 min (spaced review)', zh: '90032 闪卡或一道计算题，30 分钟（间隔复习）', m: 'mgmt90032_w12_exam_review' }, { id: 'r:2026-11-05', t: 'Review & sort (10 min): put today’s key points into your MGMT90025 cheat-sheet draft', zh: '复盘整理（10 分钟）：把今天的要点记进 MGMT90025 cheat sheet 草稿' } ] },
  { d: '2026-11-06', ph: 'p1', title: 'MGMT90025 · W9–W12 变革第 9–12 周（cheat sheet 第一版）', tasks: [
    { t: '90025 W9', zh: '学第 9 周：读完所有标签 + 测验全对', m: 'mgmt90025_w9_training' }, { t: '90025 W10', zh: '学第 10 周：读完所有标签 + 测验全对', m: 'mgmt90025_w10_individual_emotions' }, { t: '90025 W11', zh: '学第 11 周：读完所有标签 + 测验全对', m: 'mgmt90025_w11_resistance_readiness' }, { t: '90025 W12 review', zh: '学第 12 周复习课（考试信息、案例题）', m: 'mgmt90025_w12_review' },
    { t: 'Finish cheat sheet v1 (two A4 sides max)', zh: '完成 cheat sheet 第一版（最多两页 A4）' },
    { t: '90032 flashcards / one calc question — 30 min (spaced review)', zh: '90032 闪卡或一道计算题，30 分钟（间隔复习）', m: 'mgmt90032_w12_exam_review' }, { id: 'r:2026-11-06', t: 'Review & sort (10 min): put today’s key points into your MGMT90025 cheat-sheet draft', zh: '复盘整理（10 分钟）：把今天的要点记进 MGMT90025 cheat sheet 草稿' } ] },
  { d: '2026-11-07', ph: 'p1', title: 'Buffer day — catch up on anything unticked 缓冲日：补完没打勾的', tasks: [
    { t: 'Go back through the plan and finish every unticked task 补完之前没打勾的' },
    { t: 'Re-do the quizzes you got wrong (all subjects)', zh: '重做所有科目里做错的测验' },
    { t: '90032 flashcards / one calc question — 30 min (spaced review)', zh: '90032 闪卡或一道计算题，30 分钟（间隔复习）', m: 'mgmt90032_w12_exam_review' }, { id: 'r:2026-11-07', t: 'Review & sort (10 min): what still feels shaky? Add it to your cheat sheet or notes', zh: '复盘整理（10 分钟）：哪里还不熟？补进 cheat sheet 或笔记' } ] },
  { d: '2026-11-08', ph: 'p2', title: 'MKTG90004 exam prep 营销考前冲刺', tasks: [
    { t: 'MKTG90004 W12: re-read “What’s Examinable” and “How to Answer”', zh: '重读第 12 周"考与不考"和"答题方法"', m: 'mktg90004_w12_exam_review' },
    { t: 'Write the two example questions timed: DAG short answer (18 min) + customer journey long answer (36 min)', zh: '限时写两道例题：独特资产矩阵短答（18 分钟）+ 顾客旅程长答（36 分钟）', m: 'mktg90004_w12_exam_review' },
    { t: 'Make your 2 × A4 double-sided notes (follow the “2 × A4 Notes” tab)', zh: '做好 2 张双面 A4 笔记（按"2 × A4 Notes"标签的分配）' },
    { t: 'MCQ practice: redo every MKTG90004 weekly quiz (Section 1 = 25 MCQ)', zh: '练选择题：把 MKTG90004 每周测验重做一遍（Section 1 = 25 道选择题）' },
    { t: '90032 flashcards 30 min', zh: '90032 闪卡 30 分钟', m: 'mgmt90032_w12_exam_review' }, { id: 'r:2026-11-08', t: 'Review & sort (10 min): what still feels shaky? Add it to your cheat sheet or notes', zh: '复盘整理（10 分钟）：哪里还不熟？补进 cheat sheet 或笔记' } ] },
  { d: '2026-11-09', ph: 'p2', title: 'MGMT90030 exam prep 创新考前冲刺', tasks: [
    { t: 'Practice exam: write Tasks 1–3 timed (≈ 30 min each)', zh: '练习题：限时写 Task 1–3（每题约 30 分钟）', m: 'mgmt90030_w12_exam_review' },
    { t: 'Compare with the answer frames; fill gaps via the 📚 links', zh: '对照答题框架，用 📚 链接补漏' },
    { t: 'Build an open-book index: author → concept → week', zh: '做开卷索引：作者 → 概念 → 第几周' }, { t: '90032 flashcards 30 min', zh: '90032 闪卡 30 分钟', m: 'mgmt90032_w12_exam_review' }, { id: 'r:2026-11-09', t: 'Review & sort (10 min): what still feels shaky? Add it to your cheat sheet or notes', zh: '复盘整理（10 分钟）：哪里还不熟？补进 cheat sheet 或笔记' } ] },
  { d: '2026-11-10', ph: 'p2', title: 'Light review · pack · sleep early 轻复习 · 收拾东西 · 早睡', tasks: [
    { t: 'Skim your MKTG90004 2 × A4 notes + 90030 index (no new material)', zh: '快速看 MKTG90004 的 2 张 A4 和 90030 索引（不学新内容）' }, { t: 'Check LockDown Browser works; pack student ID, pen, charged laptop + charger, the 2 × A4 notes', zh: '检查 LockDown Browser 能用；带学生证、笔、充满电的电脑和充电器、2 张 A4 笔记' }, { t: 'Sleep early — first exam at 08:30', zh: '早睡，第一场 08:30' }, { id: 'r:2026-11-10', t: 'Review & sort (10 min): what still feels shaky? Add it to your cheat sheet or notes', zh: '复盘整理（10 分钟）：哪里还不熟？补进 cheat sheet 或笔记' } ] },
  { d: '2026-11-11', ph: 'exam', title: 'EXAM DAY · MKTG90004 08:30 · MGMT90030 16:30 考试日：两门', tasks: [
    { t: 'MKTG90004 exam 08:30', zh: 'MKTG90004 考试 08:30' }, { t: 'Lunch + rest; 1 hour skim of the 90030 index', zh: '午饭和休息；花 1 小时快速看 90030 索引' }, { t: 'MGMT90030 exam 16:30', zh: 'MGMT90030 考试 16:30' } ] },
  { d: '2026-11-12', ph: 'p3', title: 'MGMT90032 full day (closed book) 运营全天冲刺（闭卷）', tasks: [
    { t: 'Section 2: do all six calculation types timed (line balancing, SPC, MRP, EOQ, AP, MPS)', zh: 'Section 2：六类计算题各限时做一遍（生产线平衡、SPC、MRP、EOQ、AP、MPS）', m: 'mgmt90032_w12_exam_review' },
    { t: 'Section 1: write the 7 sample answers from memory, then compare', zh: 'Section 1：凭记忆写 7 道例题答案，再对照' },
    { t: 'Must-Memorize tab with Recall mode ON until every term is clear', zh: '"必背清单"开背诵模式，直到每个词都熟' }, { t: 'Flashcards: clear all 52', zh: '闪卡：52 张全部记住' }, { id: 'r:2026-11-12', t: 'Review & sort (10 min): what still feels shaky? Add it to your cheat sheet or notes', zh: '复盘整理（10 分钟）：哪里还不熟？补进 cheat sheet 或笔记' } ] },
  { d: '2026-11-13', ph: 'exam', title: 'EXAM · MGMT90032 16:30 (written, closed book) 考试：运营（笔试闭卷）', tasks: [
    { t: 'Morning: flashcards + Recall mode one last time', zh: '上午：最后过一遍闪卡和背诵模式', m: 'mgmt90032_w12_exam_review' }, { t: 'Bring Casio FX82 calculator + pens', zh: '带 Casio FX82 计算器和笔' }, { t: 'MGMT90032 exam 16:30', zh: 'MGMT90032 考试 16:30' } ] },
  { d: '2026-11-14', ph: 'p3', title: 'MGMT90025 cheat sheet final + cases 变革：cheat sheet 定稿 + 案例题', tasks: [
    { t: 'Finalize the two A4 cheat sheets', zh: '两张 A4 cheat sheet 定稿' }, { t: 'Write the IBM and AGL case answers timed', zh: '限时写 IBM 和 AGL 两个案例题', m: 'mgmt90025_w12_review' }, { id: 'r:2026-11-14', t: 'Review & sort (10 min): what still feels shaky? Add it to your cheat sheet or notes', zh: '复盘整理（10 分钟）：哪里还不熟？补进 cheat sheet 或笔记' } ] },
  { d: '2026-11-15', ph: 'p3', title: 'MGMT90025 mock exam 变革模拟考', tasks: [
    { t: 'Mock exam: 4 questions × 30 min using only your cheat sheets', zh: '模拟考：4 道题 × 30 分钟，只用 cheat sheet' }, { t: 'Fix the cheat sheets where you got stuck; sleep early', zh: '哪里卡住就改 cheat sheet；早点睡' }, { id: 'r:2026-11-15', t: 'Review & sort (10 min): what still feels shaky? Add it to your cheat sheet or notes', zh: '复盘整理（10 分钟）：哪里还不熟？补进 cheat sheet 或笔记' } ] },
  { d: '2026-11-16', ph: 'exam', title: 'EXAM · MGMT90025 08:30 考试：变革', tasks: [
    { t: 'Bring the two A4 sheets + student ID + charged laptop', zh: '带两张 A4、学生证、充满电的电脑' }, { t: 'MGMT90025 exam 08:30', zh: 'MGMT90025 考试 08:30' } ] }
];
// ===== 计划状态：可编辑、可拖动、可添加（全部存在本机浏览器）=====
const PLAN_KEY = 'yv-plan3';
const todayStr = () => { const t = new Date(); return t.getFullYear() + '-' + String(t.getMonth() + 1).padStart(2, '0') + '-' + String(t.getDate()).padStart(2, '0'); };
const daysUntil = ds => Math.round((new Date(ds + 'T00:00:00') - new Date(todayStr() + 'T00:00:00')) / 86400000);
const fmtDay = ds => ds === 'start' ? 'START' : new Date(ds + 'T00:00:00').toLocaleDateString('en-AU', { weekday: 'short', day: 'numeric', month: 'short' });
const defId = (d, i) => 'd:' + d + ':' + i;
function defaultLayout() {
  const days = {};
  PLAN_DAYS.forEach(d => { days[d.d] = d.tasks.map((t, i) => ({ id: t.id || defId(d.d, i), t: t.t, m: t.m || null })); });
  return days;
}
// 默认任务的中文：用户没改过英文时显示中文辅助
const PLAN_DEFAULTS = {};
PLAN_DAYS.forEach(d => d.tasks.forEach((t, i) => { PLAN_DEFAULTS[t.id || defId(d.d, i)] = t; }));
function taskZh(t) { const def = PLAN_DEFAULTS[t.id]; return t.zh || (def && def.t === t.t ? def.zh : ''); }
let planState = null;
try { planState = JSON.parse(lsGet(PLAN_KEY) || 'null'); } catch (e) {}
if (!planState || typeof planState !== 'object') {
  planState = { custom: false, days: null, done: {}, notes: {} };
  // 迁移旧版打勾（'日期#序号' → 'd:日期:序号'）
  try {
    let old = JSON.parse(lsGet('yv-plan') || '{}');
    if (lsGet('yv-plan-v') !== '2') {
      const o = '2026-10-23#', map = { 0: 'start#0', 1: 'start#1', 2: 'start#2', 3: 'start#3', 4: o + 0, 5: 'start#4', 6: o + 1, 7: o + 2, 8: o + 3 };
      const moved = {}; Object.keys(old).forEach(k => { if (k.startsWith(o)) { const t = map[k.slice(o.length)]; if (t) moved[t] = true; } else moved[k] = old[k]; });
      old = moved;
    }
    Object.keys(old).forEach(k => { const i = k.lastIndexOf('#'); if (i > 0 && old[k]) planState.done[defId(k.slice(0, i), k.slice(i + 1))] = true; });
  } catch (e) {}
}
planState.done = planState.done || {}; planState.notes = planState.notes || {};
// 补丁 4：已自定义的计划也加上每天的"复盘整理"（只加一次，删了不会再加回来）
if ((planState.patch || 0) < 4) {
  if (planState.custom && planState.days) {
    const has = new Set(); Object.values(planState.days).forEach(a => a.forEach(t => has.add(t.id)));
    PLAN_DAYS.forEach(d => d.tasks.forEach(t => { if (t.id && t.id.startsWith('r:') && !has.has(t.id)) (planState.days[d.d] = planState.days[d.d] || []).push({ id: t.id, t: t.t, m: null }); }));
  }
  planState.patch = 4; lsSet(PLAN_KEY, JSON.stringify(planState));
}
function savePlan() { lsSet(PLAN_KEY, JSON.stringify(planState)); }
function planLayout() {
  if (!planState.custom || !planState.days) return defaultLayout();
  PLAN_DAYS.forEach(d => { if (!planState.days[d.d]) planState.days[d.d] = []; });
  return planState.days;
}
function ensureCustom() { if (!planState.custom || !planState.days) { planState.days = defaultLayout(); planState.custom = true; } }
function findTask(id) {
  const L = planLayout();
  for (const d of Object.keys(L)) { const i = L[d].findIndex(t => t.id === id); if (i >= 0) return { day: d, i, task: L[d][i] }; }
  return null;
}
function planStats() {
  const L = planLayout(); let n = 0, k = 0;
  Object.values(L).forEach(arr => arr.forEach(t => { n++; if (planState.done[t.id]) k++; }));
  return { n, k };
}

// ----- 操作 -----
function togglePlanTask(id) {
  if (planState.done[id]) delete planState.done[id]; else planState.done[id] = true;
  savePlan();
  document.querySelectorAll('.plan-task[data-id="' + CSS.escape(id) + '"]').forEach(b => b.classList.toggle('done', !!planState.done[id]));
  updatePlanProgress();
}
function moveTask(id, toDay, toIndex) {
  ensureCustom();
  const f = findTask(id); if (!f) return;
  const [task] = planState.days[f.day].splice(f.i, 1);
  const arr = planState.days[toDay]; if (toIndex == null || toIndex > arr.length) toIndex = arr.length;
  arr.splice(toIndex, 0, task);
  savePlan(); rerenderPlan(id);
}
function addTask(day, text) {
  text = (text || '').trim(); if (!text) return;
  ensureCustom();
  const id = 'u:' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  planState.days[day].push({ id, t: text, m: null, mine: true });
  savePlan(); rerenderPlan(id);
}
let lastDeleted = null;
function deleteTask(id) {
  ensureCustom();
  const f = findTask(id); if (!f) return;
  planState.days[f.day].splice(f.i, 1);
  lastDeleted = { day: f.day, i: f.i, task: f.task, done: !!planState.done[id] };
  delete planState.done[id];
  savePlan(); rerenderPlan();
  planToast('Deleted 已删除', 'Undo 撤销', () => {
    if (!lastDeleted) return;
    planState.days[lastDeleted.day].splice(lastDeleted.i, 0, lastDeleted.task);
    if (lastDeleted.done) planState.done[lastDeleted.task.id] = true;
    lastDeleted = null; savePlan(); rerenderPlan();
  });
}
function editTask(id, text) {
  text = (text || '').trim(); if (!text) return;
  ensureCustom();
  const f = findTask(id); if (!f) return;
  f.task.t = text; savePlan(); rerenderPlan(id);
}
function setNote(day, text) {
  if (text.trim()) planState.notes[day] = text; else delete planState.notes[day];
  savePlan();
}
function resetPlan() {
  if (!confirm('Reset the plan to the default layout? 恢复成默认计划？\nYour own tasks and moves will be removed; ticks on default tasks are kept.')) return;
  Object.keys(planState.done).forEach(k => { if (k.startsWith('u:')) delete planState.done[k]; });
  planState.custom = false; planState.days = null; savePlan(); rerenderPlan();
}
function exportPlan() {
  const blob = new Blob([JSON.stringify({ app: 'young-vault-plan', version: 3, state: planState }, null, 2)], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'young-vault-plan-' + todayStr() + '.json';
  document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}
function importPlan(file) {
  const r = new FileReader();
  r.onload = () => {
    try {
      const j = JSON.parse(r.result);
      if (!j || j.app !== 'young-vault-plan' || !j.state) throw new Error('bad');
      planState = Object.assign({ custom: false, days: null, done: {}, notes: {} }, j.state);
      savePlan(); rerenderPlan(); planToast('Imported 已导入');
    } catch (e) { planToast('Not a Young Vault plan file 不是计划备份文件'); }
  };
  r.readAsText(file);
}
let toastTimer = 0;
function planToast(msg, actLabel, act) {
  let t = document.getElementById('plan-toast');
  if (!t) { t = document.createElement('div'); t.id = 'plan-toast'; document.body.appendChild(t); }
  t.innerHTML = esc(msg) + (actLabel ? ' <button type="button">' + esc(actLabel) + '</button>' : '');
  if (act) t.querySelector('button').onclick = () => { act(); t.classList.remove('show'); };
  t.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 5000);
}

// ----- 渲染 -----
function updatePlanProgress() {
  const { n, k } = planStats();
  document.querySelectorAll('.plan-prog-fill').forEach(f => f.style.width = (n ? k / n * 100 : 0) + '%');
  document.querySelectorAll('.plan-prog-text').forEach(f => f.textContent = k + ' / ' + n + ' tasks 已完成');
  document.querySelectorAll('.plan-day').forEach(dc => {
    const tasks = [...dc.querySelectorAll('.plan-task')], dn = tasks.filter(t => t.classList.contains('done')).length;
    const c = dc.querySelector('.pd-count'); if (c) c.textContent = dn + '/' + tasks.length;
    dc.classList.toggle('complete', tasks.length > 0 && dn === tasks.length);
  });
}
function examChip(e) {
  const s = subjectById[e.sid], col = (s && s.accent) || '#6366f1', left = daysUntil(e.date);
  const when = left > 1 ? left + ' days' : left === 1 ? 'tomorrow' : left === 0 ? 'TODAY' : 'done';
  return `<div class="exam-card${left < 0 ? ' past' : ''}" style="--ec:${col}">
    <div class="ec-top"><span class="ec-code">${e.code}</span><span class="ec-left">${left >= 0 ? '⏳ ' : '✓ '}${when}</span></div>
    <div class="ec-name">${esc(e.name)}</div>
    <div class="ec-when">${fmtDay(e.date)} · ${e.time}</div>
    <div class="ec-tags"><span>${e.fmt}</span><span class="${/Closed/.test(e.rule) ? 'hot' : ''}">${e.rule}</span><span>${e.weight}</span></div>
  </div>`;
}
let dayOptions = '';
function taskHtml(t, opts) {
  const mod = t.m && moduleById[t.m], done = planState.done[t.id] ? ' done' : '';
  const link = mod ? `<button type="button" class="pt-open" data-mod="${mod.id}" style="--mc:${mod.color}">${esc(subjectById[mod.subject_id].code)} · ${esc(mod.week.replace('Week ', 'W'))} →</button>` : '';
  const acts = opts && opts.edit ? `<span class="pt-acts">
      <button type="button" data-act="up" title="Move up 上移">↑</button><button type="button" data-act="down" title="Move down 下移">↓</button>
      <select data-act="move" title="Move to another day 移到其他天">${dayOptions}</select>
      <button type="button" data-act="edit" title="Edit 编辑">✎</button><button type="button" data-act="del" title="Delete 删除">🗑</button></span>` : '';
  return `<div class="plan-task${done}${t.mine ? ' mine' : ''}" data-id="${esc(t.id)}" role="checkbox" tabindex="0"${opts && opts.edit ? ' draggable="true"' : ''}>
    ${opts && opts.edit ? '<span class="pt-grip" title="Drag 拖动">⋮⋮</span>' : ''}<span class="pt-box"></span><span class="pt-text">${esc(t.t)}${taskZh(t) ? '<span class="pt-zh">' + esc(taskZh(t)) + '</span>' : ''}</span>${link}${acts}</div>`;
}
function planEditing() { return document.getElementById('view-plan').classList.contains('editing'); }
function renderPlan() {
  const today = todayStr(), L = planLayout(), edit = planEditing();
  document.getElementById('plan-exams').innerHTML = PLAN_EXAMS.map(examChip).join('');
  dayOptions = '<option value="" disabled selected>⇄ Move to…</option>' + PLAN_DAYS.map(d => `<option value="${d.d}">${fmtDay(d.d)} — ${esc(d.title.slice(0, 34))}</option>`).join('');
  let html = '', lastPh = '';
  PLAN_DAYS.forEach(day => {
    const ph = PLAN_PHASES[day.ph], tasks = L[day.d] || [];
    if (day.ph !== lastPh) { html += `<div class="plan-phase" style="--pc:${ph.color}">${ph.label}</div>`; lastPh = day.ph; }
    const isStart = day.d === 'start';
    const rel = isStart ? '' : day.d < today ? ' past' : day.d === today ? ' today' : '';
    const note = planState.notes[day.d] || '';
    html += `<div class="plan-day${rel}${day.ph === 'exam' ? ' examday' : ''}" style="--pc:${ph.color}" id="pd-${day.d}" data-day="${day.d}">
      <div class="pd-head"><span class="pd-date">${fmtDay(day.d)}</span>${day.d === today ? '<span class="pd-today">TODAY 今天</span>' : ''}<span class="pd-title">${esc(day.title)}</span>
        <button type="button" class="pd-note-btn${note ? ' has' : ''}" title="Notes 今日记录">📝</button><span class="pd-count"></span></div>
      <div class="pd-tasks" data-day="${day.d}">${tasks.map(t => taskHtml(t, { edit })).join('')}</div>
      <div class="pd-add"><input type="text" data-day="${day.d}" placeholder="+ Add a task or what you did 添加任务 / 记录今天做了什么（回车）" maxlength="200"></div>
      <div class="pd-note${note ? ' open' : ''}"><textarea data-day="${day.d}" rows="2" placeholder="Notes for this day 当天笔记 / 心得…">${esc(note)}</textarea></div>
    </div>`;
  });
  document.getElementById('plan-days').innerHTML = html;
  const custom = document.getElementById('plan-custom-tag'); if (custom) custom.style.display = planState.custom ? '' : 'none';
  updatePlanProgress();
}
function rerenderPlan(flashId) {
  const main = document.getElementById('main'), y = main.scrollTop;
  if (currentView === 'plan') { renderPlan(); main.scrollTop = y; }
  renderHomePlan();
  if (flashId) document.querySelectorAll('.plan-task[data-id="' + CSS.escape(flashId) + '"]').forEach(el => { el.classList.add('flash'); setTimeout(() => el.classList.remove('flash'), 1200); });
}
function renderHomePlan() {
  const box = document.getElementById('home-plan'); if (!box) return;
  const today = todayStr(), L = planLayout();
  const next = PLAN_EXAMS.filter(e => daysUntil(e.date) >= 0);
  const day = PLAN_DAYS.find(d => d.d === today) || PLAN_DAYS.find(d => d.d !== 'start' && d.d > today);
  const stTasks = L.start || [], stOpen = stTasks.some(t => !planState.done[t.id]);
  if (!next.length && !day) { box.innerHTML = ''; return; }
  const { n, k } = planStats();
  box.innerHTML = `<div class="home-plan-card">
    <div class="hp-head"><span class="hp-title">📅 Exam plan 期末复习计划</span><button class="hp-open" onclick="goPlan()">Open full plan 完整计划 →</button></div>
    <div class="hp-exams">${next.map(e => { const s = subjectById[e.sid]; const l = daysUntil(e.date); return `<span class="hp-ex" style="--ec:${(s && s.accent) || '#6366f1'}"><b>${l === 0 ? 'TODAY' : l + 'd'}</b> ${e.code}</span>`; }).join('')}</div>
    ${stOpen ? `<div class="hp-day plan-list"><div class="hp-dlabel">Start 起步</div>${stTasks.map(t => taskHtml(t)).join('')}</div>` : ''}
    ${day ? `<div class="hp-day plan-list"><div class="hp-dlabel">${day.d === today ? 'Today 今天' : 'Next 下一天'} · ${fmtDay(day.d)} — ${esc(day.title)}</div>${(L[day.d] || []).map(t => taskHtml(t)).join('')}</div>` : ''}
    <div class="progress-row"><div class="progress-bar"><i class="plan-prog-fill" style="width:${n ? k / n * 100 : 0}%;background:linear-gradient(90deg,#6366f1,#10b981)"></i></div><span class="progress-text plan-prog-text">${k} / ${n} tasks 已完成</span></div>
  </div>`;
}
function goPlan() {
  currentSubjectId = null; currentModuleId = null;
  _navByCode = true; location.hash = 'plan'; _navByCode = false;
  renderPlan();
  showView('plan');
  collapseSidebarOnMobile();
  setTimeout(() => { const t = document.querySelector('.plan-day.today') || document.querySelector('.plan-day:not(.past)'); if (t) t.scrollIntoView({ block: 'center', behavior: 'smooth' }); }, 350);
}
function togglePlanEdit() {
  const v = document.getElementById('view-plan'), on = !v.classList.contains('editing');
  v.classList.toggle('editing', on);
  document.getElementById('plan-edit-btn').textContent = on ? '✓ Done 完成编辑' : '✏️ Edit plan 编辑计划';
  rerenderPlan();
}

// ----- 交互（事件委托）-----
document.addEventListener('click', e => {
  const open = e.target.closest('.pt-open');
  if (open) { e.stopPropagation(); goModule(open.dataset.mod); return; }
  const act = e.target.closest('.pt-acts button');
  if (act) {
    e.stopPropagation();
    const row = act.closest('.plan-task'), id = row.dataset.id, f = findTask(id); if (!f) return;
    if (act.dataset.act === 'up') { if (f.i > 0) moveTask(id, f.day, f.i - 1); else { const k = PLAN_DAYS.findIndex(d => d.d === f.day); if (k > 0) moveTask(id, PLAN_DAYS[k - 1].d, null); } }
    else if (act.dataset.act === 'down') { const len = planLayout()[f.day].length; if (f.i < len - 1) moveTask(id, f.day, f.i + 1); else { const k = PLAN_DAYS.findIndex(d => d.d === f.day); if (k < PLAN_DAYS.length - 1) moveTask(id, PLAN_DAYS[k + 1].d, 0); } }
    else if (act.dataset.act === 'del') deleteTask(id);
    else if (act.dataset.act === 'edit') startEditTask(row, f.task);
    return;
  }
  const nb = e.target.closest('.pd-note-btn');
  if (nb) { const n = nb.closest('.plan-day').querySelector('.pd-note'); n.classList.toggle('open'); if (n.classList.contains('open')) n.querySelector('textarea').focus(); return; }
  const row = e.target.closest('.plan-task');
  if (row && !e.target.closest('select,input,.pt-grip')) togglePlanTask(row.dataset.id);
});
document.addEventListener('change', e => {
  const sel = e.target.closest('.pt-acts select');
  if (sel && sel.value) { moveTask(sel.closest('.plan-task').dataset.id, sel.value, null); planToast('Moved to ' + fmtDay(sel.value) + ' 已移动'); }
});
document.addEventListener('keydown', e => {
  if (e.target.matches && e.target.matches('.pd-add input') && e.key === 'Enter') { addTask(e.target.dataset.day, e.target.value); e.target.value = ''; return; }
  if ((e.key === ' ' || e.key === 'Enter') && e.target.classList && e.target.classList.contains('plan-task')) { e.preventDefault(); togglePlanTask(e.target.dataset.id); }
});
document.addEventListener('input', e => { if (e.target.matches && e.target.matches('.pd-note textarea')) setNote(e.target.dataset.day, e.target.value); });
function startEditTask(row, task) {
  const span = row.querySelector('.pt-text'); if (!span || row.querySelector('.pt-edit')) return;
  const inp = document.createElement('input'); inp.className = 'pt-edit'; inp.value = task.t; inp.maxLength = 200;
  span.replaceWith(inp); inp.focus(); inp.select();
  let doneEdit = false;
  const finish = save => { if (doneEdit) return; doneEdit = true; if (save && inp.value.trim() && inp.value.trim() !== task.t) editTask(task.id, inp.value); else rerenderPlan(); };
  inp.addEventListener('keydown', ev => { if (ev.key === 'Enter') { ev.preventDefault(); finish(true); } if (ev.key === 'Escape') finish(false); ev.stopPropagation(); });
  inp.addEventListener('blur', () => finish(true));
  inp.addEventListener('click', ev => ev.stopPropagation());
}
// 拖动排序（电脑端；手机用 ↑ ↓ 和"移到…"）
let dragId = null; const dropMark = document.createElement('div'); dropMark.className = 'pt-drop';
document.addEventListener('dragstart', e => {
  const row = e.target.closest && e.target.closest('#plan-days .plan-task'); if (!row) return;
  dragId = row.dataset.id; row.classList.add('dragging');
  try { e.dataTransfer.setData('text/plain', dragId); e.dataTransfer.effectAllowed = 'move'; } catch (err) {}
});
document.addEventListener('dragend', () => { document.querySelectorAll('.plan-task.dragging').forEach(r => r.classList.remove('dragging')); dropMark.remove(); dragId = null; });
document.addEventListener('dragover', e => {
  if (!dragId) return;
  const box = e.target.closest && (e.target.closest('.pd-tasks') || (e.target.closest('.plan-day') && e.target.closest('.plan-day').querySelector('.pd-tasks')));
  if (!box) return;
  e.preventDefault();
  const rows = [...box.querySelectorAll('.plan-task:not(.dragging)')];
  const after = rows.find(r => { const b = r.getBoundingClientRect(); return e.clientY < b.top + b.height / 2; });
  if (after) box.insertBefore(dropMark, after); else box.appendChild(dropMark);
});
document.addEventListener('drop', e => {
  if (!dragId || !dropMark.parentNode) return;
  e.preventDefault();
  const box = dropMark.parentNode, day = box.dataset.day;
  const idx = [...box.children].filter(c => c === dropMark || (c.classList.contains('plan-task') && !c.classList.contains('dragging'))).indexOf(dropMark);
  const id = dragId; dropMark.remove(); dragId = null;
  moveTask(id, day, idx);
});

// 浏览器自动填充兜底：加载后清掉被塞进搜索框的内容
[300, 1200].forEach(ms => setTimeout(() => {
  const s = document.getElementById('search-input');
  if (s && s.value && document.activeElement !== s) { s.value = ''; document.getElementById('search-results').classList.remove('visible'); }
}, ms));
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
