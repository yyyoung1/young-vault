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
  --color-text-primary: #111827;
  --color-text-secondary: #6b7280;
  --color-text-tertiary: #9ca3af;
  --color-text-info: #1d4ed8;
  --color-text-success: #15803d;
  --color-text-warning: #92400e;
  --color-text-danger: #991b1b;
  --color-background-primary: #ffffff;
  --color-background-secondary: #eef2f7;
  --color-background-info: #eff6ff;
  --color-background-success: #f0fdf4;
  --color-background-warning: #fffbeb;
  --color-background-danger: #fef2f2;
  --color-border-primary: #c8d3e0;
  --color-border-secondary: #dde3ed;
  --color-border-tertiary: #dce4f0;
  --color-border-info: #bfdbfe;
  --color-border-success: #bbf7d0;
  --color-border-warning: #fde68a;
  --color-border-danger: #fecaca;
  --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', sans-serif;
  --font-mono: 'SF Mono', 'Monaco', monospace;
  --border-radius-sm: 4px;
  --border-radius-md: 8px;
  --border-radius-lg: 12px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; }
body {
  font-family: var(--font-sans);
  color: var(--color-text-primary);
  background: #F9FAFB;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}
.sr-only {
  position: absolute !important; width: 1px !important; height: 1px !important;
  padding: 0 !important; margin: -1px !important; overflow: hidden !important;
  clip: rect(0,0,0,0) !important; white-space: nowrap !important; border: 0 !important;
}
/* Header */
#header {
  background: #1F2937; color: #fff; padding: 0 24px; height: 56px;
  display: flex; align-items: center; gap: 16px; flex-shrink: 0; z-index: 100;
  box-shadow: 0 1px 3px rgba(0,0,0,0.3);
}
.logo { font-size: 20px; font-weight: 700; letter-spacing: -0.5px; color: #fff;
  display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.logo-icon { width: 28px; height: 28px; background: linear-gradient(135deg, #10B981, #6366F1);
  border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: 14px; }
.logo-tagline { font-size: 12px; color: #94a3b8; font-weight: 400; margin-left: 4px; }
.breadcrumb { display: flex; align-items: center; gap: 6px; font-size: 13px; color: #94a3b8; flex: 1; }
.breadcrumb-sep { color: #475569; }
.breadcrumb-item { color: #94a3b8; cursor: pointer; border: none; background: none;
  font-family: var(--font-sans); font-size: 13px; padding: 2px 6px; border-radius: 4px;
  transition: color 0.15s, background 0.15s; }
.breadcrumb-item:hover { color: #fff; background: rgba(255,255,255,0.1); }
.breadcrumb-item.active { color: #e2e8f0; cursor: default; }
.breadcrumb-item.active:hover { background: none; }
#sb-toggle { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center;
  background: none; border: none; cursor: pointer; color: #94a3b8; border-radius: 6px;
  flex-shrink: 0; transition: background 0.15s, color 0.15s; }
#sb-toggle:hover { background: rgba(255,255,255,0.1); color: #fff; }
#sb-toggle svg { width: 18px; height: 18px; }
/* Layout */
#layout { display: flex; flex: 1; overflow: hidden; height: calc(100vh - 56px); }
/* Sidebar */
#sidebar { width: 240px; flex-shrink: 0; background: #1F2937; border-right: 1px solid #2d3748;
  overflow-y: auto; overflow-x: hidden; padding: 12px 0; transition: width 0.22s ease; }
#sidebar.collapsed { width: 0; padding: 0; border-right: none; }
.sidebar-section-label { font-size: 10px; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.08em; color: #6b7280; padding: 8px 16px 4px; }
.sidebar-home-btn { display: flex; align-items: center; gap: 8px; width: 100%; padding: 8px 16px;
  border: none; background: none; font-family: var(--font-sans); font-size: 13px; color: #d1d5db;
  cursor: pointer; text-align: left; transition: background 0.12s, color 0.12s; }
.sidebar-home-btn:hover { background: rgba(16,185,129,0.15); color: #fff; }
.sidebar-home-btn.active { background: rgba(16,185,129,0.2); color: #34d399; font-weight: 500; }
.sidebar-subject-name { font-size: 11px; font-weight: 600; color: #6b7280; padding: 12px 16px 4px;
  text-transform: uppercase; letter-spacing: 0.06em; }
.sidebar-week-header { padding: 6px 16px 2px; font-size: 11px; font-weight: 700; color: #6b7280;
  text-transform: uppercase; letter-spacing: 0.05em; }
.sidebar-module-btn { display: flex; align-items: flex-start; gap: 8px; width: 100%;
  padding: 6px 16px 6px 24px; border: none; background: none; font-family: var(--font-sans);
  font-size: 13px; color: #d1d5db; cursor: pointer; text-align: left; line-height: 1.3;
  transition: background 0.12s, color 0.12s; }
.sidebar-module-btn::before { content: '·'; flex-shrink: 0; margin-top: 1px; color: #4b5563; }
.sidebar-module-btn:hover { background: rgba(16,185,129,0.12); color: #fff; }
.sidebar-module-btn.active { background: rgba(16,185,129,0.2); color: #34d399; font-weight: 500; }
.sidebar-module-btn.active::before { color: #34d399; }
.sidebar-module-btn .sb-texts { display: flex; flex-direction: column; }
.sidebar-module-btn .sb-en { font-size: 13px; font-weight: 500; color: inherit; line-height: 1.4; }
.sidebar-module-btn .sb-zh { font-size: 11px; color: #6b7280; line-height: 1.3; margin-top: 1px; }
.sidebar-module-btn.active .sb-zh { color: #34d399; }
/* Main */
#main { flex: 1; overflow-y: auto; background: var(--color-background-secondary); }
/* Home */
#view-home { padding: 40px 48px; }
.home-title { font-size: 28px; font-weight: 700; color: var(--color-text-primary); margin-bottom: 6px; }
.home-subtitle { font-size: 15px; color: var(--color-text-secondary); margin-bottom: 32px; }
.subjects-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 20px; max-width: 960px; }
.subject-card { background: var(--color-background-primary); border: 1px solid var(--color-border-secondary);
  border-radius: var(--border-radius-lg); padding: 24px; cursor: pointer;
  transition: box-shadow 0.15s, transform 0.15s, border-color 0.15s; position: relative; overflow: hidden; }
.subject-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px;
  background: var(--card-accent, linear-gradient(90deg, #6366f1, #0ea5e9, #10b981)); }
.subject-card:hover { box-shadow: 0 8px 24px rgba(0,0,0,0.10); transform: translateY(-2px);
  border-color: var(--color-border-primary); }
.subject-card-code { font-size: 12px; font-weight: 600; color: var(--color-text-info);
  letter-spacing: 0.05em; margin-bottom: 8px; }
.subject-card-name { font-size: 18px; font-weight: 700; color: var(--color-text-primary); margin-bottom: 6px; }
.subject-card-desc { font-size: 13px; color: var(--color-text-secondary); margin-bottom: 16px; }
.subject-card-stats { display: flex; gap: 12px; }
.subject-card-stat { font-size: 12px; color: var(--color-text-tertiary); display: flex; align-items: center; gap: 4px; }
/* Subject view */
#view-subject { padding: 32px 40px; }
.subject-header { margin-bottom: 28px; }
.subject-header-code { font-size: 12px; font-weight: 600; color: var(--color-text-info); letter-spacing: 0.05em; margin-bottom: 6px; }
.subject-header-name { font-size: 24px; font-weight: 700; color: var(--color-text-primary); margin-bottom: 4px; }
.subject-header-desc { font-size: 14px; color: var(--color-text-secondary); }
.week-group { margin-bottom: 32px; }
.week-group-header { font-size: 13px; font-weight: 700; color: var(--color-text-tertiary);
  text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 12px;
  padding-bottom: 8px; border-bottom: 1px solid var(--color-border-tertiary); }
.modules-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.module-card { background: var(--color-background-primary); border: 1px solid var(--color-border-secondary);
  border-radius: var(--border-radius-lg); padding: 20px; cursor: pointer;
  transition: box-shadow 0.15s, transform 0.15s, border-color 0.15s; position: relative; overflow: hidden; }
.module-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--card-color, #6366f1); }
.module-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.08); transform: translateY(-2px); border-color: var(--color-border-primary); }
.module-card-week { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--card-color, #6366f1); margin-bottom: 8px; }
.module-card-title { font-size: 15px; font-weight: 600; color: var(--color-text-primary); margin-bottom: 6px; line-height: 1.3; }
.module-card-subtitle { font-size: 12px; color: var(--color-text-secondary); line-height: 1.4; }
/* Module view */
#view-module.active { min-height: 100%; display: flex; justify-content: center; padding: 32px 24px; }
.module-content-wrapper { width: 100%; max-width: 760px; background: #ffffff; border-radius: var(--border-radius-lg);
  border: 1px solid var(--color-border-secondary); padding: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.07);
  transform-origin: top center; align-self: flex-start; }
/* Zoom */
#zoom-bar { display: none; position: fixed; bottom: 20px; right: 24px; background: #1F2937;
  border-radius: 20px; padding: 5px 8px; gap: 4px; align-items: center;
  box-shadow: 0 2px 10px rgba(0,0,0,0.25); z-index: 200; }
#zoom-bar.visible { display: flex; }
#zoom-bar button { width: 26px; height: 26px; border: none; background: none; color: #d1d5db;
  font-size: 16px; cursor: pointer; border-radius: 50%; display: flex; align-items: center;
  justify-content: center; transition: background 0.15s; line-height: 1; }
#zoom-bar button:hover { background: rgba(255,255,255,0.12); color: #fff; }
#zoom-bar button:disabled { opacity: 0.3; cursor: default; }
#zoom-label { font-size: 12px; font-weight: 500; color: #d1d5db; min-width: 38px;
  text-align: center; cursor: pointer; padding: 2px 4px; border-radius: 4px; transition: background 0.15s; }
#zoom-label:hover { background: rgba(255,255,255,0.1); color: #fff; }
.view { display: none; }
.view.active { display: block; }
#sidebar::-webkit-scrollbar, #main::-webkit-scrollbar { width: 6px; }
#sidebar::-webkit-scrollbar-track, #main::-webkit-scrollbar-track { background: transparent; }
#sidebar::-webkit-scrollbar-thumb, #main::-webkit-scrollbar-thumb { background: #d1d5db; border-radius: 3px; }
/* Password modal */
#pw-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.55);
  z-index: 500; align-items: center; justify-content: center; }
#pw-overlay.visible { display: flex; }
#pw-box { background: #fff; border-radius: 16px; padding: 36px 32px; width: 340px;
  box-shadow: 0 24px 60px rgba(0,0,0,0.25); text-align: center; }
#pw-icon { font-size: 40px; margin-bottom: 12px; }
#pw-title { font-size: 18px; font-weight: 700; color: #111827; margin-bottom: 6px; }
#pw-subtitle { font-size: 13px; color: #6b7280; margin-bottom: 22px; }
#pw-input { width: 100%; padding: 10px 14px; font-size: 15px; border: 1.5px solid #d1d5db;
  border-radius: 8px; outline: none; font-family: var(--font-sans); letter-spacing: 0.08em;
  transition: border-color 0.15s; }
#pw-input:focus { border-color: #6366f1; }
#pw-input.error { border-color: #ef4444; animation: shake 0.3s; }
@keyframes shake { 0%,100%{transform:translateX(0)} 25%{transform:translateX(-6px)} 75%{transform:translateX(6px)} }
#pw-error-msg { font-size: 12px; color: #ef4444; margin-top: 6px; min-height: 18px; }
#pw-btn-row { display: flex; gap: 10px; margin-top: 18px; }
#pw-submit { flex: 1; padding: 10px; background: #6366f1; color: #fff; border: none;
  border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer;
  transition: background 0.15s; font-family: var(--font-sans); }
#pw-submit:hover { background: #4f46e5; }
#pw-cancel { padding: 10px 16px; background: none; border: 1.5px solid #d1d5db;
  border-radius: 8px; font-size: 14px; color: #6b7280; cursor: pointer;
  transition: border-color 0.15s; font-family: var(--font-sans); }
#pw-cancel:hover { border-color: #9ca3af; color: #374151; }

/* 进度 / 已读 */
.progress-row { display: flex; align-items: center; gap: 10px; margin-top: 14px; }
.progress-bar { flex: 1; height: 5px; background: #e5e7eb; border-radius: 3px; overflow: hidden; }
.progress-bar > div { height: 100%; border-radius: 3px; transition: width 0.3s; }
.progress-text { font-size: 12px; color: var(--color-text-tertiary); white-space: nowrap; }
.card-done { float: right; color: #15803d; font-weight: 600; text-transform: none; letter-spacing: 0; }
.sb-done { margin-left: auto; padding-left: 8px; color: #34d399; font-size: 12px; }
.sidebar-forget { margin-top: 16px; font-size: 12px; color: #6b7280; }
/* 上一页 / 下一页 */
.mod-nav { display: flex; justify-content: space-between; gap: 12px; margin-top: 32px;
  padding-top: 20px; border-top: 1px solid var(--color-border-tertiary); }
.mod-nav-btn { flex: 1; max-width: 48%; padding: 10px 14px; background: #f3f4f6; border: 1px solid var(--color-border-secondary);
  border-radius: 8px; font-size: 13px; color: #374151; cursor: pointer; font-family: var(--font-sans);
  text-align: left; transition: background 0.15s; }
.mod-nav-btn.next { text-align: right; margin-left: auto; }
.mod-nav-btn:hover { background: #e5e7eb; }
/* 搜索 */
#search-wrap { position: relative; flex-shrink: 0; }
#search-input { width: 220px; padding: 7px 12px; border-radius: 8px; border: 1px solid #374151;
  background: #111827; color: #fff; font-size: 13px; font-family: var(--font-sans); outline: none; }
#search-input:focus { border-color: #6366f1; }
#search-results { display: none; position: absolute; right: 0; top: 40px; width: 420px; max-width: calc(100vw - 24px);
  max-height: 70vh; overflow-y: auto; background: #fff; border-radius: 10px; z-index: 300;
  box-shadow: 0 12px 36px rgba(0,0,0,0.25); border: 1px solid var(--color-border-secondary); }
#search-results.visible { display: block; }
.sr-item { padding: 10px 14px; cursor: pointer; border-bottom: 1px solid #f3f4f6; }
.sr-item:hover { background: #f5f7ff; }
.sr-title { font-size: 14px; font-weight: 600; color: #111827; }
.sr-tag { font-size: 11px; font-weight: 500; color: #6366f1; margin-left: 6px; }
.sr-snip { font-size: 12px; color: #6b7280; margin-top: 3px; line-height: 1.5; }
.sr-snip mark { background: #fef08a; color: inherit; border-radius: 2px; }
.sr-empty { padding: 16px; font-size: 13px; color: #6b7280; }
#pw-remember-row { display: block; margin-top: 12px; font-size: 12px; color: #6b7280; cursor: pointer; text-align: left; }
.module-content-wrapper { overflow-x: auto; }
/* 手机适配 */
@media (max-width: 768px) {
  #header { padding: 0 12px; gap: 8px; }
  .logo-tagline { display: none; }
  #search-input { width: 130px; }
  #sidebar { position: fixed; top: 56px; left: 0; bottom: 0; z-index: 150; width: 270px; }
  #sidebar.collapsed { width: 0; }
  #view-home { padding: 24px 16px; }
  #view-subject { padding: 20px 16px; }
  .subjects-grid { grid-template-columns: 1fr; }
  .modules-grid { grid-template-columns: 1fr; }
  #view-module.active { padding: 12px 8px; }
  .module-content-wrapper { padding: 14px; }
  .breadcrumb { overflow: hidden; white-space: nowrap; }
  #search-results { position: fixed; left: 12px; right: 12px; top: 60px; width: auto; }
  .mod-nav { flex-direction: column; }
  .mod-nav-btn { max-width: 100%; }
}
@media (max-width: 520px) { .breadcrumb { display: none; } #search-wrap { flex: 1; } #search-input { width: 100%; } }
</style>
</head>
<body>

<header id="header">
  <button id="sb-toggle" onclick="toggleSidebar()" title="Toggle sidebar">
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
      <h1 class="home-title">Welcome back 👋</h1>
      <p class="home-subtitle">Select a subject to start reviewing.</p>
      <div class="subjects-grid" id="subjects-grid"></div>
    </section>

    <section id="view-subject" class="view">
      <div class="subject-header">
        <div class="subject-header-code" id="subj-code"></div>
        <div class="subject-header-name" id="subj-name"></div>
        <div class="subject-header-desc" id="subj-desc"></div>
      </div>
      <div id="subject-module-list"></div>
    </section>

    <section id="view-module" class="view">
      <div class="module-content-wrapper" id="module-content"></div>
    </section>

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
})();
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
  let html = '';
  for (const s of SUBJECTS) {
    const weeks = new Set(s.modules.map(m => m.week)).size;
    const done = readCount(s), total = s.modules.length;
    const lock = s.enc && !unlocked[s.id] ? ' 🔒' : '';
    html += `
      <div class="subject-card" style="--card-accent:${s.accent}" onclick="goSubject('${s.id}')" role="button" tabindex="0">
        <div class="subject-card-code">${s.code}${lock}</div>
        <div class="subject-card-name">${s.name}</div>
        <div class="subject-card-desc">${s.desc}</div>
        <div class="subject-card-stats">
          <span class="subject-card-stat">📚 ${total} modules</span>
          <span class="subject-card-stat">📅 ${weeks} weeks</span>
        </div>
        <div class="progress-row">
          <div class="progress-bar"><div style="width:${total ? done/total*100 : 0}%;background:${s.accent}"></div></div>
          <span class="progress-text">已读 ${done}/${total}</span>
        </div>
      </div>`;
  }
  document.getElementById('subjects-grid').innerHTML = html;
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
        html += `<button class="sidebar-module-btn${active}" onclick="goModule('${m.id}')">
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
  document.getElementById('subj-desc').textContent = s.desc + ` · 已读 ${readCount(s)}/${s.modules.length}`;
  let html = '';
  for (const g of groupByWeek(s.modules)) {
    html += `<div class="week-group"><div class="week-group-header">${g.week}</div><div class="modules-grid">`;
    for (const m of g.modules) {
      const done = readSet.has(m.id) ? '<span class="card-done">✓ 已读</span>' : '';
      html += `<div class="module-card" style="--card-color:${m.color}" onclick="goModule('${m.id}')" role="button" tabindex="0">
        <div class="module-card-week">${m.week}${done}</div>
        <div class="module-card-title">${m.title}</div>
        <div class="module-card-subtitle">${m.subtitle}</div>
      </div>`;
    }
    html += `</div></div>`;
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
  document.getElementById('main').scrollTop = 0;
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
