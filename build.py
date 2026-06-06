#!/usr/bin/env python3
"""Build script for Young Vault study website."""

import json
import os

BASE_DIR = "/Users/yangyi/Desktop/YoungVault"

# Module definitions: (filename, week_label, title_EN, subtitle_ZH, color)
MODULE_DEFS = [
    ("week1_linear_programming.html",         "Week 1", "Linear Programming",       "LP三大要素 · 建模 · 解读",          "#10B981"),
    ("week2_sensitivity_ilp.html",            "Week 2", "Sensitivity Analysis & ILP","敏感性分析 · 整数规划",            "#10B981"),
    ("week3_nlp.html",                        "Week 3", "LP Applications & NLP",    "LP应用 · 非线性规划",              "#10B981"),
    ("week4_probability.html",                "Week 4", "Probability Distributions", "离散 · 连续 · Excel公式",          "#F59E0B"),
    ("week5_monte_carlo.html",                "Week 5", "Monte Carlo Simulation",   "随机模拟 · Uniform · Normal",      "#F59E0B"),
    ("week6_descriptive_data_mining.html",    "Week 6", "Descriptive Data Mining",  "聚类 · 关联规则 · 文本挖掘",       "#6366F1"),
    ("week7_regression_interactive_guide.html","Week 7", "Regression Analysis",     "回归分析互动指南",                 "#6366F1"),
    ("sat_gpa_interaction_regression.html",   "Week 7", "Interaction Term Regression","SAT × GPA 交互项",              "#6366F1"),
    ("week8_time_series_patterns.html",       "Week 8", "Time Series Patterns",     "时间序列模式",                    "#F59E0B"),
    ("week8_2_forecast_methods.html",         "Week 8", "Forecast Methods",         "预测方法 · Naive · MA · ES",       "#F59E0B"),
    ("week8_3_regression_forecasting.html",   "Week 8", "Regression Forecasting",   "回归预测时间序列",                 "#F59E0B"),
    ("week8_exam_review_checklist.html",      "Week 8", "Exam Review Checklist",    "考前复习清单",                    "#F59E0B"),
    ("week9_predictive_data_mining.html",     "Week 9", "Predictive Data Mining",   "分类树 · 逻辑回归",               "#10B981"),
    ("week9_full_exam_question.html",         "Week 9", "Full Exam Practice",       "完整考题练习 · BankChurn",         "#10B981"),
    ("exam_past_papers.html",                 "Finals", "Past Exam Papers",         "历年真题 · 官方答案解析",            "#6366F1"),
]

modules = []
for fname, week, title, subtitle, color in MODULE_DEFS:
    path = os.path.join(BASE_DIR, fname)
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    mod_id = fname.replace(".html", "")
    modules.append({
        "id": mod_id,
        "week": week,
        "title": title,
        "subtitle": subtitle,
        "color": color,
        "content": content,
    })

modules_json = (json.dumps(modules, ensure_ascii=False)
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
/* ===== CSS Variables ===== */
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
  --color-text-info: #1d4ed8;
  --color-border-info: #bfdbfe;
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

/* ===== Reset & Base ===== */
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

/* ===== Accessibility ===== */
.sr-only {
  position: absolute !important;
  width: 1px !important;
  height: 1px !important;
  padding: 0 !important;
  margin: -1px !important;
  overflow: hidden !important;
  clip: rect(0,0,0,0) !important;
  white-space: nowrap !important;
  border: 0 !important;
}

/* Hide Claude-specific buttons */
.ask-btn { display: none !important; }

/* ===== Header ===== */
#header {
  background: #1F2937;
  color: #fff;
  padding: 0 24px;
  height: 56px;
  display: flex;
  align-items: center;
  gap: 16px;
  flex-shrink: 0;
  z-index: 100;
  box-shadow: 0 1px 3px rgba(0,0,0,0.3);
}

.logo {
  font-size: 20px;
  font-weight: 700;
  letter-spacing: -0.5px;
  color: #fff;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}

.logo-icon {
  width: 28px;
  height: 28px;
  background: linear-gradient(135deg, #10B981, #6366F1);
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
}

.logo-tagline {
  font-size: 12px;
  color: #94a3b8;
  font-weight: 400;
  margin-left: 4px;
}

.breadcrumb {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  color: #94a3b8;
  flex: 1;
}

.breadcrumb-sep { color: #475569; }

.breadcrumb-item {
  color: #94a3b8;
  cursor: pointer;
  border: none;
  background: none;
  font-family: var(--font-sans);
  font-size: 13px;
  padding: 2px 6px;
  border-radius: 4px;
  transition: color 0.15s, background 0.15s;
}
.breadcrumb-item:hover { color: #fff; background: rgba(255,255,255,0.1); }
.breadcrumb-item.active { color: #e2e8f0; cursor: default; }
.breadcrumb-item.active:hover { background: none; }

/* ===== Sidebar Toggle Button ===== */
#sb-toggle {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: none;
  border: none;
  cursor: pointer;
  color: #94a3b8;
  border-radius: 6px;
  flex-shrink: 0;
  transition: background 0.15s, color 0.15s;
}
#sb-toggle:hover { background: rgba(255,255,255,0.1); color: #fff; }
#sb-toggle svg { width: 18px; height: 18px; }

/* ===== Layout ===== */
#layout {
  display: flex;
  flex: 1;
  overflow: hidden;
  height: calc(100vh - 56px);
}

/* ===== Sidebar ===== */
#sidebar {
  width: 240px;
  flex-shrink: 0;
  background: #1F2937;
  border-right: 1px solid #2d3748;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 12px 0;
  transition: width 0.22s ease;
}
#sidebar.collapsed {
  width: 0;
  padding: 0;
  border-right: none;
}

.sidebar-section-label {
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #6b7280;
  padding: 8px 16px 4px;
}

.sidebar-home-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 8px 16px;
  border: none;
  background: none;
  font-family: var(--font-sans);
  font-size: 13px;
  color: #d1d5db;
  cursor: pointer;
  text-align: left;
  border-radius: 0;
  transition: background 0.12s, color 0.12s;
}
.sidebar-home-btn:hover { background: rgba(16,185,129,0.15); color: #fff; }
.sidebar-home-btn.active { background: rgba(16,185,129,0.2); color: #34d399; font-weight: 500; }

.sidebar-subject-name {
  font-size: 11px;
  font-weight: 600;
  color: #6b7280;
  padding: 12px 16px 4px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.sidebar-week-header {
  padding: 6px 16px 2px;
  font-size: 11px;
  font-weight: 700;
  color: #6b7280;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.sidebar-module-btn {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  width: 100%;
  padding: 6px 16px 6px 24px;
  border: none;
  background: none;
  font-family: var(--font-sans);
  font-size: 13px;
  color: #d1d5db;
  cursor: pointer;
  text-align: left;
  line-height: 1.3;
  transition: background 0.12s, color 0.12s;
}
.sidebar-module-btn::before {
  content: '·';
  flex-shrink: 0;
  margin-top: 1px;
  color: #4b5563;
}
.sidebar-module-btn:hover { background: rgba(16,185,129,0.12); color: #fff; }
.sidebar-module-btn.active {
  background: rgba(16,185,129,0.2);
  color: #34d399;
  font-weight: 500;
}
.sidebar-module-btn.active::before { color: #34d399; }
.sidebar-module-btn .sb-texts { display: flex; flex-direction: column; }
.sidebar-module-btn .sb-en { font-size: 13px; font-weight: 500; color: inherit; line-height: 1.4; }
.sidebar-module-btn .sb-zh { font-size: 11px; color: #6b7280; line-height: 1.3; margin-top: 1px; }
.sidebar-module-btn.active .sb-zh { color: #34d399; }

/* ===== Main Content ===== */
#main {
  flex: 1;
  overflow-y: auto;
  background: var(--color-background-secondary);
}

/* ===== Home View ===== */
#view-home {
  padding: 40px 48px;
}

.home-title {
  font-size: 28px;
  font-weight: 700;
  color: var(--color-text-primary);
  margin-bottom: 6px;
}

.home-subtitle {
  font-size: 15px;
  color: var(--color-text-secondary);
  margin-bottom: 32px;
}

.subjects-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 20px;
  max-width: 960px;
}

.subject-card {
  background: var(--color-background-primary);
  border: 1px solid var(--color-border-secondary);
  border-radius: var(--border-radius-lg);
  padding: 24px;
  cursor: pointer;
  transition: box-shadow 0.15s, transform 0.15s, border-color 0.15s;
  position: relative;
  overflow: hidden;
}
.subject-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 4px;
  background: linear-gradient(90deg, #6366f1, #0ea5e9, #10b981);
}
.subject-card:hover {
  box-shadow: 0 8px 24px rgba(0,0,0,0.10);
  transform: translateY(-2px);
  border-color: var(--color-border-primary);
}

.subject-card-code {
  font-size: 12px;
  font-weight: 600;
  color: var(--color-text-info);
  letter-spacing: 0.05em;
  margin-bottom: 8px;
}

.subject-card-name {
  font-size: 18px;
  font-weight: 700;
  color: var(--color-text-primary);
  margin-bottom: 6px;
}

.subject-card-desc {
  font-size: 13px;
  color: var(--color-text-secondary);
  margin-bottom: 16px;
}

.subject-card-stats {
  display: flex;
  gap: 12px;
}

.subject-card-stat {
  font-size: 12px;
  color: var(--color-text-tertiary);
  display: flex;
  align-items: center;
  gap: 4px;
}

/* ===== Subject View ===== */
#view-subject {
  padding: 32px 40px;
}

.subject-header {
  margin-bottom: 28px;
}

.subject-header-code {
  font-size: 12px;
  font-weight: 600;
  color: var(--color-text-info);
  letter-spacing: 0.05em;
  margin-bottom: 6px;
}

.subject-header-name {
  font-size: 24px;
  font-weight: 700;
  color: var(--color-text-primary);
  margin-bottom: 4px;
}

.subject-header-desc {
  font-size: 14px;
  color: var(--color-text-secondary);
}

.week-group { margin-bottom: 32px; }

.week-group-header {
  font-size: 13px;
  font-weight: 700;
  color: var(--color-text-tertiary);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-bottom: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--color-border-tertiary);
}

.modules-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
}

.module-card {
  background: var(--color-background-primary);
  border: 1px solid var(--color-border-secondary);
  border-radius: var(--border-radius-lg);
  padding: 20px;
  cursor: pointer;
  transition: box-shadow 0.15s, transform 0.15s, border-color 0.15s;
  position: relative;
  overflow: hidden;
}

.module-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 3px;
  background: var(--card-color, #6366f1);
}

.module-card:hover {
  box-shadow: 0 4px 16px rgba(0,0,0,0.08);
  transform: translateY(-2px);
  border-color: var(--color-border-primary);
}

.module-card-week {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--card-color, #6366f1);
  margin-bottom: 8px;
}

.module-card-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--color-text-primary);
  margin-bottom: 6px;
  line-height: 1.3;
}

.module-card-subtitle {
  font-size: 12px;
  color: var(--color-text-secondary);
  line-height: 1.4;
}

/* ===== Module View ===== */
#view-module.active {
  min-height: 100%;
  display: flex;
  justify-content: center;
  padding: 32px 24px;
}

.module-content-wrapper {
  width: 100%;
  max-width: 760px;
  background: #ffffff;
  border-radius: var(--border-radius-lg);
  border: 1px solid var(--color-border-secondary);
  padding: 24px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.07);
  transform-origin: top center;
  align-self: flex-start;
}

/* ===== Zoom Control ===== */
#zoom-bar {
  display: none;
  position: fixed;
  bottom: 20px;
  right: 24px;
  background: #1F2937;
  border-radius: 20px;
  padding: 5px 8px;
  gap: 4px;
  align-items: center;
  box-shadow: 0 2px 10px rgba(0,0,0,0.25);
  z-index: 200;
}
#zoom-bar.visible { display: flex; }
#zoom-bar button {
  width: 26px;
  height: 26px;
  border: none;
  background: none;
  color: #d1d5db;
  font-size: 16px;
  cursor: pointer;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background 0.15s;
  line-height: 1;
}
#zoom-bar button:hover { background: rgba(255,255,255,0.12); color: #fff; }
#zoom-bar button:disabled { opacity: 0.3; cursor: default; }
#zoom-label {
  font-size: 12px;
  font-weight: 500;
  color: #d1d5db;
  min-width: 38px;
  text-align: center;
  cursor: pointer;
  padding: 2px 4px;
  border-radius: 4px;
  transition: background 0.15s;
}
#zoom-label:hover { background: rgba(255,255,255,0.1); color: #fff; }

/* ===== Hidden ===== */
.view { display: none; }
.view.active { display: block; }

/* ===== Scrollbar ===== */
#sidebar::-webkit-scrollbar,
#main::-webkit-scrollbar { width: 6px; }
#sidebar::-webkit-scrollbar-track,
#main::-webkit-scrollbar-track { background: transparent; }
#sidebar::-webkit-scrollbar-thumb,
#main::-webkit-scrollbar-thumb { background: #d1d5db; border-radius: 3px; }
#sidebar::-webkit-scrollbar-thumb:hover,
#main::-webkit-scrollbar-thumb:hover { background: #9ca3af; }
</style>
</head>
<body>

<!-- HEADER -->
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
  <nav class="breadcrumb" id="breadcrumb" aria-label="Navigation">
    <!-- filled by JS -->
  </nav>
</header>

<!-- LAYOUT -->
<div id="layout">
  <!-- SIDEBAR -->
  <aside id="sidebar">
    <div class="sidebar-section-label">Navigation</div>
    <button class="sidebar-home-btn" id="sb-home" onclick="goHome()">
      🏠 Home
    </button>
    <div id="sb-subject-section" style="display:none">
      <div class="sidebar-subject-name">MGMT90280</div>
      <div id="sb-week-list"></div>
    </div>
  </aside>

  <!-- MAIN -->
  <main id="main">
    <!-- HOME VIEW -->
    <section id="view-home" class="view active">
      <h1 class="home-title">Welcome back 👋</h1>
      <p class="home-subtitle">Select a subject to start reviewing.</p>
      <div class="subjects-grid">
        <div class="subject-card" onclick="goSubject('mgmt90280')" role="button" tabindex="0">
          <div class="subject-card-code">MGMT90280</div>
          <div class="subject-card-name">Managerial Decision Analytics</div>
          <div class="subject-card-desc">Business Analytics · Weeks 1–9</div>
          <div class="subject-card-stats">
            <span class="subject-card-stat">📚 14 modules</span>
            <span class="subject-card-stat">📅 9 weeks</span>
          </div>
        </div>
      </div>
    </section>

    <!-- SUBJECT VIEW -->
    <section id="view-subject" class="view">
      <div class="subject-header">
        <div class="subject-header-code">MGMT90280</div>
        <div class="subject-header-name">Managerial Decision Analytics</div>
        <div class="subject-header-desc">Business Analytics · Weeks 1–9</div>
      </div>
      <div id="subject-module-list"></div>
    </section>

    <!-- MODULE VIEW -->
    <section id="view-module" class="view">
      <div class="module-content-wrapper" id="module-content"></div>
    </section>

  <!-- Zoom control -->
  <div id="zoom-bar">
    <button id="zoom-out" onclick="adjustZoom(-1)" title="缩小">−</button>
    <span id="zoom-label" onclick="resetZoom()" title="点击还原100%">100%</span>
    <button id="zoom-in" onclick="adjustZoom(1)" title="放大">+</button>
  </div>
  </main>
</div>

<script>
const MODULES = """ + modules_json + r""";

// ===== Zoom =====
const ZOOM_STEPS = [50, 75, 100, 125, 150, 175, 200];
let zoomIdx = 2; // always start at 100%

function applyZoom() {
  const z = ZOOM_STEPS[zoomIdx];
  document.getElementById('module-content').style.transform = `scale(${z/100})`;
  document.getElementById('module-content').style.marginBottom = z > 100 ? `${(z-100)*3}px` : '0';
  document.getElementById('zoom-label').textContent = z + '%';
  document.getElementById('zoom-out').disabled = zoomIdx === 0;
  document.getElementById('zoom-in').disabled  = zoomIdx === ZOOM_STEPS.length - 1;
}
function adjustZoom(dir) { zoomIdx = Math.max(0, Math.min(ZOOM_STEPS.length-1, zoomIdx+dir)); applyZoom(); }
function resetZoom() { zoomIdx = 2; applyZoom(); }
applyZoom();

// ===== Sidebar Toggle =====
function toggleSidebar() {
  const sb = document.getElementById('sidebar');
  const collapsed = sb.classList.toggle('collapsed');
  localStorage.setItem('sb-collapsed', collapsed ? '1' : '0');
}
(function() {
  if (localStorage.getItem('sb-collapsed') === '1') {
    document.getElementById('sidebar').classList.add('collapsed');
  }
})();

// ===== State =====
let currentView = 'home';   // 'home' | 'subject' | 'module'
let currentSubject = null;
let currentModuleId = null;
let _navByCode = false;     // prevents hashchange loop

// ===== Helpers =====
function groupByWeek(mods) {
  const map = {};
  const order = [];
  for (const m of mods) {
    if (!map[m.week]) { map[m.week] = []; order.push(m.week); }
    map[m.week].push(m);
  }
  return order.map(w => ({ week: w, modules: map[w] }));
}

// ===== Breadcrumb =====
function renderBreadcrumb() {
  const bc = document.getElementById('breadcrumb');
  let html = '<button class="breadcrumb-item" onclick="goHome()">Young Vault</button>';
  if (currentView === 'subject') {
    html += '<span class="breadcrumb-sep">›</span>';
    html += '<button class="breadcrumb-item active">MGMT90280</button>';
  } else if (currentView === 'module') {
    const mod = MODULES.find(m => m.id === currentModuleId);
    html += '<span class="breadcrumb-sep">›</span>';
    html += '<button class="breadcrumb-item" onclick="goSubject(\'mgmt90280\')">MGMT90280</button>';
    html += '<span class="breadcrumb-sep">›</span>';
    html += `<button class="breadcrumb-item active">${mod ? mod.title : ''}</button>`;
  }
  bc.innerHTML = html;
}

// ===== Sidebar =====
function renderSidebar() {
  const sbHome = document.getElementById('sb-home');
  const sbSubjectSection = document.getElementById('sb-subject-section');

  if (currentView === 'home') {
    sbHome.className = 'sidebar-home-btn active';
    sbSubjectSection.style.display = 'none';
  } else {
    sbHome.className = 'sidebar-home-btn';
    sbSubjectSection.style.display = 'block';
    renderSidebarModules();
  }
}

function renderSidebarModules() {
  const container = document.getElementById('sb-week-list');
  const groups = groupByWeek(MODULES);
  let html = '';
  for (const g of groups) {
    html += `<div class="sidebar-week-header">${g.week}</div>`;
    for (const m of g.modules) {
      const active = m.id === currentModuleId ? ' active' : '';
      html += `<button class="sidebar-module-btn${active}" onclick="goModule('${m.id}')"><div class="sb-texts"><span class="sb-en">${m.title}</span><span class="sb-zh">${m.subtitle}</span></div></button>`;
    }
  }
  container.innerHTML = html;
}

// ===== Subject module grid =====
function renderSubjectModules() {
  const container = document.getElementById('subject-module-list');
  const groups = groupByWeek(MODULES);
  let html = '';
  for (const g of groups) {
    html += `<div class="week-group">`;
    html += `<div class="week-group-header">${g.week}</div>`;
    html += `<div class="modules-grid">`;
    for (const m of g.modules) {
      html += `
        <div class="module-card" style="--card-color:${m.color}" onclick="goModule('${m.id}')" role="button" tabindex="0">
          <div class="module-card-week">${m.week}</div>
          <div class="module-card-title">${m.title}</div>
          <div class="module-card-subtitle">${m.subtitle}</div>
        </div>`;
    }
    html += `</div></div>`;
  }
  container.innerHTML = html;
}

// ===== View switching =====
function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById('view-' + name).classList.add('active');
  currentView = name;
  document.getElementById('main').scrollTop = 0;
  document.getElementById('zoom-bar').classList.toggle('visible', name === 'module');
  renderBreadcrumb();
  renderSidebar();
}

function goHome() {
  currentSubject = null;
  currentModuleId = null;
  _navByCode = true; location.hash = ''; _navByCode = false;
  showView('home');
}

function goSubject(id) {
  currentSubject = id;
  currentModuleId = null;
  _navByCode = true; location.hash = 'subject/' + id; _navByCode = false;
  renderSubjectModules();
  showView('subject');
}

function goModule(id) {
  currentModuleId = id;
  const mod = MODULES.find(m => m.id === id);
  if (!mod) return;
  _navByCode = true; location.hash = 'module/' + id; _navByCode = false;

  const contentDiv = document.getElementById('module-content');
  contentDiv.innerHTML = mod.content;

  // Re-execute script tags so interactive features work
  contentDiv.querySelectorAll('script').forEach(old => {
    const s = document.createElement('script');
    s.textContent = old.textContent;
    old.replaceWith(s);
  });

  showView('module');
}

// ===== Hash-based navigation (browser back/forward) =====
window.addEventListener('hashchange', function() {
  if (_navByCode) return;
  const hash = location.hash.slice(1);
  if (hash.startsWith('module/')) goModule(hash.slice(7));
  else if (hash.startsWith('subject/')) goSubject(hash.slice(8));
  else goHome();
});

// ===== Keyboard support for cards =====
document.addEventListener('keydown', function(e) {
  if (e.key === 'Enter' && e.target.getAttribute('role') === 'button') {
    e.target.click();
  }
});

// ===== Init: restore position from hash on load/refresh =====
(function() {
  const hash = location.hash.slice(1);
  if (hash.startsWith('module/')) goModule(hash.slice(7));
  else if (hash.startsWith('subject/')) goSubject(hash.slice(8));
  else { renderBreadcrumb(); renderSidebar(); }
})();
</script>
</body>
</html>"""

out_path = os.path.join(BASE_DIR, "index.html")
with open(out_path, "w", encoding="utf-8") as f:
    f.write(html)

size_kb = os.path.getsize(out_path) / 1024
print(f"Done! Written to {out_path}")
print(f"File size: {size_kb:.1f} KB")
