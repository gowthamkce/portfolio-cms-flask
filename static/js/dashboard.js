/**
 * Portfolio Admin Dashboard — dashboard.js
 */

'use strict';

const API = 'http://127.0.0.1:5000/api';

const PAGE_META = {
  dashboard:  ['Dashboard',  'Live portfolio overview'],
  profile:    ['Profile',    'Your public identity'],
  projects:   ['Projects',   'Showcase your work'],
  skills:     ['Skills',     'Technical expertise'],
  experience: ['Experience', 'Work history'],
  education:  ['Education',  'Academic background'],
  messages:   ['Messages',   'Contact form submissions'],
  analytics:  ['Analytics',  'Visitor insights (30 days)'],
};

const LEVEL_PCT = { Beginner: 28, Intermediate: 58, Advanced: 80, Expert: 96 };
const DAYS_ABBR = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

// ── Generic fetch helpers ─────────────────────────────────────────────────────
async function req(method, path, body) {
  const opts = { method, credentials: 'include', headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(API + path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}
const GET    = (p)    => req('GET',    p);
const POST   = (p, b) => req('POST',   p, b);
const PUT    = (p, b) => req('PUT',    p, b);
const DELETE = (p)    => req('DELETE', p);

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, type = 'success') {
  const el = document.getElementById('toast');
  if (!el) return;
  document.getElementById('toast-icon').textContent = type === 'success' ? '✓' : '✕';
  document.getElementById('toast-msg').textContent = msg;
  el.classList.toggle('error', type === 'error');
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 3200);
}

// ── Built-in Login Screen ─────────────────────────────────────────────────────
function showLoginScreen(errorMsg) {
  document.body.innerHTML = `
    <style>
      *{margin:0;padding:0;box-sizing:border-box;}
      body{background:#050709;font-family:'DM Mono',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;}
      .lb{background:#0b0e14;border:1px solid #1c2130;border-radius:18px;padding:44px 40px;width:380px;max-width:94vw;box-shadow:0 40px 100px rgba(0,0,0,.7);}
      .li{width:48px;height:48px;border-radius:12px;background:rgba(0,212,170,.1);border:1px solid rgba(0,212,170,.25);display:flex;align-items:center;justify-content:center;font-size:20px;margin-bottom:20px;}
      .lh{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:#e8eef5;margin-bottom:8px;}
      .ls{font-size:11px;color:#6b7589;margin-bottom:26px;}
      .fg{display:flex;flex-direction:column;gap:6px;margin-bottom:14px;}
      label{font-size:9px;color:#6b7589;letter-spacing:2px;text-transform:uppercase;}
      input{background:#050709;border:1px solid #1c2130;border-radius:8px;padding:12px 14px;color:#e8eef5;font-family:'DM Mono',monospace;font-size:12px;outline:none;width:100%;transition:all .2s;}
      input:focus{border-color:#00d4aa;box-shadow:0 0 0 3px rgba(0,212,170,.08);}
      .le{font-size:11px;color:#ff6b6b;background:rgba(255,107,107,.08);border:1px solid rgba(255,107,107,.2);border-radius:6px;padding:9px 12px;margin-bottom:12px;display:none;}
      .le.show{display:block;}
      .lb-btn{width:100%;padding:13px;background:#00d4aa;color:#050709;border:none;border-radius:8px;font-family:'DM Mono',monospace;font-size:12px;font-weight:500;cursor:pointer;transition:all .2s;margin-top:6px;}
      .lb-btn:hover{background:#00c49a;}
      .lb-btn:disabled{opacity:.6;cursor:not-allowed;}
    </style>
    <link href="https://fonts.googleapis.com/css2?family=Syne:wght@800&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
    <div class="lb">
      <div class="li">⬡</div>
      <div class="lh">Admin Login</div>
      <div class="ls">Sign in to manage your portfolio content.</div>
      <div class="le" id="login-err"></div>
      <div class="fg"><label>Email</label><input type="email" id="login-email" placeholder="admin@example.com" /></div>
      <div class="fg"><label>Password</label><input type="password" id="login-pass" placeholder="••••••••" /></div>
      <button class="lb-btn" id="login-btn" onclick="doLogin()">Sign In → Admin Panel</button>
    </div>`;
  if (errorMsg) {
    const el = document.getElementById('login-err');
    el.textContent = errorMsg;
    el.classList.add('show');
  }
  setTimeout(() => document.getElementById('login-email')?.focus(), 100);
  document.addEventListener('keydown', function h(e) {
    if (e.key === 'Enter') { doLogin(); document.removeEventListener('keydown', h); }
  });
}

async function doLogin() {
  const btn   = document.getElementById('login-btn');
  const errEl = document.getElementById('login-err');
  const email = document.getElementById('login-email')?.value.trim();
  const pass  = document.getElementById('login-pass')?.value;
  if (!email || !pass) {
    errEl.textContent = 'Please enter your email and password.';
    errEl.classList.add('show'); return;
  }
  btn.disabled = true;
  btn.textContent = 'Signing in...';
  try {
    const r = await fetch(API + '/auth/login', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pass }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Login failed');
    window.location.reload();
  } catch(e) {
    errEl.textContent = e.message || 'Invalid credentials.';
    errEl.classList.add('show');
    btn.disabled = false;
    btn.textContent = 'Sign In → Admin Panel';
  }
}

// ── Confirm delete modal ──────────────────────────────────────────────────────
function confirmDelete(msg, onOk) {
  document.getElementById('confirm-msg').textContent = msg || 'Delete this item?';
  const btn = document.getElementById('confirm-ok-btn');
  const newBtn = btn.cloneNode(true);
  btn.parentNode.replaceChild(newBtn, btn);
  newBtn.onclick = () => { closeModal('confirm-modal'); onOk(); };
  openModal('confirm-modal');
}

// ── Modal helpers ─────────────────────────────────────────────────────────────
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
});

// ── Navigation ────────────────────────────────────────────────────────────────
function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const page = document.getElementById('page-' + id);
  const nav  = document.querySelector(`.nav-item[data-page="${id}"]`);
  if (!page) return;
  page.classList.add('active');
  if (nav) nav.classList.add('active');
  const [title, sub] = PAGE_META[id] || [id, ''];
  document.getElementById('page-title').textContent = title;
  document.getElementById('page-sub').textContent   = sub;
  const loaders = {
    dashboard: loadDashboard, profile: loadProfile, projects: loadProjects,
    skills: loadSkills, experience: loadExperience, education: loadEducation,
    messages: loadMessages, analytics: loadAnalytics,
  };
  if (loaders[id]) loaders[id]();
}

document.querySelectorAll('.nav-item[data-page]').forEach(btn => {
  btn.addEventListener('click', () => showPage(btn.dataset.page));
});

// ── Auth ──────────────────────────────────────────────────────────────────────
async function checkAuth() {
  try {
    const data = await GET('/auth/me');
    if (!data.logged_in) { showLoginScreen(); return false; }
    document.getElementById('admin-name').textContent   = data.name || 'Admin';
    document.getElementById('admin-avatar').textContent = (data.name || 'A')[0].toUpperCase();
    return true;
  } catch {
    showLoginScreen('Could not connect to server.');
    return false;
  }
}

document.getElementById('logout-btn').addEventListener('click', async () => {
  await req('POST', '/auth/logout').catch(() => {});
  showLoginScreen();
});

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const s = await GET('/dashboard');
    document.getElementById('s-views').textContent    = s.views_30          ?? '—';
    document.getElementById('s-unique').textContent   = `${s.unique_visitors ?? '—'} unique visitors`;
    document.getElementById('s-msgs').textContent     = s.total_messages     ?? '—';
    document.getElementById('s-unread').textContent   = `${s.unread_messages ?? '—'} unread`;
    document.getElementById('s-projects').textContent = s.projects           ?? '—';
    document.getElementById('s-skills').textContent   = s.skills             ?? '—';
    if (s.unread_messages > 0) {
      const b = document.getElementById('msg-badge');
      b.textContent = s.unread_messages; b.style.display = 'inline';
    }
  } catch (e) { console.error('Dashboard stats:', e); }
  try {
    const msgs = await GET('/contact');
    const el   = document.getElementById('dash-messages');
    const show = msgs.slice(0, 5);
    if (!show.length) { el.innerHTML = '<div class="empty">No messages yet.</div>'; }
    else { el.innerHTML = show.map(m => `<div class="msg-preview ${m.read_status?'':'unread'}"><div class="msg-dot ${m.read_status?'read':''}"></div><div class="msg-name">${esc(m.name)}</div><div class="msg-sub">${esc(m.subject)}</div><div class="msg-time">${relTime(m.created_at)}</div></div>`).join(''); }
  } catch (e) { console.error('Dash messages:', e); }
  try { const a = await GET('/analytics'); renderBarChart('traffic-chart', a.daily_last7, 'var(--accent)'); } catch (e) { console.error('Dash chart:', e); }
}

// ── PROFILE ───────────────────────────────────────────────────────────────────
let profileId = null;

async function loadProfile() {
  try {
    const p = await GET('/profile');
    if (!p) return;
    profileId = p.profile_id || null;
    document.getElementById('p-id').value       = p.profile_id   || '';
    document.getElementById('p-name').value     = p.name         || '';
    document.getElementById('p-title').value    = p.title        || '';
    document.getElementById('p-bio').value      = p.bio          || '';
    document.getElementById('p-email').value    = p.email        || '';
    document.getElementById('p-resume').value   = p.resume_link  || '';
    document.getElementById('p-github').value   = p.github_url   || '';
    document.getElementById('p-linkedin').value = p.linkedin_url || '';
    document.getElementById('p-twitter').value  = p.twitter_url  || '';
  } catch (e) { toast('Could not load profile', 'error'); }
}

window.saveProfile = async function () {
  const id = document.getElementById('p-id').value;
  const fileInput = document.getElementById('p-image');
  let imageUrl = '';
  if (fileInput && fileInput.files && fileInput.files.length > 0) {
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    try {
      const res = await fetch(`${API}/upload-profile`, { method: 'POST', credentials: 'include', body: formData });
      imageUrl = (await res.json()).url || '';
    } catch { toast('Image upload failed', 'error'); return; }
  }
  const body = {
    name: document.getElementById('p-name').value.trim(), title: document.getElementById('p-title').value.trim(),
    bio: document.getElementById('p-bio').value.trim(), email: document.getElementById('p-email').value.trim(),
    resume_link: document.getElementById('p-resume').value.trim(), github_url: document.getElementById('p-github').value.trim(),
    linkedin_url: document.getElementById('p-linkedin').value.trim(), twitter_url: document.getElementById('p-twitter').value.trim(),
  };
  if (imageUrl) body.profile_image = imageUrl;
  try {
    if (id) { await PUT(`/profile/${id}`, body); }
    else { const res = await POST('/profile', body); document.getElementById('p-id').value = res.profile_id || ''; }
    toast('Profile saved ✓');
  } catch (e) { toast(e.message || 'Profile save failed', 'error'); }
};

// ── PROJECTS ──────────────────────────────────────────────────────────────────
let projects = [];

async function loadProjects() {
  try { projects = await GET('/project'); document.getElementById('project-count').textContent = projects.length; renderProjects(); }
  catch (e) { toast('Could not load projects.', 'error'); }
}

function renderProjects() {
  const grid = document.getElementById('projects-grid');
  if (!projects.length) { grid.innerHTML = '<div class="empty" style="grid-column:1/-1">No projects yet. Add your first one!</div>'; return; }
  grid.innerHTML = projects.map(p => `
    <div class="item-card">
      ${p.image ? `<div class="item-thumb"><img src="${p.image}" alt="${esc(p.title)}" style="width:100%;height:160px;object-fit:cover;border-radius:8px;margin-bottom:10px;"></div>` : `<div style="height:160px;background:#1a1a1a;border-radius:8px;margin-bottom:10px;display:flex;align-items:center;justify-content:center;color:#777;font-size:12px;">No Image</div>`}
      ${p.featured ? `<span class="tag tag-gold" style="margin-bottom:8px;display:inline-flex">★ Featured</span>` : ''}
      <div class="item-title">${esc(p.title)}</div>
      <div class="item-meta">${p.tech_stack ? `<span style="color:var(--accent4)">${esc(p.tech_stack)}</span><br>` : ''}${p.description ? esc(p.description).slice(0,90)+(p.description.length>90?'…':'') : 'No description'}</div>
      <div class="item-actions">
        <button class="btn-sm-edit" onclick="editProject('${p.project_id}')">Edit</button>
        <button class="btn-sm-del"  onclick="delProject('${p.project_id}','${esc(p.title)}')">Delete</button>
      </div>
    </div>`).join('');
}

function openProjectModal(id) {
  const p = id ? projects.find(x => x.project_id === id) : null;
  document.getElementById('project-modal-title').textContent = p ? 'Edit Project' : 'Add Project';
  document.getElementById('pm-id').value = p?.project_id||''; document.getElementById('pm-title').value = p?.title||'';
  document.getElementById('pm-desc').value = p?.description||''; document.getElementById('pm-stack').value = p?.tech_stack||'';
  document.getElementById('pm-github').value = p?.github_link||''; document.getElementById('pm-live').value = p?.live_link||'';
  document.getElementById('pm-image').value = ''; document.getElementById('pm-featured').checked = p?.featured||false;
  openModal('project-modal');
}
function editProject(id) { openProjectModal(id); }

async function saveProject() {
  const id = document.getElementById('pm-id').value;
  const title = document.getElementById('pm-title').value.trim();
  if (!title) { toast('Title is required.', 'error'); return; }
  const fd = new FormData();
  fd.append('title', title); fd.append('description', document.getElementById('pm-desc').value.trim());
  fd.append('tech_stack', document.getElementById('pm-stack').value.trim()); fd.append('github_link', document.getElementById('pm-github').value.trim());
  fd.append('live_link', document.getElementById('pm-live').value.trim()); fd.append('featured', document.getElementById('pm-featured').checked);
  const img = document.getElementById('pm-image').files[0]; if (img) fd.append('image', img);
  try {
    const res = await fetch(id ? `${API}/project/${id}` : `${API}/project`, { method: id?'PUT':'POST', credentials:'include', body:fd });
    const data = await res.json().catch(()=>({}));
    if (!res.ok) throw new Error(data.error||`HTTP ${res.status}`);
    toast(id?'Project updated ✓':'Project added ✓'); closeModal('project-modal'); loadProjects();
  } catch (e) { toast(e.message||'Project save failed','error'); }
}

function delProject(id, name) {
  confirmDelete(`Delete project "${name}"?`, async () => {
    try { await DELETE(`/project/${id}`); toast('Project deleted'); loadProjects(); } catch(e) { toast(e.message,'error'); }
  });
}

// ── SKILLS ────────────────────────────────────────────────────────────────────
let skills = [];

async function loadSkills() {
  try { skills = await GET('/skills'); document.getElementById('skill-count').textContent = skills.length; renderSkills(); }
  catch (e) { toast('Could not load skills.', 'error'); }
}

function renderSkills() {
  const tbody = document.getElementById('skills-tbody');
  if (!skills.length) { tbody.innerHTML = '<tr><td colspan="5" class="empty">No skills yet.</td></tr>'; return; }
  tbody.innerHTML = skills.map(s => `<tr>
    <td>${esc(s.skill_name)}</td>
    <td><span class="tag tag-purple">${esc(s.category||'General')}</span></td>
    <td><span class="tag ${levelTag(s.skill_level)}">${s.skill_level}</span></td>
    <td><div class="mini-bar"><div class="mini-fill" style="width:${LEVEL_PCT[s.skill_level]||60}%"></div></div></td>
    <td><div style="display:flex;gap:6px"><button class="btn-sm-edit" onclick="editSkill('${s.skill_id}')">Edit</button><button class="btn-sm-del" onclick="delSkill('${s.skill_id}','${esc(s.skill_name)}')">Delete</button></div></td>
  </tr>`).join('');
}

function levelTag(l) { return {Beginner:'tag-gold',Intermediate:'tag-purple',Advanced:'tag-green',Expert:'tag-green'}[l]||'tag-purple'; }

function openSkillModal(id) {
  const s = id ? skills.find(x => x.skill_id === id) : null;
  document.getElementById('skill-modal-title').textContent = s ? 'Edit Skill' : 'Add Skill';
  document.getElementById('sm-id').value = s?.skill_id||''; document.getElementById('sm-name').value = s?.skill_name||'';
  document.getElementById('sm-cat').value = s?.category||''; document.getElementById('sm-level').value = s?.skill_level||'Advanced';
  openModal('skill-modal');
}
function editSkill(id) { openSkillModal(id); }

async function saveSkill() {
  const id = document.getElementById('sm-id').value;
  const body = { skill_name: document.getElementById('sm-name').value.trim(), category: document.getElementById('sm-cat').value.trim()||'General', skill_level: document.getElementById('sm-level').value };
  if (!body.skill_name) { toast('Skill name is required.','error'); return; }
  try {
    if (id) { await PUT(`/skills/${id}`, body); toast('Skill updated ✓'); } else { await POST('/skills', body); toast('Skill added ✓'); }
    closeModal('skill-modal'); loadSkills();
  } catch(e) { toast(e.message,'error'); }
}

function delSkill(id, name) {
  confirmDelete(`Delete skill "${name}"?`, async () => {
    try { await DELETE(`/skills/${id}`); toast('Skill deleted'); loadSkills(); } catch(e) { toast(e.message,'error'); }
  });
}

// ── EXPERIENCE ────────────────────────────────────────────────────────────────
let experience = [];

async function loadExperience() {
  try { experience = await GET('/experience'); document.getElementById('exp-count').textContent = experience.length; renderExperience(); }
  catch (e) { toast('Could not load experience.','error'); }
}

function renderExperience() {
  const grid = document.getElementById('experience-grid');
  if (!experience.length) { grid.innerHTML = '<div class="empty" style="grid-column:1/-1">No experience yet.</div>'; return; }
  grid.innerHTML = experience.map(e => `
    <div class="item-card">
      <span class="tag ${!e.end_date?'tag-green':'tag-gold'}" style="margin-bottom:8px;display:inline-flex">${!e.end_date?'Current':'Past'}</span>
      <div class="item-title">${esc(e.role)}</div>
      <div class="item-meta">@ ${esc(e.company_name)}${e.location?` · ${esc(e.location)}`:''}<br>${fmtDate(e.start_date)} — ${e.end_date?fmtDate(e.end_date):'Present'}<br>${e.description?esc(e.description).slice(0,80)+(e.description.length>80?'…':''):''}</div>
      <div class="item-actions"><button class="btn-sm-edit" onclick="editExp('${e.experience_id}')">Edit</button><button class="btn-sm-del" onclick="delExp('${e.experience_id}','${esc(e.role)}')">Delete</button></div>
    </div>`).join('');
}

function openExpModal(id) {
  const e = id ? experience.find(x => x.experience_id === id) : null;
  document.getElementById('exp-modal-title').textContent = e ? 'Edit Experience' : 'Add Experience';
  document.getElementById('em-id').value = e?.experience_id||''; document.getElementById('em-company').value = e?.company_name||'';
  document.getElementById('em-role').value = e?.role||''; document.getElementById('em-start').value = e?.start_date||'';
  document.getElementById('em-end').value = e?.end_date||''; document.getElementById('em-location').value = e?.location||'';
  document.getElementById('em-desc').value = e?.description||''; openModal('exp-modal');
}
function editExp(id) { openExpModal(id); }

async function saveExperience() {
  const id = document.getElementById('em-id').value;
  const body = { company_name: document.getElementById('em-company').value.trim(), role: document.getElementById('em-role').value.trim(), start_date: document.getElementById('em-start').value||null, end_date: document.getElementById('em-end').value||null, location: document.getElementById('em-location').value.trim(), description: document.getElementById('em-desc').value.trim() };
  if (!body.company_name || !body.role) { toast('Company and Role are required.','error'); return; }
  try {
    if (id) { await PUT(`/experience/${id}`, body); toast('Experience updated ✓'); } else { await POST('/experience', body); toast('Experience added ✓'); }
    closeModal('exp-modal'); loadExperience();
  } catch(e) { toast(e.message,'error'); }
}

function delExp(id, name) {
  confirmDelete(`Delete experience "${name}"?`, async () => {
    try { await DELETE(`/experience/${id}`); toast('Deleted'); loadExperience(); } catch(e) { toast(e.message,'error'); }
  });
}

// ── EDUCATION ─────────────────────────────────────────────────────────────────
let education = [];

async function loadEducation() {
  try { education = await GET('/education'); document.getElementById('edu-count').textContent = education.length; renderEducation(); }
  catch (e) { toast('Could not load education.','error'); }
}

function renderEducation() {
  const grid = document.getElementById('education-grid');
  if (!education.length) { grid.innerHTML = '<div class="empty" style="grid-column:1/-1">No education yet.</div>'; return; }
  grid.innerHTML = education.map(e => `
    <div class="item-card">
      <div class="item-title">${esc(e.degree)}${e.field?` in ${esc(e.field)}`:''}</div>
      <div class="item-meta">${esc(e.institution)}<br>${e.start_year||''} — ${e.end_year||'Present'}${e.gpa?`<br>GPA: ${esc(e.gpa)}`:''}</div>
      <div class="item-actions"><button class="btn-sm-edit" onclick="editEdu('${e.education_id}')">Edit</button><button class="btn-sm-del" onclick="delEdu('${e.education_id}','${esc(e.degree)}')">Delete</button></div>
    </div>`).join('');
}

function openEduModal(id) {
  const e = id ? education.find(x => x.education_id === id) : null;
  document.getElementById('edu-modal-title').textContent = e ? 'Edit Education' : 'Add Education';
  document.getElementById('edm-id').value = e?.education_id||''; document.getElementById('edm-institution').value = e?.institution||'';
  document.getElementById('edm-degree').value = e?.degree||''; document.getElementById('edm-field').value = e?.field||'';
  document.getElementById('edm-start').value = e?.start_year||''; document.getElementById('edm-end').value = e?.end_year||'';
  document.getElementById('edm-gpa').value = e?.gpa||''; document.getElementById('edm-desc').value = e?.description||'';
  openModal('edu-modal');
}
function editEdu(id) { openEduModal(id); }

async function saveEducation() {
  const id = document.getElementById('edm-id').value;
  const body = { institution: document.getElementById('edm-institution').value.trim(), degree: document.getElementById('edm-degree').value.trim(), field: document.getElementById('edm-field').value.trim(), start_year: Number(document.getElementById('edm-start').value)||null, end_year: Number(document.getElementById('edm-end').value)||null, gpa: document.getElementById('edm-gpa').value.trim(), description: document.getElementById('edm-desc').value.trim() };
  if (!body.institution || !body.degree) { toast('Institution and Degree are required.','error'); return; }
  try {
    if (id) { await PUT(`/education/${id}`, body); toast('Education updated ✓'); } else { await POST('/education', body); toast('Education added ✓'); }
    closeModal('edu-modal'); loadEducation();
  } catch(e) { toast(e.message,'error'); }
}

function delEdu(id, name) {
  confirmDelete(`Delete "${name}"?`, async () => {
    try { await DELETE(`/education/${id}`); toast('Deleted'); loadEducation(); } catch(e) { toast(e.message,'error'); }
  });
}

// ── MESSAGES ──────────────────────────────────────────────────────────────────
async function loadMessages() {
  try {
    const msgs = await GET('/contact');
    const unread = msgs.filter(m => !m.read_status).length;
    const badge = document.getElementById('unread-badge'); badge.textContent = `${unread} unread`; badge.style.display = unread>0?'inline':'none';
    const navBadge = document.getElementById('msg-badge'); navBadge.textContent = unread; navBadge.style.display = unread>0?'inline':'none';
    const tbody = document.getElementById('messages-tbody');
    if (!msgs.length) { tbody.innerHTML = '<tr><td colspan="7" class="empty">No messages yet.</td></tr>'; return; }
    tbody.innerHTML = msgs.map(m => `<tr>
      <td style="color:${m.read_status?'var(--border)':'var(--accent2)'}">${m.read_status?'○':'●'}</td>
      <td>${esc(m.name)}</td><td style="color:var(--muted)">${esc(m.email)}</td><td>${esc(m.subject)}</td>
      <td style="color:var(--muted)">${fmtDateTime(m.created_at)}</td>
      <td><span class="tag ${m.read_status?'tag-green':'tag-red'}">${m.read_status?'Read':'Unread'}</span></td>
      <td><div style="display:flex;gap:6px">${!m.read_status?`<button class="btn-sm-read" onclick="markRead('${m.message_id}')">Mark Read</button>`:''}<button class="btn-sm-del" onclick="delMsg('${m.message_id}')">Delete</button></div></td>
    </tr>`).join('');
  } catch(e) { toast('Could not load messages.','error'); }
}

async function markRead(id) {
  try { await PUT(`/contact/${id}/read`); toast('Marked as read ✓'); loadMessages(); } catch(e) { toast(e.message,'error'); }
}

function delMsg(id) {
  confirmDelete('Delete this message permanently?', async () => {
    try { await DELETE(`/contact/${id}`); toast('Message deleted'); loadMessages(); } catch(e) { toast(e.message,'error'); }
  });
}

// ── ANALYTICS ─────────────────────────────────────────────────────────────────
async function loadAnalytics() {
  try {
    const a = await GET('/analytics');
    document.getElementById('a-total').textContent  = a.total  ?? '—';
    document.getElementById('a-unique').textContent = a.unique ?? '—';
    renderBarChart('analytics-chart', a.daily_last7, 'var(--accent)');
    renderTopPages(a.by_page);
  } catch(e) { toast('Could not load analytics.','error'); }
}

function renderBarChart(containerId, daily, color) {
  const el = document.getElementById(containerId);
  if (!el || !daily) return;
  const entries = Object.entries(daily);
  const max = Math.max(...entries.map(([,v])=>v), 1);
  el.innerHTML = entries.map(([date, count]) => {
    const pct = Math.max((count/max)*100, 4);
    return `<div class="bar-group"><div class="bar-col" style="height:${pct}%;background:${color};opacity:${count===max?'1':'0.5'}"><div class="bar-tip">${count}</div></div><div class="bar-lbl">${DAYS_ABBR[new Date(date).getDay()]}</div></div>`;
  }).join('');
}

function renderTopPages(byPage) {
  const el = document.getElementById('top-pages');
  if (!el) return;
  const entries = Object.entries(byPage).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const max = entries[0]?.[1]||1;
  el.innerHTML = entries.map(([page,count]) => `<div class="page-row"><div class="page-name">${esc(page)}</div><div class="page-bar-wrap"><div class="page-bar" style="width:${(count/max)*100}%"></div></div><div class="page-count">${count}</div></div>`).join('');
}

// ── Utilities ─────────────────────────────────────────────────────────────────
function esc(s) { if (!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function fmtDate(d) { if (!d) return ''; return new Date(d).toLocaleDateString('en-US',{month:'short',year:'numeric'}); }
function fmtDateTime(d) { if (!d) return ''; return new Date(d).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}); }
function relTime(d) {
  if (!d) return '';
  const diff = Date.now() - new Date(d).getTime();
  const h = Math.floor(diff/36e5);
  if (h<1) return 'just now'; if (h<24) return `${h}h ago`;
  const days = Math.floor(h/24);
  if (days<7) return `${days}d ago`; if (days<30) return `${Math.floor(days/7)}w ago`;
  return fmtDate(d);
}

// ── Init ──────────────────────────────────────────────────────────────────────
(async function init() {
  const authed = await checkAuth();
  if (authed) showPage('dashboard');
})();