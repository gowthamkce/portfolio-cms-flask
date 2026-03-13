const API_BASE = "https://portfolio-cms-flask.onrender.com";
const API = API_BASE + "/api";

const LEVELS = { Beginner:28, Intermediate:58, Advanced:80, Expert:96 };
// ── Generic fetch ─────────────────────────────────────────────────────────────
async function api(path) {
  const r = await fetch(API + path);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ── Profile ───────────────────────────────────────────────────────────────────
async function loadProfile() {
  try {
    const p = await api('/profile');
    if (!p || !p.name) return;
    document.title = `${p.name} · Portfolio`;
    const first = p.name.split(' ')[0];
    document.getElementById('nav-logo').textContent    = `⬡ ${first}`;
    document.getElementById('footer-logo').textContent = `⬡ ${p.name}`;
    document.getElementById('hero-name').textContent   = p.name;
    document.getElementById('hero-role').textContent   = p.title || '';
    document.getElementById('hero-bio').textContent    = p.bio   || '';
    document.getElementById('about-text').innerHTML    = `<p>${(p.bio||'').replace(/\n/g,'</p><p>')}</p>`;
    if (p.resume_link) document.getElementById('resume-btn').href = p.resume_link;
    if (p.profile_image) {
      document.getElementById('about-img').innerHTML = `<img src="${p.profile_image}" alt="${p.name}" />`;
    }
    const links = [];
    if (p.github_url)   links.push({href:p.github_url,        label:'GitHub'});
    if (p.linkedin_url) links.push({href:p.linkedin_url,      label:'LinkedIn'});
    if (p.twitter_url)  links.push({href:p.twitter_url,       label:'Twitter'});
    if (p.email)        links.push({href:`mailto:${p.email}`, label:p.email});
    document.getElementById('about-links').innerHTML =
      links.map(l => `<a class="social-link" href="${l.href}" target="_blank">↗ ${l.label}</a>`).join('');
    const cd = [];
    if (p.email)        cd.push(`<a class="contact-item" href="mailto:${p.email}">✉ ${p.email}</a>`);
    if (p.github_url)   cd.push(`<a class="contact-item" href="${p.github_url}" target="_blank">⬡ GitHub</a>`);
    if (p.linkedin_url) cd.push(`<a class="contact-item" href="${p.linkedin_url}" target="_blank">in LinkedIn</a>`);
    document.getElementById('contact-details').innerHTML = cd.join('');
  } catch(e) {
    document.getElementById('hero-name').textContent = 'Developer';
    document.getElementById('hero-role').textContent = 'Full Stack Developer';
    document.getElementById('about-text').innerHTML  = '<p>Welcome to my portfolio.</p>';
  }
}

// ── Skills ────────────────────────────────────────────────────────────────────
async function loadSkills() {
  const grid = document.getElementById('skills-grid');
  try {
    const skills = await api('/skills');
    if (!skills.length) { grid.innerHTML = '<p style="color:var(--muted);font-size:12px">No skills added yet.</p>'; return; }
    grid.innerHTML = skills.map(s => `
      <div class="skill-card">
        <div class="skill-top">
          <div class="skill-name">${s.skill_name}</div>
          ${s.category ? `<div class="skill-cat">${s.category}</div>` : ''}
        </div>
        <div class="skill-level-label">${s.skill_level}</div>
        <div class="skill-bar"><div class="skill-fill" data-pct="${LEVELS[s.skill_level]||60}" style="width:0%"></div></div>
      </div>`).join('');
    setTimeout(() => {
      document.querySelectorAll('.skill-fill').forEach(el => { el.style.width = el.dataset.pct + '%'; });
    }, 300);
  } catch(e) { grid.innerHTML = '<p style="color:var(--muted);font-size:12px">Could not load skills.</p>'; }
}

// ── Experience ────────────────────────────────────────────────────────────────
async function loadExperience() {
  const tl = document.getElementById('timeline');
  try {
    const jobs = await api('/experience');
    if (!jobs.length) { tl.innerHTML = '<p style="color:var(--muted);font-size:12px">No experience added yet.</p>'; return; }
    tl.innerHTML = jobs.map(j => `
      <div class="timeline-item">
        <div class="tl-date">${fmt(j.start_date)} — ${j.end_date ? fmt(j.end_date) : 'Present'}</div>
        <div class="tl-role">${j.role}</div>
        <div class="tl-company">@ ${j.company_name}${j.location ? ` · ${j.location}` : ''}</div>
        <div class="tl-desc">${j.description || ''}</div>
      </div>`).join('');
    const earliest = jobs.map(j => new Date(j.start_date).getFullYear()).sort()[0];
    document.getElementById('exp-years').textContent = (new Date().getFullYear() - earliest) + '+';
  } catch(e) { tl.innerHTML = '<p style="color:var(--muted);font-size:12px">Could not load experience.</p>'; }
}

// ── Projects ──────────────────────────────────────────────────────────────────
async function loadProjects() {
  const grid = document.getElementById('projects-grid');
  const EMOJIS = ['🖥️','📊','🤖','💬','🛒','🗺️','🎮','🔒','📱','🌐','⚡','🧠'];
  try {
    const projects = await api('/project');
    if (!projects.length) { grid.innerHTML = '<p style="color:var(--muted);font-size:12px">No projects yet.</p>'; return; }
    grid.innerHTML = projects.map((p,i) => {
      const stacks = (p.tech_stack||'').split(',').filter(Boolean).map(s => `<span class="stack-tag">${s.trim()}</span>`).join('');
      return `
      <div class="project-card">
        <div class="project-thumb">
          ${p.image ? `<img src="${p.image}" alt="${p.title}" />` : EMOJIS[i%EMOJIS.length]}
          <div class="project-thumb-overlay"></div>
        </div>
        <div class="project-body">
          <div class="project-title">${p.title}</div>
          <div class="project-desc">${p.description||''}</div>
          <div class="project-stack">${stacks}</div>
          <div class="project-links">
            ${p.github_link ? `<a href="${p.github_link}" target="_blank" class="proj-link">⬡ GitHub</a>` : ''}
            ${p.live_link   ? `<a href="${p.live_link}"   target="_blank" class="proj-link">↗ Live Demo</a>` : ''}
          </div>
        </div>
      </div>`;
    }).join('');
  } catch(e) { grid.innerHTML = '<p style="color:var(--muted);font-size:12px">Could not load projects.</p>'; }
}

// ── Contact form ──────────────────────────────────────────────────────────────
async function sendMessage() {
  const btn    = document.getElementById('send-btn');
  const status = document.getElementById('form-status');
  const body   = {
    name:    document.getElementById('c-name').value.trim(),
    email:   document.getElementById('c-email').value.trim(),
    subject: document.getElementById('c-subject').value.trim(),
    message: document.getElementById('c-message').value.trim(),
  };
  if (Object.values(body).some(v => !v)) {
    status.textContent = 'Please fill in all fields.';
    status.className = 'form-status error';
    return;
  }
  btn.textContent = 'Sending...';
  btn.disabled = true;
  try {
    const r = await fetch(API + '/contact', {
      method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body),
    });
    if (!r.ok) throw new Error();
    status.textContent = "✓ Message sent! I'll get back to you within 24 hours.";
    status.className = 'form-status success';
    ['c-name','c-email','c-subject','c-message'].forEach(id => document.getElementById(id).value='');
  } catch {
    status.textContent = 'Something went wrong. Please try again or email me directly.';
    status.className = 'form-status error';
  } finally {
    btn.textContent = 'Send Message →';
    btn.disabled = false;
  }
}

// ── Login modal ───────────────────────────────────────────────────────────────
function openModal() {
  document.getElementById('login-overlay').classList.add('open');
  document.getElementById('modal-err').style.display = 'none';
  document.getElementById('m-email').value = '';
  document.getElementById('m-pass').value  = '';
  setTimeout(() => document.getElementById('m-email').focus(), 120);
}
function closeModal() { document.getElementById('login-overlay').classList.remove('open'); }
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

async function doLogin() {
  const btn   = document.getElementById('login-btn');
  const errEl = document.getElementById('modal-err');
  const email = document.getElementById('m-email').value.trim();
  const pass  = document.getElementById('m-pass').value;

  errEl.style.display = 'none';
  if (!email || !pass) {
    errEl.textContent = 'Please enter your email and password.';
    errEl.style.display = 'block';
    return;
  }
  btn.classList.add('loading');
  btn.disabled = true;
  try {
    const r = await fetch(API + '/auth/login', {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ email, password: pass }),
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Login failed');

    btn.querySelector('.btn-lbl').textContent = 'Opening Admin…';

    // ✅ FIX: Open admin panel in new tab to avoid cross-domain cookie loss
    setTimeout(() => {
      window.open(API_BASE + '/admin', '_blank');
      closeModal();
      btn.classList.remove('loading');
      btn.disabled = false;
      btn.querySelector('.btn-lbl').textContent = 'Sign In → Admin Panel';
    }, 500);

  } catch(e) {
    errEl.textContent = e.message || 'Invalid credentials. Please try again.';
    errEl.style.display = 'block';
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

// ── Navbar scroll ─────────────────────────────────────────────────────────────
window.addEventListener('scroll', () => {
  document.getElementById('navbar').classList.toggle('scrolled', window.scrollY > 50);
});

// ── Utils ─────────────────────────────────────────────────────────────────────
function fmt(dateStr) {
  if (!dateStr) return '';
  return new Date(dateStr).toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.getElementById('footer-year').textContent = new Date().getFullYear();
Promise.all([loadProfile(), loadSkills(), loadExperience(), loadProjects()]);