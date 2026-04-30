/**
 * BunkMath — server.js
 * Login via direct EduPlus API (no reCAPTCHA on API layer)
 * Attendance fetched with saved session headers
 */

import express       from 'express';
import cors          from 'cors';
import rateLimit     from 'express-rate-limit';
import { GoogleGenAI } from '@google/genai';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { config }    from 'dotenv';
import path          from 'path';
import { fileURLToPath } from 'url';
import crypto        from 'crypto';

config();

const __dirname  = path.dirname(fileURLToPath(import.meta.url));
const app        = express();
const PORT       = process.env.PORT || 3000;
const GEMINI_KEY = process.env.GEMINI_API_KEY || '';

// EduPlus API base — the actual API server (not the learner UI)
const ERP_API = 'https://learnerapi.pceterp.in';
const ERP_UI  = 'https://learner.pceterp.in';

// ─────────────────────────────────────────────────────────
// DATA DIR
// ─────────────────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, '.data');
if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

// ─────────────────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/', rateLimit({ windowMs: 60_000, max: 40, standardHeaders: true, legacyHeaders: false }));

// ─────────────────────────────────────────────────────────
// FILE HELPERS
// ─────────────────────────────────────────────────────────
function uid(username) {
  return crypto.createHash('sha256').update(username.trim().toLowerCase()).digest('hex').slice(0, 16);
}
const fp = {
  session:    id => path.join(DATA_DIR, `sess_${id}.json`),
  attendance: id => path.join(DATA_DIR, `att_${id}.json`),
  timetable:  id => path.join(DATA_DIR, `tt_${id}.json`),
};
function readJSON(p, fb=null){ try{ return existsSync(p)?JSON.parse(readFileSync(p,'utf8')):fb; }catch{ return fb; } }
function writeJSON(p,data){ try{ writeFileSync(p,JSON.stringify(data,null,2)); }catch(e){ console.error('[writeJSON]',e.message); } }

// ─────────────────────────────────────────────────────────
// EDUPLUS LOGIN — direct API, bypasses reCAPTCHA
// The portal's reCAPTCHA is only on the UI layer.
// The underlying API accepts credentials directly.
// ─────────────────────────────────────────────────────────
async function erpLogin(username, password) {
  console.log(`[Login] Attempting for ${username.slice(0,10)}...`);

  // Step 1: POST to the EduPlus login API
  const loginRes = await fetch(`${ERP_API}/appUserDetail/NewsignIn`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json, text/plain, */*',
      'Origin': ERP_UI,
      'Referer': ERP_UI + '/',
      'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36',
    },
    body: JSON.stringify({ username, password }),
  });

  const loginData = await loginRes.json().catch(() => null);
  console.log(`[Login] Response status: ${loginRes.status}, msg: ${loginData?.msg}`);

  if (!loginData) throw new Error('No response from login API');

  // Check success — EduPlus returns msg:"200" or status 200
  const ok = loginData.msg === '200' || loginData.statusCode === 200 || loginData.status === '200' || loginRes.status === 200;
  if (!ok) {
    throw new Error(loginData.message || loginData.msg || 'Invalid username or password');
  }

  // Extract the encrypted auth headers from response
  // EduPlus returns encrypted user identifiers used in subsequent API calls
  const d = loginData.data || loginData;

  const headers = {
    'eps-learnerid': d.encLearnerId || d.learnerId || d.eps_learnerid || '',
    'eps-loginid':   d.encLoginId   || d.loginId   || d.eps_loginid   || '',
    'eps-orgid':     d.encOrgId     || d.orgId      || d.eps_orgid     || '',
    'eps-uid':       d.encUid       || d.uid        || d.eps_uid       || '',
    'data':          d.encData      || d.data       || d.token         || '',
  };

  // Validate we got something
  const hasHeaders = Object.values(headers).some(v => v && v.length > 0);
  if (!hasHeaders) {
    // Try extracting from top-level response
    headers['data']          = loginData.token || loginData.encData || loginData.data || '';
    headers['eps-learnerid'] = loginData.encLearnerId || loginData.learnerId || '';
    headers['eps-loginid']   = loginData.encLoginId   || loginData.loginId   || '';
    headers['eps-orgid']     = loginData.encOrgId     || loginData.orgId     || '';
    headers['eps-uid']       = loginData.encUid       || loginData.uid       || '';
  }

  console.log(`[Login] Got headers: ${Object.entries(headers).filter(([,v])=>v).map(([k])=>k).join(', ')}`);
  return headers;
}

// ─────────────────────────────────────────────────────────
// FETCH ATTENDANCE using saved headers
// ─────────────────────────────────────────────────────────
async function fetchAttendance(headers, ay='2025-26', sem='2') {
  console.log(`[Attendance] Fetching ay=${ay} sem=${sem}`);

  const res = await fetch(`${ERP_API}/appLearnerAcademics/learnerAttendence?ay=${ay}&sem=${sem}`, {
    method: 'POST',
    headers: {
      'Accept': 'application/json, text/plain, */*',
      'Content-Type': 'application/json',
      'Origin': ERP_UI,
      'Referer': ERP_UI + '/',
      'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36',
      'cache-control': 'no-cache',
      'pragma': 'no-cache',
      ...headers,
    },
  });

  if (res.status === 401) throw new Error('SESSION_EXPIRED');

  const j = await res.json().catch(() => null);
  if (!j) throw new Error('Empty attendance response');
  if (j.msg === '401' || j.statusCode === 401) throw new Error('SESSION_EXPIRED');
  if (!j.learnerarray?.[0]?.subarray) throw new Error('Unexpected attendance format');

  console.log(`[Attendance] Got ${j.learnerarray[0].subarray.length} entries`);
  return j;
}

// ─────────────────────────────────────────────────────────
// TRANSFORM raw portal JSON → clean subjects
// ─────────────────────────────────────────────────────────
function transform(raw) {
  const subarray = raw.learnerarray[0].subarray;
  const crsList  = raw.crs_list || [];

  const subjects = subarray.map((entry, idx) => {
    const bid  = entry.courseofferingbatch.id;
    const info = crsList.find(c => c.batch_id === bid) || {};
    return {
      name:        info.course_name  || `Subject ${idx + 1}`,
      code:        info.course_code  || '',
      type:        info.load_type    || 'Theory',
      batchNumber: info.batch_number || '-1',
      attended:    entry.lectureattended,
      total:       entry.lecturetotal,
      percentage:  entry.totalPrecentPer,
      instructor:  (info.instructor_name || '').replace(/^\d+\s*\/\s*/, ''),
    };
  });

  return {
    subjects,
    overall:  raw.overall_percentage || 0,
    learner:  raw.learner            || {},
    ay:       raw.ay                 || '2025-26',
    sem:      raw.sem                || '2',
  };
}

// ─────────────────────────────────────────────────────────
// GEMINI — parse timetable image
// ─────────────────────────────────────────────────────────
async function parseWithGemini(b64, mime) {
  if (!GEMINI_KEY) throw new Error('GEMINI_API_KEY not configured on server');
  const ai = new GoogleGenAI({ apiKey: GEMINI_KEY });

  const prompt = `Analyze this college timetable image and extract the complete weekly schedule.
Return ONLY valid JSON, no markdown fences, no explanation:
{
  "division": "H",
  "batches": ["1","2","3"],
  "schedule": {
    "Mon": [
      { "slot": "Pre-Lunch", "subject": "subject name", "room": "room", "batches": [], "type": "Theory", "academic": true }
    ],
    "Tue": [], "Wed": [], "Thu": [], "Fri": [], "Sat": []
  }
}
Rules:
- slot must be exactly: "Pre-Lunch", "Post-Lunch", or "Short Break"
- batches: [] means all batches. ["1"] means batch 1 only, ["2"] batch 2 only etc
- type: "Theory", "Lab", or "Tutorial"
- academic: false for Sports, Events, Mentor Meeting
- Create separate entries for each batch sub-row
- Include every visible row`;

  const result = await ai.models.generateContent({
    model: 'gemini-2.0-flash-lite',
    contents: [{ parts: [{ text: prompt }, { inlineData: { mimeType: mime, data: b64 } }] }],
    generationConfig: { temperature: 0.1, maxOutputTokens: 4096 },
  });

  let text = result.candidates[0].content.parts[0].text.trim();
  text = text.replace(/^```(?:json)?\n?/i,'').replace(/\n?```\s*$/i,'').trim();
  try { return JSON.parse(text); }
  catch {
    const m = text.match(/\{[\s\S]*\}/);
    if (m) return JSON.parse(m[0]);
    throw new Error('Gemini returned invalid JSON');
  }
}

// ─────────────────────────────────────────────────────────
// API ROUTES
// ─────────────────────────────────────────────────────────
app.get('/api/health', (_, res) => res.json({ ok: true, version: '3.0.0', gemini: !!GEMINI_KEY }));

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ ok: false, error: 'Username and password required' });

  const id    = uid(username);
  const cache = readJSON(fp.attendance(id));

  // Return cache if fresh (< 4 hours)
  if (cache?.lastSync) {
    const age = Date.now() - new Date(cache.lastSync).getTime();
    if (age < 4 * 3600 * 1000) {
      console.log(`[Login] Cache hit for ${username.slice(0,8)}`);
      return res.json({ ok: true, data: cache.data, lastSync: cache.lastSync, fromCache: true });
    }
  }

  try {
    const headers = await erpLogin(username, password);
    writeJSON(fp.session(id), { username, headers, savedAt: new Date().toISOString() });

    const raw  = await fetchAttendance(headers);
    const data = transform(raw);
    const lastSync = new Date().toISOString();

    writeJSON(fp.attendance(id), { data, lastSync });
    return res.json({ ok: true, data, lastSync });

  } catch(e) {
    console.error('[Login error]', e.message);
    // If we have cache, return it with error
    if (cache) return res.json({ ok: true, data: cache.data, lastSync: cache.lastSync, fromCache: true, warning: e.message });
    return res.status(401).json({ ok: false, error: e.message });
  }
});

// POST /api/sync — force fresh fetch
app.post('/api/sync', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ ok: false, error: 'Username and password required' });

  const id = uid(username);
  try {
    // Try reusing saved session first
    const saved = readJSON(fp.session(id));
    let headers = saved?.headers;

    if (!headers) {
      headers = await erpLogin(username, password);
      writeJSON(fp.session(id), { username, headers, savedAt: new Date().toISOString() });
    }

    let raw;
    try {
      raw = await fetchAttendance(headers);
    } catch(e) {
      if (e.message === 'SESSION_EXPIRED') {
        // Re-login
        headers = await erpLogin(username, password);
        writeJSON(fp.session(id), { username, headers, savedAt: new Date().toISOString() });
        raw = await fetchAttendance(headers);
      } else throw e;
    }

    const data     = transform(raw);
    const lastSync = new Date().toISOString();
    writeJSON(fp.attendance(id), { data, lastSync });
    return res.json({ ok: true, data, lastSync });

  } catch(e) {
    console.error('[Sync error]', e.message);
    const cache = readJSON(fp.attendance(id));
    if (cache) return res.json({ ok: true, data: cache.data, lastSync: cache.lastSync, fromCache: true, error: e.message });
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// POST /api/parse-timetable
app.post('/api/parse-timetable', async (req, res) => {
  const { image, mimeType, username } = req.body;
  if (!image) return res.status(400).json({ ok: false, error: 'No image provided' });
  try {
    const tt = await parseWithGemini(image, mimeType || 'image/jpeg');
    if (username) {
      const id = uid(username);
      const cache = readJSON(fp.timetable(id)) || {};
      writeJSON(fp.timetable(id), { ...cache, timetable: tt, generatedAt: new Date().toISOString() });
    }
    return res.json({ ok: true, timetable: tt });
  } catch(e) {
    console.error('[Gemini error]', e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// GET /api/timetable
app.get('/api/timetable', (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ ok: false, error: 'username required' });
  const cache = readJSON(fp.timetable(uid(username)));
  if (cache?.timetable) return res.json({ ok: true, timetable: cache.timetable, generatedAt: cache.generatedAt });
  return res.status(404).json({ ok: false, error: 'No timetable found. Upload one first.' });
});

// ─────────────────────────────────────────────────────────
// START
// ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🎓 BunkMath v3 on :${PORT}`);
  console.log(`   Gemini : ${GEMINI_KEY ? '✓' : '✗ (timetable upload disabled)'}`);
  console.log(`   Data   : ${DATA_DIR}\n`);
});
