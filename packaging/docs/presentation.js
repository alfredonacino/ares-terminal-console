#!/usr/bin/env node
/*
 * Builds the ARES Terminal Console executive presentation as a PowerPoint file.
 *
 *   node packaging/docs/presentation.js [out.pptx]
 *       default: dist/docs/ares-terminal-console-executive-presentation.pptx
 *
 * The same twelve slides as docs/executive-presentation.html. Speaker notes are
 * read from docs/EXECUTIVE-PRESENTATION.md ("**Speaker notes.**" under each
 * "## Slide N"), so the notes have one source. Run by packaging/build-docs.sh;
 * needs `npm ci` in packaging/docs (pptxgenjs).
 */
'use strict';
const fs = require('fs');
const path = require('path');
const pptxgen = require('pptxgenjs');

const ROOT = path.resolve(__dirname, '..', '..');
const BRAND = path.join(ROOT, 'app', 'static', 'brand');
const OUT = path.resolve(process.argv[2] || path.join(ROOT, 'dist', 'docs', 'ares-terminal-console-executive-presentation.pptx'));
const VERSION = (fs.readFileSync(path.join(ROOT, 'apexmodule.toml'), 'utf8').match(/^version\s*=\s*"([^"]+)"/m) || [])[1] || '';

// ── Theme ────────────────────────────────────────────────────────────────
const THEME = {
  name: 'ARES Terminal Console',
  headFontFace: 'Arial',
  bodyFontFace: 'Calibri',
  colors: {
    dk1: '070B15',      // page
    lt1: 'FFFFFF',      // strongest text
    dk2: '101A2C',      // card
    lt2: '93A6C6',      // muted text
    accent1: '22D3EE',  // cyan
    accent2: 'B14CFF',  // violet
    accent3: '2EE59D',  // live / ok
    accent4: 'FFB020',  // broadcast amber
    accent5: '23324D',  // rules and card borders
    accent6: 'EEF3FB',  // body text
    hlink: '22D3EE',
    folHlink: 'B14CFF',
  },
};
const HEX = THEME.colors;

// ── Speaker notes from the Markdown outline ──────────────────────────────
function readNotes() {
  const md = fs.readFileSync(path.join(ROOT, 'docs', 'EXECUTIVE-PRESENTATION.md'), 'utf8');
  const notes = {};
  for (const part of md.split(/^## Slide /m).slice(1)) {
    const n = parseInt(part, 10);
    const m = part.match(/\*\*Speaker notes\.\*\*\s*([\s\S]*?)(?:\n---|\s*$)/);
    if (n && m) notes[n] = m[1].replace(/\s*\n\s*/g, ' ').trim();
  }
  return notes;
}

// ── Deck ────────────────────────────────────────────────────────────────
const pres = new pptxgen();
pres.layout = 'LAYOUT_WIDE'; // 13.333 x 7.5 in
pres.title = 'ARES Terminal Console — Executive Presentation';
pres.subject = 'ARES Application Suite';
pres.author = 'Alfredo Nacino';
pres.company = 'ARES';
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;
// Scheme roles: text1=dk1 page, background1=lt1 white, text2=dk2 card, background2=lt2 muted.
const PAGE = C.text1, WHITE = C.background1, CARD = C.text2, MUTED = C.background2;
const CYAN = C.accent1, VIOLET = C.accent2, GREEN = C.accent3, AMBER = C.accent4, RULE = C.accent5, TEXT = C.accent6;

const W = 13.333, MX = 0.75;
const BG = { path: path.join(__dirname, 'slide-bg.png') };
const LOGO = path.join(BRAND, 'ares-terminal-logo-dark.png'); // 880 x 300
const ICON = path.join(BRAND, 'ares-terminal-icon-512.png');

pres.defineSlideMaster({
  title: 'ARES Title',
  background: BG,
  objects: [
    { placeholder: { options: { name: 'title', type: 'title', x: 5.1, y: 2.0, w: 7.5, h: 1.9, fontSize: 54, bold: true, color: WHITE, align: 'left', valign: 'top', margin: 0, fontFace: THEME.headFontFace }, text: '' } },
    { placeholder: { options: { name: 'body', type: 'body', x: 5.1, y: 4.0, w: 7.4, h: 1.0, fontSize: 20, color: MUTED, align: 'left', valign: 'top', margin: 0 }, text: '' } },
  ],
});
pres.defineSlideMaster({
  title: 'ARES Content',
  background: BG,
  margin: [0.5, MX, 0.6, MX],
  objects: [
    { image: { x: MX, y: 6.86, w: 1.17, h: 0.4, path: LOGO, altText: 'ARES Terminal Console' } },
    { placeholder: { options: { name: 'eyebrow', type: 'body', x: MX, y: 0.55, w: 11.8, h: 0.35, fontSize: 14, bold: true, charSpacing: 4, color: CYAN, align: 'left', margin: 0, valign: 'top' }, text: '' } },
    { placeholder: { options: { name: 'title', type: 'title', x: MX, y: 0.95, w: 11.8, h: 0.85, fontSize: 36, bold: true, color: WHITE, align: 'left', margin: 0, valign: 'top', fontFace: THEME.headFontFace }, text: '' } },
  ],
  slideNumber: { x: 12.2, y: 6.92, w: 0.5, h: 0.3, fontSize: 12, color: MUTED, align: 'right' },
});

const notes = readNotes();
let n = 0;
function content(section, eyebrow, title) {
  n += 1;
  const s = pres.addSlide({ masterName: 'ARES Content', sectionTitle: section });
  s.addText(eyebrow.toUpperCase(), { placeholder: 'eyebrow' });
  if (title) s.addText(title, { placeholder: 'title' });
  if (notes[n]) s.addNotes(notes[n]);
  return s;
}

// A card: rounded panel, optional glyph in a circle, heading, body.
function card(s, name, x, y, w, h, { glyph, glyphColor = CYAN, head, body, big, bigColor = CYAN, border = RULE, dashed = false, bodySize = 15 } = {}) {
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    objectName: `${name} card`, x, y, w, h, rectRadius: 0.14,
    fill: { color: dashed ? PAGE : CARD, transparency: dashed ? 100 : 0 },
    line: { color: border, width: 1, dashType: dashed ? 'dash' : 'solid' },
  });
  let cy = y + 0.25;
  if (glyph) {
    s.addShape(pres.shapes.OVAL, { objectName: `${name} glyph circle`, x: x + 0.25, y: cy, w: 0.56, h: 0.56, fill: { color: PAGE }, line: { color: glyphColor, width: 1.25 } });
    s.addText(glyph, { objectName: `${name} glyph`, isTextBox: true, x: x + 0.25, y: cy, w: 0.56, h: 0.56, align: 'center', valign: 'middle', fontSize: 18, color: glyphColor, fontFace: 'Segoe UI Symbol', margin: 0 });
    cy += 0.72;
  }
  if (big) {
    s.addText(big, { objectName: `${name} figure`, isTextBox: true, x: x + 0.25, y: cy, w: w - 0.5, h: 0.85, fontSize: 40, bold: true, color: bigColor, fontFace: THEME.headFontFace, margin: 0, valign: 'middle', fit: 'shrink' });
    cy += 0.95;
  }
  if (head) {
    s.addText(head, { objectName: `${name} heading`, isTextBox: true, x: x + 0.25, y: cy, w: w - 0.5, h: 0.42, fontSize: 19, bold: true, color: WHITE, margin: 0, valign: 'top' });
    cy += 0.48;
  }
  if (body) {
    s.addText(body, { objectName: `${name} text`, isTextBox: true, x: x + 0.25, y: cy, w: w - 0.5, h: y + h - cy - 0.15, fontSize: bodySize, color: MUTED, margin: 0, valign: 'top', paraSpaceAfter: 4 });
  }
}

// Bulleted list; items are arrays of [text, bold?] runs. One text box per item:
// (See applyThemeColours for why a bullet on several runs needs a clean-up.)
function bullets(s, name, items, x, y, w, h, size = 20) {
  const step = h / items.length;
  items.forEach((parts, i) => {
    const runs = parts.map(([t, b]) => ({ text: t, options: { fontSize: size, color: b ? WHITE : TEXT, bold: !!b } }));
    s.addText(runs, { objectName: `${name} ${i + 1}`, isTextBox: true, bullet: { characterCode: '25A0', indent: 24 }, x, y: y + i * step, w, h: step, valign: 'top', margin: 0 });
  });
}
function note(s, text, y = 6.2) {
  s.addText(text, { objectName: 'note', isTextBox: true, x: MX, y, w: 11.8, h: 0.45, fontSize: 15, color: MUTED, margin: 0, valign: 'top' });
}
function table(s, name, rows, y, firstW = 2.6) {
  s.addTable(rows.map(([k, v]) => [
    { text: k, options: { bold: true, color: CYAN, fontSize: 18 } },
    { text: v, options: { color: TEXT, fontSize: 18 } },
  ]), {
    objectName: name, x: MX, y, w: 11.8, colW: [firstW, 11.8 - firstW],
    border: [{ type: 'none' }, { type: 'none' }, { pt: 1, color: HEX.accent5 }, { type: 'none' }],
    fill: { color: PAGE, transparency: 100 }, margin: [0.12, 0.15, 0.12, 0.15], valign: 'top',
  });
}

// ── 1. Title ────────────────────────────────────────────────────────────
pres.addSection({ title: 'Introduction' });
{
  n += 1;
  const s = pres.addSlide({ masterName: 'ARES Title', sectionTitle: 'Introduction' });
  s.addImage({ objectName: 'product icon', path: ICON, x: 0.8, y: 1.7, w: 3.8, h: 3.8, altText: 'ARES Terminal Console icon' });
  s.addText('ARES APPLICATION SUITE', { objectName: 'eyebrow', isTextBox: true, x: 5.1, y: 1.5, w: 7, h: 0.4, fontSize: 15, bold: true, charSpacing: 4, color: CYAN, margin: 0 });
  s.addText([
    { text: 'ARES ', options: { color: WHITE } },
    { text: 'Terminal', options: { color: CYAN, breakLine: true } },
    { text: 'Console', options: { color: WHITE } },
  ], { placeholder: 'title' });
  s.addText('The terminal for the people who run our servers: it remembers, diagnoses, and never acts on its own.', { placeholder: 'body' });
  [['DESKTOP', 'Linux · macOS · Windows', GREEN, 3.75], ['DOCKER', 'ares/terminal-console', CYAN, 3.55]].forEach(([k, v, col, w], i) => {
    const x = 5.1 + (i ? 3.95 : 0);
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { objectName: `${k} chip`, x, y: 5.15, w, h: 0.5, rectRadius: 0.1, fill: { color: CARD }, line: { color: RULE, width: 1 } });
    s.addText([{ text: k + '  ', options: { bold: true, color: col } }, { text: v, options: { color: TEXT } }],
      { objectName: `${k} chip text`, isTextBox: true, x: x + 0.15, y: 5.15, w: w - 0.3, h: 0.5, fontSize: 14, valign: 'middle', margin: 0 });
  });
  s.addText(`Version ${VERSION} · 16 November 2026 · Alfredo Nacino`, { objectName: 'byline', isTextBox: true, x: 5.1, y: 5.95, w: 7, h: 0.4, fontSize: 14, color: MUTED, margin: 0 });
  if (notes[1]) s.addNotes(notes[1]);
}

// ── 2. Problem ──────────────────────────────────────────────────────────
{
  const s = content('Introduction', 'The problem', 'Server work happens in plain terminals');
  bullets(s, 'problems', [
    [['Nothing records', 1], [' what was run, or on which machine.']],
    [['Diagnosing a server means '], ['copying scripts across', 1], [' or opening other tools.']],
    [['A change on several servers is done '], ['one at a time', 1], [', or with a risky shortcut.']],
    [['AI tools that "just run it" are '], ['the wrong fit', 1], [' for production machines.']],
  ], MX, 2.15, 7.3, 4.0, 21);
  card(s, 'shell history', 8.55, 2.15, 4.0, 3.9, { big: '?', bigColor: AMBER, head: 'Last Tuesday on db1', body: 'Who ran what, from whose laptop? In a plain terminal the honest answer is shell history, if it wasn\'t cleared.', bodySize: 16 });
}

// ── 3. Solution ─────────────────────────────────────────────────────────
{
  const s = content('Introduction', 'The solution', 'One window for the whole job');
  const items = [
    ['▥', 'Panes & tabs', 'Splits like tmux, one tab per connection, broadcast when you mean it.'],
    ['⌘', 'The record', 'Every connection and command, with time, pane and server.'],
    ['◈', 'Server tools', 'Seven read-only diagnostics on any SSH pane.'],
    ['✦', 'Assistant', 'Suggests the command. A person presses Enter.'],
  ];
  const cw = (11.8 - 3 * 0.3) / 4;
  items.forEach(([g, h, b], i) => card(s, h, MX + i * (cw + 0.3), 2.15, cw, 3.4, { glyph: g, glyphColor: i % 2 ? VIOLET : CYAN, head: h, body: b, bodySize: 16 }));
  note(s, 'Formerly Apex Terminal. Desktop app, Docker image and ApexBuild module from one codebase.', 5.85);
}

// ── 4. Broadcast ────────────────────────────────────────────────────────
pres.addSection({ title: 'The product' });
{
  const s = content('The product', 'Panes, tabs and broadcast', '');
  s.addText([{ text: 'Many machines, ', options: { color: WHITE } }, { text: 'one deliberate keystroke', options: { color: AMBER } }], { placeholder: 'title' });
  bullets(s, 'pane features', [
    [['Ctrl+Shift+D', 1], [' / '], ['E', 1], [' splits; closing a pane closes the gap.']],
    [['One tab per connection; the layout survives a reload.']],
    [['Broadcast', 1], [' sends every key to every pane in the tab.']],
    [['Send to all', 1], [' is the one-shot: type a line, it lands everywhere.']],
  ], MX, 2.15, 6.6, 4.0, 20);
  card(s, 'amber', 7.75, 2.15, 4.8, 3.6, { big: 'AMBER', bigColor: AMBER, border: AMBER, body: 'The whole window stays amber while broadcast is on, because forgetting it is how a command meant for one machine runs on nine.', bodySize: 17 });
}

// ── 5. Sessions ─────────────────────────────────────────────────────────
{
  const s = content('The product', 'Nothing is lost', 'Sessions outlive the window');
  const cw = (11.8 - 2 * 0.35) / 3;
  [
    ['256 KB', CYAN, 'of scrollback replayed when you reopen: the command kept running.'],
    ['20 s', VIOLET, 'keep-alive ping, so proxies and power managers don\'t drop the link.'],
    ['host · IP · dir', GREEN, 'on every pane\'s bar: which machine am I on, before every command.'],
  ].forEach(([k, col, b], i) => card(s, k, MX + i * (cw + 0.35), 2.15, cw, 3.1, { big: k, bigColor: col, body: b, bodySize: 17 }));
  note(s, 'Optional anti-idle keeps the far end from timing out a quiet session. Off by default, and the pane says when it is on.', 5.6);
}

// ── 6. Record ───────────────────────────────────────────────────────────
{
  const s = content('The product', 'The record', 'What was run, where, and when');
  table(s, 'record table', [
    ['Commands', 'Every command line sent, with time, pane and server. Searchable; Insert puts one back on a prompt.'],
    ['Servers', 'Every SSH destination: sessions, durations, commands sent. Connect reopens it.'],
    ['History', 'Every connection opened; name one to keep it under Saved.'],
    ['Never stored', 'Passwords: input that wasn\'t echoed is skipped, and --password-style secrets are blanked.'],
  ], 2.15);
}

// ── 7. Server tools ─────────────────────────────────────────────────────
pres.addSection({ title: 'Server tools' });
{
  const s = content('Server tools', 'Server tools · ◈ server · Ctrl+Shift+X', 'Seven diagnostics, one click from the problem');
  const tools = [
    ['♥', 'Health', 'CPU, memory, disk, load, network; top processes.'],
    ['⚡', 'Performance', 'What is slow, and why.'],
    ['☰', 'Logs', 'Errors grouped and counted.'],
    ['✦', 'AI log analysis', 'Verdict, cause, first command.'],
    ['▤', 'Packages', 'Runtimes, servers, databases.'],
    ['⛨', 'Vulnerabilities', 'Security updates and CVEs (OSV.dev).'],
    ['↺', 'History', 'Every scan of this machine.'],
  ];
  const cw = (11.8 - 3 * 0.25) / 4, ch = 2.2;
  tools.forEach(([g, h, b], i) => {
    const x = MX + (i % 4) * (cw + 0.25), y = 2.0 + Math.floor(i / 4) * (ch + 0.25);
    card(s, h, x, y, cw, ch, { glyph: g, glyphColor: i % 2 ? VIOLET : CYAN, head: h, body: b, bodySize: 14 });
  });
  card(s, 'system', MX + 3 * (cw + 0.25), 2.0 + ch + 0.25, cw, ch, { head: '◈ system', body: 'The same seven tools for this computer.', dashed: true, bodySize: 14 });
}

// ── 8. Shared login ─────────────────────────────────────────────────────
{
  const s = content('Server tools', 'Nothing installed, nothing changed', 'The tools ride the login you already typed');
  const steps = [
    ['⌨', 'Pane', 'ssh admin@db1: the password or one-time code is typed once.'],
    ['⇄', 'Shared connection', 'OpenSSH multiplexing: no second login, no second prompt.'],
    ['$', 'Read-only probe', 'Run with sh -s: nothing copied, nothing left behind.'],
  ];
  const cw = 3.35, gap = (11.8 - 3 * cw) / 2;
  steps.forEach(([g, h, b], i) => {
    const x = MX + i * (cw + gap);
    card(s, h, x, 2.2, cw, 2.9, { glyph: g, glyphColor: [CYAN, VIOLET, GREEN][i], head: h, body: b, bodySize: 16 });
    if (i < 2) s.addShape(pres.shapes.RIGHT_ARROW, { objectName: `arrow ${i + 1}`, x: x + cw + gap / 2 - 0.3, y: 3.45, w: 0.6, h: 0.4, fill: { color: CYAN }, line: { color: CYAN, width: 0 } });
  });
  note(s, 'A server is recognised by its machine identity, so the same box by name, IP or jump host has one history.', 5.5);
}

// ── 9. Assistant ────────────────────────────────────────────────────────
pres.addSection({ title: 'AI and security' });
{
  const s = content('AI and security', 'The assistant', 'AI proposes, a person decides');
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { objectName: 'terminal', x: MX, y: 2.15, w: 6.5, h: 2.75, rectRadius: 0.12, fill: { color: PAGE }, line: { color: RULE, width: 1 } });
  const mono = 'Courier New';
  s.addText([
    { text: 'ask  ', options: { color: MUTED } }, { text: 'what is listening on port 8443?', options: { color: WHITE, breakLine: true } },
    { text: ' ', options: { breakLine: true } },
    { text: '$ ', options: { color: GREEN } }, { text: "ss -ltnp 'sport = :8443'", options: { color: TEXT, breakLine: true } },
    { text: '$ ', options: { color: GREEN } }, { text: 'sudo lsof -iTCP:8443 -sTCP:LISTEN', options: { color: TEXT, breakLine: true } },
    { text: ' ', options: { breakLine: true } },
    { text: '$0.0121 · 908 in / 181 out · included in subscription', options: { color: MUTED, fontSize: 13 } },
  ], { objectName: 'terminal text', isTextBox: true, x: MX + 0.3, y: 2.4, w: 5.9, h: 2.8, fontSize: 16, fontFace: mono, valign: 'top', margin: 0 });
  [2.98, 3.27].forEach((y, i) => {
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { objectName: `insert ${i + 1}`, x: MX + 5.25, y, w: 1.0, h: 0.26, rectRadius: 0.05, fill: { color: PAGE }, line: { color: CYAN, width: 1 } });
    s.addText('INSERT', { objectName: `insert ${i + 1} label`, isTextBox: true, x: MX + 5.25, y, w: 1.0, h: 0.26, fontSize: 11, bold: true, color: CYAN, align: 'center', valign: 'middle', margin: 0 });
  });
  bullets(s, 'assistant rules', [
    [['The agent has '], ['no tools', 1], [' and no permission to use any.']],
    [['INSERT', 1], [' puts the command at the prompt, '], ['without Enter', 1], ['.']],
    [['Runs on your '], ['Claude subscription', 1], ['; no API key in the app.']],
  ], 7.65, 2.15, 4.9, 3.6, 19);
}

// ── 10. Security ────────────────────────────────────────────────────────
{
  const s = content('AI and security', 'Consent and security', 'Nothing leaves without being seen first');
  const items = [
    ['Before AI or OSV.dev', 'The exact text is shown first, with secrets as ***, no address and no server identity. It\'s sent only on Send.'],
    ['Access token', 'The desktop app and Docker image always require one. It becomes an HttpOnly, SameSite=Strict cookie.'],
    ['No web page can open a shell', 'The WebSocket Origin is checked, and framing is refused except by ApexBuild.'],
    ['Data stays local', 'History and reports live on the operator\'s computer. Nothing goes to a central service.'],
  ];
  const cw = (11.8 - 0.3) / 2, ch = 1.85;
  items.forEach(([h, b], i) => card(s, h, MX + (i % 2) * (cw + 0.3), 2.1 + Math.floor(i / 2) * (ch + 0.3), cw, ch, { head: h, body: b, bodySize: 16 }));
}

// ── 11. Where it runs ───────────────────────────────────────────────────
pres.addSection({ title: 'Delivery' });
{
  const s = content('Delivery', 'Where it runs', 'One codebase, three ways to run it');
  table(s, 'platforms table', [
    ['Desktop', 'Linux (native Qt window; .deb, Arch package, tarball) · macOS Apple silicon · Windows (ConPTY, PowerShell)'],
    ['Docker', 'The console in a browser; shells inside the container as an unprivileged user'],
    ['ApexBuild', 'The terminal module, signed in by the suite'],
    ['From source', 'Python 3.11 and nothing else: it opens on a machine already in trouble'],
  ], 2.15);
  note(s, 'Releases are signed and published to ARES Repository; every build must pass --self-test.', 5.9);
}

// ── 12. Status ──────────────────────────────────────────────────────────
{
  const s = content('Delivery', 'Status and next steps', 'In daily use; the open items are polish');
  const cw = (11.8 - 2 * 0.35) / 3;
  [
    [VERSION || '2.3.0', GREEN, 'Released: native Linux window. 2.2.x added server tools, tabs and the command record.'],
    ['macOS', AMBER, 'Decision: fund an Apple Developer ID to remove the right-click on first launch.'],
    ['Docker', CYAN, 'Recommendation: private network or behind TLS only. A token is not a personal login.'],
  ].forEach(([k, col, b], i) => card(s, k, MX + i * (cw + 0.35), 2.15, cw, 3.1, { big: k, bigColor: col, body: b, bodySize: 17 }));
  note(s, 'On Windows the server tools need an SSH key or agent, because its OpenSSH can\'t share a connection.', 5.6);
}

// ── Write, then give the deck its own theme colours ─────────────────────
(async () => {
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  await pres.writeFile({ fileName: OUT });
  await applyThemeColours(OUT);
  console.log(OUT);
})().catch((e) => { console.error(e); process.exit(1); });

// pptxgenjs writes Office's stock palette into the theme; replace it with ours.
async function applyThemeColours(file) {
  const JSZip = require('jszip');
  const zip = await JSZip.loadAsync(fs.readFileSync(file));
  const part = 'ppt/theme/theme1.xml';
  let xml = await zip.file(part).async('string');
  for (const [k, v] of Object.entries(THEME.colors)) {
    xml = xml.replace(new RegExp(`(<a:${k}>)[\\s\\S]*?(</a:${k}>)`), `$1<a:srgbClr val="${v}"/>$2`);
  }
  xml = xml.replace(/<a:clrScheme name="[^"]*"/, `<a:clrScheme name="${THEME.name}"`);
  zip.file(part, xml);
  // pptxgenjs repeats <a:pPr> before every run after the first in a paragraph. Only one is
  // allowed, at the start; the stray ones carry <a:buNone/>, which cancels the bullet.
  for (const name of Object.keys(zip.files).filter((k) => /^ppt\/slides\/slide\d+\.xml$/.test(k))) {
    const slide = await zip.file(name).async('string');
    zip.file(name, slide.replace(/(<\/a:r>)(?:<a:pPr[^>]*\/>|<a:pPr[^>]*>[\s\S]*?<\/a:pPr>)(?=<a:r>)/g, '$1'));
  }
  // Copy files only: folder entries upset some cloud viewers.
  const out = new JSZip();
  for (const [name, entry] of Object.entries(zip.files)) {
    if (!entry.dir) out.file(name, await entry.async('nodebuffer'), { createFolders: false });
  }
  fs.writeFileSync(file, await out.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' }));
}
