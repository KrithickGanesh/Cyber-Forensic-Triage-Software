# Cyber Forensic Triage Software — Task Plan
## B.L.A.S.T. Protocol Task Tracker

---

## Protocol 0: Initialization
- [x] Create `task_plan.md`
- [x] Create `findings.md`
- [x] Create `progress.md`
- [x] Create `gemini.md` (Project Constitution)
- [ ] Discovery Questions answered by user
- [ ] Data Schema defined in `gemini.md`
- [ ] Blueprint approved by user

---

## Phase 1: B — Blueprint (Vision & Logic)
- [ ] Discovery Questions answered
- [ ] Data Schema (Input/Output JSON shapes) defined
- [ ] Tech stack finalized
- [ ] GitHub repo created & initialized
- [ ] Architecture plan approved

---

## Phase 2: L — Link (Connectivity)
- [ ] Python environment setup (venv, dependencies)
- [ ] GitHub repo linked to local project
- [ ] All API connections verified (if applicable)
- [ ] Development server boots successfully

---

## Phase 3: A — Architect (The 3-Layer Build)
### Layer 1: Architecture (SOPs)
- [ ] `architecture/scanning.md` — Device scanning SOP
- [ ] `architecture/analysis.md` — AI analysis SOP
- [ ] `architecture/timeline.md` — Timeline generation SOP
- [ ] `architecture/reporting.md` — Report generation SOP
- [ ] `architecture/scoring.md` — Evidence classification SOP

### Layer 2: Navigation (Decision Making)
- [ ] Main app routing (`app.py`)
- [ ] Case management workflow
- [ ] Scan → Analyze → Report pipeline

### Layer 3: Tools (Python Scripts)
- [ ] `tools/scanner.py` — File system scanning engine
- [ ] `tools/hasher.py` — SHA-256 hashing & integrity
- [ ] `tools/analyzer.py` — AI-powered file analysis
- [ ] `tools/timeline.py` — Chronological event builder
- [ ] `tools/scorer.py` — RAG (Red-Amber-Green) classifier
- [ ] `tools/reporter.py` — Court-ready PDF generation
- [ ] `tools/artifact_extractor.py` — Browser, registry, log extraction

---

## Phase 4: S — Stylize (UI/UX)
- [ ] Dashboard design (dark mode, forensic aesthetic)
- [ ] Case creation / management interface
- [ ] Scan progress & status views
- [ ] Evidence gallery with RAG indicators
- [ ] Timeline visualization
- [ ] Report preview & export
- [ ] Responsive design (desktop-first)

---

## Phase 5: T — Trigger (Deployment)
- [ ] Documentation finalized
- [ ] GitHub repo with clean commits
- [ ] Demo-ready prototype
- [ ] README with setup instructions
