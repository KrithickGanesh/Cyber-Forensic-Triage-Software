# Cyber Forensic Triage Software — Task Plan
## B.L.A.S.T. Protocol Task Tracker

---

## Protocol 0: Initialization
- [x] Create `task_plan.md`
- [x] Create `findings.md`
- [x] Create `progress.md`
- [x] Create `gemini.md` (Project Constitution)
- [x] Discovery Questions answered by user
- [x] Data Schema defined in `gemini.md`
- [x] Blueprint approved by user

---

## Phase 1: B — Blueprint (Vision & Logic)
- [x] Discovery Questions answered
- [x] Data Schema (Input/Output JSON shapes) defined
- [x] Tech stack finalized
- [x] GitHub repo created & initialized
- [x] Architecture plan approved

---

## Phase 2: L — Link (Connectivity)
- [x] Python environment setup (venv, dependencies)
- [x] GitHub repo linked to local project
- [x] All API connections verified (if applicable)
- [x] Development server boots successfully

---

## Phase 3: A — Architect (The 3-Layer Build)
### Layer 1: Architecture (SOPs)
- [x] `architecture/scanning.md` — Device scanning SOP
- [x] `architecture/analysis.md` — AI analysis SOP
- [x] `architecture/timeline.md` — Timeline generation SOP
- [x] `architecture/reporting.md` — Report generation SOP
- [x] `architecture/scoring.md` — Evidence classification SOP

### Layer 2: Navigation (Decision Making)
- [x] Main app routing (`app.py`)
- [x] Case management workflow
- [x] Scan → Analyze → Report pipeline

### Layer 3: Tools (Python Scripts)
- [x] `tools/scanner.py` — File system scanning engine
- [x] `tools/hasher.py` — SHA-256 hashing & integrity
- [x] `tools/analyzer.py` — AI-powered file analysis
- [x] `tools/timeline.py` — Chronological event builder
- [x] `tools/scorer.py` — RAG (Red-Amber-Green) classifier
- [x] `tools/reporter.py` — Court-ready PDF generation
- [x] `tools/artifact_extractor.py` — Browser, registry, log extraction

---

## Phase 4: S — Stylize (UI/UX)
- [x] Dashboard design (dark mode, forensic aesthetic)
- [x] Case creation / management interface
- [x] Scan progress & status views
- [x] Evidence gallery with RAG indicators
- [x] Timeline visualization
- [x] Report preview & export
- [x] Responsive design (desktop-first)

---

## Phase 5: T — Trigger (Deployment)
- [ ] Documentation finalized
- [ ] GitHub repo with clean commits
- [ ] Demo-ready prototype
- [ ] README with setup instructions
