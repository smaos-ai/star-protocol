# Partner Critique & A/B/C Classification Protocol
**Document Version:** 1.0.5 &bull; **Target Asset:** `dist/review_package.zip` (Synthetic 250-Row Test Vector)  
**Objective:** Measure partner comprehension time (<5 minutes) and qualify lead client use case for €750 Data Feasibility Sprint  
**Target Audience:** Consulting Partners, Big-4 / Regional Risk Advisory Leads, Specialized System Integrators

---

## 1. Interview Workflow & 5-Minute Comprehension Test

Dispatch `dist/review_package.zip` to the partner. Have them extract the 8 files and present the three verification prompts:

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        THE 5-MINUTE COMPREHENSION TEST                                 │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ PROMPT 1: Row Conservation & Dispositions                                              │
│ • Open `conservation_scorecard.json`.                                                 │
│ • Question: "Does every input row account for its disposition, and what is the delta?" │
│ • Target Answer (< 60s): 250 declared = 200 confirmed + 40 unknown + 5 conflicts +     │
│   5 malformed. Delta Δ = 0 (100% mathematical conservation).                           │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ PROMPT 2: The UNKNOWN State Lock & Secondary Findings                                  │
│ • Open `unknown_exposure_inventory.json`.                                             │
│ • Question: "Why are these 40 actions locked in UNKNOWN rather than failed or retry?" │
│ • Target Answer (< 120s): 45 secondary timeout findings (HTTP 504s, connection drops, │
│   socket resets). SMAOS preserves uncertainty because external effect is unconfirmed. │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ PROMPT 3: Replay & Avoided Risk                                                        │
│ • Open `replay.json` and `servicenow_case_export.json`.                                │
│ • Question: "What is the concrete difference between baseline and modeled holds?"      │
│ • Target Answer (< 180s): Baseline allowed unconfirmed dispatches (€5.85M); policy     │
│   holds contained duplicate exposure to €0, drafting a ServiceNow case for CRO sign-off│
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. A / B / C Partner Classification Matrix

Evaluate partner response against this strict qualification gate:

| Classification | Partner Signals & Response | Required Next Action |
| :--- | :--- | :--- |
| **Classification A** *(Immediate Commercial Fit)* | • Comprehends the 8 files in **< 5 minutes**.<br>• Identifies an active client pain point (e.g. autonomous agent dispatches, SWIFT gateway timeouts, unconfirmed payment APIs).<br>• Confirms a **named financial institution / client** + **target date** (< 14 days). | Immediately execute the **€750 Data Feasibility Sprint SOW** ([`docs/SOW_EUR750_DATA_FEASIBILITY_SPRINT.md`](SOW_EUR750_DATA_FEASIBILITY_SPRINT.md)). Deliver in 48 hours. |
| **Classification B** *(Schema / Adaptation Required)* | • Understands the core thesis and values the zero-delta conservation.<br>• Requests specific logging format or schema adaptations (e.g., Datadog, Splunk CEF, AWS CloudWatch, or proprietary core banking JSON). | **Apply schema adjustments ONLY IF tied to a signed €750 SOW.** Do not build speculative adapters for uncommitted partners. |
| **Classification C** *(Non-Aligned / Low-Relevance)* | • Does not grasp the difference between synthetic success and true confirmation.<br>• Client does not deploy autonomous agents making external mutations, or insists on full multi-tenant SaaS. | Log feedback in partner CRM. Politely exit engagement. Do not expend engineering effort. |

---

## 3. Partner Critique Scorecard Template

Copy and fill during the debrief session:

```text
================================================================================
PARTNER CRITIQUE & CLASSIFICATION SCORECARD
================================================================================
Partner Firm:               _____________________________________________
Lead Interviewee / Title:   _____________________________________________
Date & Time of Review:      _____________________________________________
Package Version Reviewed:   review_package.zip (SHA-256: 755caaf71752...)
================================================================================

1. COMPREHENSION METRICS:
   • Time to identify 250 primary dispositions:   ____ minutes ____ seconds
   • Time to locate 45 secondary timeout findings: ____ minutes ____ seconds
   • Understanding of UNKNOWN preservation:       [ ] Immediate  [ ] Hesitant  [ ] Failed

2. PARTNER CLASSIFICATION:
   [ ] CLASSIFICATION A (Immediate commercial fit; named client identified)
   [ ] CLASSIFICATION B (Schema adaptation requested; conditional on €750 SOW)
   [ ] CLASSIFICATION C (Disqualified / non-aligned)

3. NAMED CLIENT OPPORTUNITY (Required for A / B):
   • Target Client Name:     _____________________________________________
   • Core Banking / Agent:   _____________________________________________
   • Target Execution Date:  _____________________________________________
   • SOW Status:             [ ] Issued  [ ] Under Review  [ ] Signed
================================================================================
```
