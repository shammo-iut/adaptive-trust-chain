# Adaptive Trust Chain (ATC) — Prototype Implementation

> **Companion code for:**
> Sk. Riad Bin Ashraf, Hasibur Rahman, Bernd Noche, Tan Gürpinar — *"Adaptive Trust Chain (ATC): A Blockchain-Based Weld Certification Framework for Structural Integrity Assurance in Green Hydrogen Infrastructure"* — IEEE Access (under review)
> Chair of Transport Systems and Logistics (TuL), University of Duisburg-Essen, Germany

---

## Overview

This repository provides the full prototype implementation of the **Adaptive Trust Chain (ATC)** — a five-layer permissioned blockchain architecture that closes the *passive safety gap* in weld certification for green hydrogen infrastructure. The prototype comprises three artefacts described in the paper appendix:

1. **`WeldComplianceASC.sol`** — Solidity 0.8.20 Adaptive Smart Contract (Algorithm 1)
2. **`ASI_ComplianceBit.st`** — IEC 61131-3 Structured Text ASI-PLC specification (Algorithm 2)
3. **`Prototype.py`** — Python Monte Carlo simulation reproducing Section VII-E results
4. **`gen_final_figs.py`** — Publication figure generator (Figs. 1, 6, 7, 8 of the paper)

All artefacts are design-level prototypes — latency parameters are derived from published Hyperledger Besu QBFT benchmarks, not a deployed physical system.

---

## Background

Welded joints in green hydrogen infrastructure operate under pressures exceeding 700 bar and are susceptible to **hydrogen embrittlement (HE)** in the weld heat-affected zone (HAZ). Prevailing certification practice relies on paper-based procedure logs and post-fabrication audits — a *passive safety gap* that gives rise to:

- **Administrative latency**: credential expiry not matched by equipment lockout
- **Traceability deficits**: in-process parameters cannot be reconstructed after a structural failure

The ATC addresses this by linking a Hyperledger Besu QBFT blockchain directly to a SIL 2-rated Safety PLC. The **Compliance Bit** is `FALSE` by default (Fail-Locked design). The welding relay energises **if and only if** all upstream checks pass and the Oracle payload is cryptographically verified.

---

## Repository Structure

```
atc/
│
├── WeldComplianceASC.sol         # Algorithm 1 — Solidity 0.8.20 Adaptive Smart Contract
├── ASI_ComplianceBit.st          # Algorithm 2 — IEC 61131-3 ST ASI-PLC specification
├── Prototype.py                  # Core simulation — reproduces paper figures & Table 8
├── Prototype_app.py              # Interactive Streamlit UI for exploratory analysis
├── gen_final_figs.py             # Publication figures: radar (Fig.1), Paris (Fig.6),
│                                 #   DTMC (Fig.7), Monte Carlo overview (Fig.8)
├── ATC_Phase4_Simulator.html     # Self-contained browser-based ASI-PLC simulator
├── run_atc_app.bat               # One-click launcher for the Streamlit app (Windows)
├── requirements.txt              # Python dependencies
├── Images/                       # Simulation output figures (Figs. 6a–6f)
│   ├── Figure_1.png              # Fig. 6a — ASI-PLC Latency Distribution
│   ├── Figure_2.png              # Fig. 6b — Decision Outcomes by Scenario Type
│   ├── Figure_3.png              # Fig. 6c — Compliance Bit Timeline & Latency
│   ├── Figure_4.png              # Fig. 6d — Latency CDF: Valid vs. Timeout
│   ├── Figure_5.png              # Fig. 6e — Non-Compliance & Attack Detection Rate
│   └── Figure_6.png              # Fig. 6f — ASI-PLC Safety State Machine
└── README.md
```

**Artefacts and paper sections:**

| Artefact                    | Paper section / Algorithm | Description                                              |
| --------------------------- | ------------------------- | -------------------------------------------------------- |
| `WeldComplianceASC.sol`     | §V-C, Algorithm 1         | Solidity 0.8.20 Adaptive Smart Contract                  |
| `ASI_ComplianceBit.st`      | §V-D, Algorithm 2         | IEC 61131-3 Structured Text ASI-PLC safety interlock     |
| `Prototype.py`              | §VII-E, Table 8           | Monte Carlo ASI-PLC simulation (200 scenarios, seed=2025)|
| `gen_final_figs.py`         | Figs. 1, 6, 7, 8          | Radar benchmark, Paris–Erdogan, DTMC, Monte Carlo summary|
| `Prototype_app.py`          | —                         | Interactive Streamlit dashboard for exploratory runs     |
| `ATC_Phase4_Simulator.html` | —                         | Browser-based ASI-PLC simulator (no install needed)      |

---

## The ASI-PLC State Machine

The simulator implements the five-step Compliance Bit decision cycle from **Algorithm 2** in the paper, running on a 500 ms cycle aligned with the QBFT finality window:

```
Step 1 — Heartbeat Monitoring   → Latency > 500 ms          ⟹ SOFT_LOCK
Step 2 — Anti-Replay Check      → Nonce ≤ last nonce         ⟹ HARD_LOCK
Step 3 — HMAC-SHA256 Verify     → Signature mismatch         ⟹ HARD_LOCK (MitM detected)
Step 4 — Asymmetric Sig Verify  → Oracle identity unverified ⟹ HARD_LOCK
Step 5 — Compliance Bit         → All checks passed          ⟹ COMPLIANT / NON_COMPLIANT
```

**PLC States:**

| State           | Meaning                                         | Recovery                           |
| --------------- | ----------------------------------------------- | ---------------------------------- |
| `IDLE`          | Awaiting first Oracle payload                   | —                                  |
| `COMPLIANT`     | Compliance Bit TRUE — relay energised           | —                                  |
| `NON_COMPLIANT` | ASC returned FALSE (e.g. preheat below minimum) | Automatic on next valid cycle      |
| `SOFT_LOCK`     | Heartbeat timeout (>500 ms)                     | Automatic on restored connectivity |
| `HARD_LOCK`     | Cryptographic failure (MitM / replay)           | **Manual admin reset required**    |

The full state transition diagram (IEC 61131-3 / IEC 61511-1 SIL 2) is shown below:

[![Fig. 6f — ASI-PLC Safety State Machine](Images/Figure_6.png)](Images/Figure_6.png)

*Fig. 6f — ASI-PLC Safety State Machine (IEC 61131-3 / IEC 61511-1 SIL 2). Default state is Fail-Locked (ComplianceBit := FALSE). HARD LOCK requires authenticated manual admin reset; SOFT LOCK recovers automatically on heartbeat restoration.*

---

## Monte Carlo Simulation (n = 200, seed = 2025)

`Prototype.py` runs 200 welding operation scenarios across five fault types and reproduces all results in **Section VII-E** and **Table 8** of the paper.

**Default scenario plan:**

| Scenario           | Count | Fault Type   | Expected Outcome           |
| ------------------ | ----- | ------------ | -------------------------- |
| Valid (compliant)  | 120   | `NONE`       | `COMPLIANT`, relay ON      |
| Non-compliant weld | 50    | `NON_COMPLY` | `NON_COMPLIANT`, relay OFF |
| MitM attack        | 10    | `MITM`       | `HARD_LOCK`, relay OFF     |
| Replay attack      | 10    | `REPLAY`     | `HARD_LOCK`, relay OFF     |
| Oracle timeout     | 10    | `TIMEOUT`    | `SOFT_LOCK`, relay OFF     |

### Decision Outcomes by Scenario Type

[![Fig. 6b — ASI-PLC Decision Outcomes by Scenario Type](Images/Figure_2.png)](Images/Figure_2.png)

*Fig. 6b — ASI-PLC decision outcomes across all 200 scenarios (n=200, seed=2025). All 120 valid scenarios resolve as COMPLIANT; all MitM and Replay attacks trigger HARD_LOCK; 9/10 timeout scenarios trigger SOFT_LOCK.*

### Non-Compliance and Attack Detection Rate

[![Fig. 6e — Non-Compliance & Attack Detection Rate](Images/Figure_5.png)](Images/Figure_5.png)

*Fig. 6e — Zero false permits confirmed across all 80 non-compliant and attack scenarios. Non-compliant: 50/50 (100%); MitM: 10/10 (100%); Replay: 10/10 (100%); Timeout: 9/10 (90%, one scenario at boundary latency).*

**Key results (reproduced from paper):**

- Valid scenario mean latency: **274.6 ms** (P95 = 320.6 ms) — within the 500 ms permissive window
- **Zero false permits (relay never energised on non-compliant weld)** across all 80 non-compliant/attack scenarios
- Timeout scenarios trigger Soft Lock at mean **514.6 ms** (SD ≈ 20 ms)

> ⚠️ These results confirm the logical correctness of the simulation model under the assumed latency distributions. They are not measurements from a deployed physical system.

---

## Simulation Output Figures

Running `Prototype.py` generates the following six publication-quality figures, saved to the `Images/` folder.

### Fig. 6a — ASI-PLC Latency Distribution: Valid-Credential Scenarios

[![Fig. 6a — ASI-PLC Latency Distribution](Images/Figure_1.png)](Images/Figure_1.png)

*QBFT finality + OPC-UA delivery latency for valid-credential scenarios (n=120, seed=2025). Mean = 274.6 ms; P95 = 320.6 ms. All valid scenarios fall well within the 500 ms permissive window. KDE overlay confirms near-normal distribution.*

---

### Fig. 6c — Compliance Bit Timeline & Latency (First 40 Decisions)

[![Fig. 6c — Compliance Bit Timeline & Latency](Images/Figure_3.png)](Images/Figure_3.png)

*Top panel: Compliance Bit state (TRUE/FALSE) over the first 40 PLC decision cycles. Bottom panel: per-cycle latency with 500 ms permissive window and mean valid latency (274.6 ms) reference lines. All 40 valid-credential cycles resolve as COMPLIANT with latency well below the threshold.*

---

### Fig. 6d — ASI-PLC Latency CDF: Valid vs. Timeout Scenarios

[![Fig. 6d — Latency CDF: Valid vs. Timeout](Images/Figure_4.png)](Images/Figure_4.png)

*Cumulative distribution functions for valid (n=120, solid green) and timeout (n=10, dashed blue) scenarios. Valid P95 = 320.6 ms; the entire valid CDF sits below the 500 ms permissive window. All timeout scenarios fall in the Soft Lock zone (>500 ms), confirming clean separation between the two populations.*

---

## Security Scenarios Tested

| Threat                       | Injection Method                                      | ATC Response                                   |
| ---------------------------- | ----------------------------------------------------- | ---------------------------------------------- |
| **MitM payload injection**   | HMAC signature corrupted                              | HARD\_LOCK — manual reset required             |
| **Replay attack**            | Stale nonce re-used (nonce = 1)                       | HARD\_LOCK — monotonic nonce check fails       |
| **Oracle connectivity loss** | Latency drawn from `N(514.6, 20)` ms                  | SOFT\_LOCK — relay de-energised, auto-recovers |
| **Non-compliant weld**       | `compliant_flag = False` (e.g. preheat below minimum) | `NON_COMPLIANT` — relay stays off              |

These correspond to the STRIDE threat model in **Table IV** of the paper.

---

## Smart Contract (WeldComplianceASC.sol)

`WeldComplianceASC.sol` is the Solidity 0.8.20 Adaptive Smart Contract (Algorithm 1). It implements:

- **`checkCompliance()`** — `view` function; evaluates five compliance conditions sequentially; no state change (minimises QBFT round-trip latency on the critical pre-weld path).
- **`recordWeld()`** — writes the Structural Passport entry to on-chain storage after weld completion; increments per-equipment weld sequence number.
- **Multi-sig governance** — `proposeThresholdUpdate()` / `signProposal()` require `MIN_SIGNATORIES = 3` council signatures; satisfies EU Hydrogen Package 2023 auto-update requirement.
- **Credential registry** — W3C DID hashes → certificate expiry timestamps; ISO 9606-1 two-year validity enforced on-chain.

Deploy on a Hyperledger Besu QBFT network:

```bash
# Install Hardhat
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
npx hardhat compile
# Deploy with constructor args: minPreheat=1000 (100.0°C × 10), maxInterpass=2500, maxHumidity=800, minNDT=900
npx hardhat run scripts/deploy.js --network besu
```

## IEC 61131-3 Structured Text (ASI_ComplianceBit.st)

`ASI_ComplianceBit.st` implements Algorithm 2 for a SIL 2-rated Safety PLC (IEC 61511-1). The five-step cycle runs at 500 ms:

1. **Heartbeat monitoring** — latency > 500 ms → `SOFT_LOCK` (auto-recovers)
2. **Anti-replay nonce check** — nonce ≤ session max → `HARD_LOCK`
3. **HMAC-SHA256 verification** — payload integrity (via HSM sub-program)
4. **Asymmetric signature verification** — Oracle identity (Ed25519 via HSM)
5. **Compliance Bit evaluation** — sets `ComplianceBit := TRUE` and energises relay IFF all checks pass AND `checkCompliance()` returned `TRUE`

The `ComplianceBit` is `FALSE` by default (fail-locked). `HARD_LOCK` requires authenticated manual admin reset; `SOFT_LOCK` auto-recovers on heartbeat restoration.

## Publication Figures (gen_final_figs.py)

`gen_final_figs.py` generates the four paper figures that depend on simulation data:

```bash
python gen_final_figs.py
# Outputs: fig1_radar.png, fig6_paris.png, fig7_dtmc.png, fig8_montecarlo.png
```

| Output            | Paper figure | Content                                              |
| ----------------- | ------------ | ---------------------------------------------------- |
| `fig1_radar.png`  | Fig. 1       | Six-dimension capability benchmark (radar chart)     |
| `fig6_paris.png`  | Fig. 6       | Paris–Erdogan crack growth (air vs H₂ environment)   |
| `fig7_dtmc.png`   | Fig. 7       | DTMC workforce H₂-readiness dynamics (30-year)       |
| `fig8_montecarlo.png` | Fig. 8   | Monte Carlo latency summary (3-panel)                |

**Key parameters (Paris–Erdogan):** a₀ = 0.5 mm, aₒ = 10 mm, C_air = 6.9 × 10⁻¹², m = 3.0, Δσ = 200 MPa, f = 3 000 cycles/yr, Y = 1.12. Result: a(30 yr) ≈ 1.6 mm (air), fracture at 53 yr; H₂ fracture at 13 yr.

**Key parameters (DTMC):** π₀ = [0.70, 0.22, 0.08]; without-intervention: yr-10 H₂-ready = 12.3 %, stationary = 22.6 %; with-intervention: yr-10 = 58.0 %, stationary = 90.0 %.

---

## Installation

**Requirements:** Python 3.10+ (developed and tested on Python 3.14)

```bash
pip install numpy scipy matplotlib seaborn streamlit
```

For Windows users with Python 3.14 installed at `c:\python314\`, the batch launcher (`run_atc_app.bat`) uses that path directly.

---

## Usage

### Command-line simulation (reproduces paper figures)

```bash
python Prototype.py
```

Outputs 6 publication-quality figures (Figs. 6a–6f) to the `Images/` folder.

### Interactive Streamlit app

```bash
streamlit run Prototype_app.py
```

Or on Windows, double-click `run_atc_app.bat`.

The app provides:

- Adjustable scenario counts and random seed via sidebar controls
- Live metric cards (total scenarios, false permits/negatives, hard lock events)
- Latency distribution histogram
- PLC state distribution bar chart
- Scrollable scenario detail table (first 30 results)
- Full state count JSON export

### Browser-based simulator

Open `ATC_Phase4_Simulator.html` directly in any modern browser — no installation required. Implements the same ASI-PLC state machine logic in JavaScript with interactive controls and Chart.js visualisations.

---

## Reproducibility

All simulation parameters are fully documented in **Tables 4–6** of the manuscript. To reproduce the exact paper results:

```python
# Fixed seed ensures identical latency draws and scenario outcomes
seed = 2025
```

The simulation uses `numpy.random.default_rng(seed)` throughout. No external data files are required.

---

## Limitations and Scope

This prototype is a **design-level plausibility check**, not an empirical validation of deployed hardware:

- Latency parameters are drawn from published QBFT benchmarks (Saleh & Cevik, 2025), not measured on a physical fabrication floor
- The HMAC/asymmetric signature verification is a faithful software simulation; production deployment requires a hardware security module (HSM) for the Oracle private key
- Field measurement of latency and false-permit rates under industrial electromagnetic and network conditions remains a prerequisite for operational deployment

---

## Citation

If you use this code in your research, please cite:

```bibtex
@article{ashraf2025atc,
  author  = {Sk. Riad Bin Ashraf, Hasibur Rahman, Bernd Noche, Tan Gürpinar},
  title   = {Adaptive Trust Chain (ATC): A Blockchain-Based Weld Certification
             Framework for Structural Integrity Assurance in Green Hydrogen
             Infrastructure},
  journal = {IEEE Access},
  year    = {2026},
  note    = {Under review}
}
```

---

## Authors

**Sk. Riad Bin Ashraf** · **Hasibur Rahman** · **Bernd Noche** · **Tan Gürpinar**  
Chair of Transport Systems and Logistics (TuL), Faculty of Engineering  
University of Duisburg-Essen, 47057 Duisburg, Germany  
Correspondence: riad.ashraf@uni-due.de

---

## License

This code is released for academic reproducibility. For commercial use or deployment in safety-critical systems, please contact the authors. No warranty is provided; this is a research prototype and must not be used as-is in any production or regulatory context.
