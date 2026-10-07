# Prototype.py — ATC Phase 4: ASI-PLC Simulation
# Reproduces all Monte Carlo results in Section VII-E and Table 8 of:
#   Sk. Riad Bin Ashraf, Hasibur Rahman, Bernd Noche, Tan Gürpinar —
#   "Adaptive Trust Chain (ATC): A Blockchain-Based Weld Certification Framework
#    for Structural Integrity Assurance in Green Hydrogen Infrastructure"
#   IEEE Access (under review)
#
# Run:  python Prototype.py
# Outputs: Images/Figure_1.png through Images/Figure_6.png  (Figs. 6a–6f)
#
# This is a synthetic behavioural simulation under computer-generated inputs.
# It is NOT a measurement from a deployed physical system.

import hashlib
import hmac as hmac_lib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from scipy import stats
import seaborn as sns

sns.set_style('whitegrid')
os.makedirs('Images', exist_ok=True)

# ─────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────

class PLCState(Enum):
    IDLE          = 'IDLE'
    COMPLIANT     = 'COMPLIANT'
    NON_COMPLIANT = 'NON_COMPLIANT'
    SOFT_LOCK     = 'SOFT_LOCK'
    HARD_LOCK     = 'HARD_LOCK'


class FaultType(Enum):
    NONE       = 'none'
    NON_COMPLY = 'non_comply'
    MITM       = 'mitm'
    REPLAY     = 'replay'
    TIMEOUT    = 'timeout'


# ─────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────

@dataclass
class OraclePayload:
    compliant_flag:  bool
    failure_reason:  str
    weld_id:         str
    timestamp_utc:   int
    nonce:           int
    latency_ms:      float
    hmac_sig:        str
    asym_sig:        str


@dataclass
class PLCCycleResult:
    scenario_id:    int
    fault_type:     FaultType
    payload:        OraclePayload
    state:          PLCState
    compliance_bit: bool
    relay_on:       bool
    latency_ms:     float
    step_failures:  List[str] = field(default_factory=list)


# ─────────────────────────────────────────────
# ASI-PLC state machine (Algorithm 2)
# ─────────────────────────────────────────────

class ASI_PLC:
    HEARTBEAT_TIMEOUT_MS = 500.0
    GATEWAY_KEY = b'ATC-QBFT-Besu-OracleKey-TuL-2025'

    def __init__(self):
        self._state          = PLCState.IDLE
        self._last_heartbeat = 0.0
        self._last_nonce     = 0
        self._hard_lock      = False
        self._soft_lock      = False
        self._compliance_bit = False
        self._cycle_clock_ms = 0.0

    @property
    def state(self)          -> PLCState: return self._state
    @property
    def compliance_bit(self) -> bool:     return self._compliance_bit
    @property
    def relay_on(self)       -> bool:     return self._compliance_bit

    # Shared admin key — in production this lives in an HSM (Security Assumption SA2).
    # The simulation uses a fixed token to verify the authenticated admin reset path
    # introduced in Algorithm 2 Step 4a (reviewer correction applied 2026-10).
    ADMIN_KEY   = b'ATC-AdminReset-Key-TuL-2025'
    ADMIN_TOKEN = hmac_lib.new(b'ATC-AdminReset-Key-TuL-2025',
                               b'admin-reset-authorised', hashlib.sha256).hexdigest()

    def admin_reset(self, admin_token: str | None = None) -> bool:
        """Authenticated HardLock reset (Algorithm 2, Step 4a).

        HardLock can only be cleared by an administrator presenting a valid HMAC
        token.  An unauthenticated call (admin_token=None) is rejected and returns
        False, mirroring the paper's IEC 61131-3 Structured Text specification.
        SoftLock clears automatically without authentication.

        Returns True on successful reset, False if authentication failed.
        """
        if self._hard_lock:
            expected = hmac_lib.new(
                self.ADMIN_KEY, b'admin-reset-authorised', hashlib.sha256
            ).hexdigest()
            if admin_token is None or admin_token != expected:
                return False          # Step 4a auth check failed — HardLock persists
        self._hard_lock      = False
        self._compliance_bit = False
        self._state          = PLCState.IDLE
        return True

    def _compute_hmac(self, payload: OraclePayload) -> str:
        data = json.dumps({
            'compliant': payload.compliant_flag,
            'reason':    payload.failure_reason,
            'weld_id':   payload.weld_id,
            'ts':        payload.timestamp_utc,
            'nonce':     payload.nonce,
        }, sort_keys=True).encode()
        return hmac_lib.new(self.GATEWAY_KEY, data, hashlib.sha256).hexdigest()

    def process_cycle(self, payload: OraclePayload) -> Tuple[PLCState, List[str]]:
        failures = []
        self._cycle_clock_ms += self.HEARTBEAT_TIMEOUT_MS

        # Step 1 — Heartbeat timeout → SOFT_LOCK
        if payload.latency_ms > self.HEARTBEAT_TIMEOUT_MS:
            self._soft_lock      = True
            self._compliance_bit = False
            self._state          = PLCState.SOFT_LOCK
            failures.append(f"STEP1_HEARTBEAT_TIMEOUT ({payload.latency_ms:.1f}ms > 500ms)")
            return self._state, failures

        # Step 2 — Anti-replay → HARD_LOCK
        if payload.nonce <= self._last_nonce:
            self._hard_lock      = True
            self._compliance_bit = False
            self._state          = PLCState.HARD_LOCK
            failures.append(f"STEP2_NONCE_REPLAY (rcv={payload.nonce} ≤ last={self._last_nonce})")
            return self._state, failures

        # Step 3 — HMAC-SHA256 verification → HARD_LOCK
        expected_hmac = self._compute_hmac(payload)
        if payload.hmac_sig != expected_hmac:
            self._hard_lock      = True
            self._compliance_bit = False
            self._state          = PLCState.HARD_LOCK
            failures.append('STEP3_HMAC_INVALID (MitM attack detected)')
            return self._state, failures

        # Step 4 — Asymmetric signature verification → HARD_LOCK
        expected_asym = hashlib.sha256(expected_hmac.encode()).hexdigest()
        if payload.asym_sig != expected_asym:
            self._hard_lock      = True
            self._compliance_bit = False
            self._state          = PLCState.HARD_LOCK
            failures.append('STEP4_ASYM_SIG_INVALID (Oracle identity unverified)')
            return self._state, failures

        # Step 5 — Compliance Bit
        self._soft_lock      = False
        self._last_heartbeat = self._cycle_clock_ms
        self._last_nonce     = payload.nonce
        self._compliance_bit = payload.compliant_flag and (not self._hard_lock)
        self._state = PLCState.COMPLIANT if self._compliance_bit else PLCState.NON_COMPLIANT
        return self._state, failures


# ─────────────────────────────────────────────
# Oracle Gateway (payload generator)
# ─────────────────────────────────────────────

class OracleGateway:
    MEAN_LATENCY_MS  = 274.6
    STD_LATENCY_MS   = 25.0
    TIMEOUT_MEAN_MS  = 514.6
    TIMEOUT_STD_MS   = 20.0
    GATEWAY_KEY      = b'ATC-QBFT-Besu-OracleKey-TuL-2025'

    def __init__(self, rng: np.random.Generator):
        self._rng   = rng
        self._nonce = 0

    def build_payload(self, compliant: bool, reason: str, fault: FaultType) -> OraclePayload:
        # REPLAY: do NOT advance the counter — reuse the last accepted nonce.
        # This models an attacker retransmitting a captured valid payload.
        # The PLC session ledger has already accepted this nonce, so it rejects it.
        if fault != FaultType.REPLAY:
            self._nonce += 1
        ts      = int(time.time())
        weld_id = secrets.token_hex(8)
        nonce   = self._nonce  # for REPLAY: same value as last accepted nonce

        latency = float(
            self._rng.normal(self.TIMEOUT_MEAN_MS, self.TIMEOUT_STD_MS)
            if fault == FaultType.TIMEOUT
            else self._rng.normal(self.MEAN_LATENCY_MS, self.STD_LATENCY_MS)
        )

        body = json.dumps({
            'compliant': compliant,
            'reason':    reason,
            'weld_id':   weld_id,
            'ts':        ts,
            'nonce':     nonce,
        }, sort_keys=True).encode()

        hmac_sig = hmac_lib.new(self.GATEWAY_KEY, body, hashlib.sha256).hexdigest()
        asym_sig = hashlib.sha256(hmac_sig.encode()).hexdigest()

        if fault == FaultType.MITM:
            hmac_sig = secrets.token_hex(32)          # corrupt the HMAC

        return OraclePayload(
            compliant_flag=compliant,
            failure_reason=reason,
            weld_id=weld_id,
            timestamp_utc=ts,
            nonce=nonce,
            latency_ms=latency,
            hmac_sig=hmac_sig,
            asym_sig=asym_sig,
        )


# ─────────────────────────────────────────────
# Simulation runner
# ─────────────────────────────────────────────

SCENARIO_PLAN = [
    (120, FaultType.NONE,       True,  'COMPLIANT'),
    (50,  FaultType.NON_COMPLY, False, 'PREHEAT_BELOW_MINIMUM'),
    (10,  FaultType.MITM,       True,  'COMPLIANT'),
    (10,  FaultType.REPLAY,     True,  'COMPLIANT'),
    (10,  FaultType.TIMEOUT,    True,  'COMPLIANT'),
]


def run_simulation(seed: int = 2025) -> List[PLCCycleResult]:
    """Run 200-cycle Monte Carlo simulation.

    State isolation (Reviewer R2 correction, 2026-10):
    - HardLock, SoftLock and ComplianceBit are reset before EVERY individual run
      so that each cycle's outcome is statistically independent.
    - The session-level nonce ledger (seen_nonces) is intentionally preserved
      across runs: replay detection requires that the PLC remember nonces it has
      already accepted within the same operational session.  A replay attacker
      re-injects a nonce the PLC already accepted; resetting the nonce ledger
      per-run would make every replay look fresh and defeat detection.
    - This mirrors real-world PLC behaviour: lock state is cleared by an admin
      reset between welds, but the nonce ledger persists for the session.

    Scenario breakdown: 120 valid + 50 non-compliant + 10 MitM
                        + 10 replay + 10 timeout  =  200 total.
    """
    rng     = np.random.default_rng(seed)
    oracle  = OracleGateway(rng)
    plc     = ASI_PLC()
    results: List[PLCCycleResult] = []
    sid     = 0

    # Session-level nonce ledger: preserved across runs within the session.
    # The PLC rejects any nonce ≤ the highest nonce it has accepted so far.
    session_max_nonce: int = 0

    for count, fault, compliant, reason in SCENARIO_PLAN:
        for _ in range(count):
            # Per-run lock/state reset — clears HardLock, SoftLock, ComplianceBit.
            # Does NOT reset the nonce ledger (session_max_nonce) — see docstring.
            plc.admin_reset(admin_token=ASI_PLC.ADMIN_TOKEN)
            plc._soft_lock      = False
            plc._compliance_bit = False
            # Restore nonce ledger into PLC so each run starts with correct history.
            plc._last_nonce = session_max_nonce

            payload = oracle.build_payload(compliant, reason, fault)
            state, failures = plc.process_cycle(payload)

            # Update session nonce ledger only on legitimate (non-replay) accepted payloads.
            if fault != FaultType.REPLAY and payload.nonce > session_max_nonce:
                session_max_nonce = payload.nonce

            results.append(PLCCycleResult(
                scenario_id=sid,
                fault_type=fault,
                payload=payload,
                state=state,
                compliance_bit=plc.compliance_bit,
                relay_on=plc.relay_on,
                latency_ms=payload.latency_ms,
                step_failures=failures,
            ))
            sid += 1

    return results


# ─────────────────────────────────────────────
# Figure generators  (Figs. 6a – 6f)
# ─────────────────────────────────────────────

COLORS = {
    'compliant':     '#2E7D32',
    'non_compliant': '#C62828',
    'soft_lock':     '#E65100',
    'hard_lock':     '#4A148C',
    'timeout':       '#1565C0',
    'neutral':       '#455A64',
    'threshold':     '#B71C1C',
    'mean_line':     '#1B5E20',
}


def fig6a_latency_hist(results: List[PLCCycleResult]):
    """Fig. 6a — ASI-PLC Latency Distribution: Valid-Credential Scenarios"""
    valid_lats = [r.latency_ms for r in results if r.fault_type == FaultType.NONE]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.hist(valid_lats, bins=25, color=COLORS['compliant'], edgecolor='white', alpha=0.75, label='Valid scenario latency')
    kde_x = np.linspace(min(valid_lats), max(valid_lats), 300)
    kde = stats.gaussian_kde(valid_lats)
    ax2 = ax.twinx()
    ax2.plot(kde_x, kde(kde_x), color='#1B5E20', lw=2, label='KDE')
    ax2.set_ylabel('Density', fontsize=11)
    mean_lat = np.mean(valid_lats)
    p95_lat  = np.percentile(valid_lats, 95)
    ax.axvline(mean_lat,  color=COLORS['mean_line'], lw=1.8, ls='--', label=f'Mean = {mean_lat:.1f} ms')
    ax.axvline(p95_lat,   color='#F57F17',            lw=1.8, ls=':',  label=f'P95  = {p95_lat:.1f} ms')
    ax.axvline(500,       color=COLORS['threshold'],   lw=1.8, ls='-',  label='500 ms threshold')
    ax.set_xlabel('Latency (ms)', fontsize=12)
    ax.set_ylabel('Count',        fontsize=12)
    ax.set_title('Fig. 6a — ASI-PLC Latency Distribution: Valid-Credential Scenarios\n'
                 f'(n={len(valid_lats)}, seed=2025, mean={mean_lat:.1f} ms, P95={p95_lat:.1f} ms)',
                 fontsize=11)
    handles1, labels1 = ax.get_legend_handles_labels()
    handles2, labels2 = ax2.get_legend_handles_labels()
    ax.legend(handles1 + handles2, labels1 + labels2, fontsize=9, loc='upper right')
    plt.tight_layout()
    plt.savefig('Images/Figure_1.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Fig. 6a saved  (mean={mean_lat:.1f} ms, P95={p95_lat:.1f} ms)")


def fig6b_decision_outcomes(results: List[PLCCycleResult]):
    """Fig. 6b — Decision Outcomes by Scenario Type"""
    fault_labels = ['NONE\n(valid)', 'NON_COMPLY', 'MITM', 'REPLAY', 'TIMEOUT']
    state_order  = [PLCState.COMPLIANT, PLCState.NON_COMPLIANT, PLCState.HARD_LOCK,
                    PLCState.SOFT_LOCK, PLCState.IDLE]
    state_colors = ['#2E7D32', '#C62828', '#4A148C', '#E65100', '#455A64']

    groups = {FaultType.NONE: [], FaultType.NON_COMPLY: [], FaultType.MITM: [],
              FaultType.REPLAY: [], FaultType.TIMEOUT: []}
    for r in results:
        groups[r.fault_type].append(r)

    data = {s: [] for s in state_order}
    for ft in [FaultType.NONE, FaultType.NON_COMPLY, FaultType.MITM,
               FaultType.REPLAY, FaultType.TIMEOUT]:
        grp = groups[ft]
        for s in state_order:
            data[s].append(sum(1 for r in grp if r.state == s))

    x   = np.arange(len(fault_labels))
    w   = 0.15
    fig, ax = plt.subplots(figsize=(11, 6))
    for i, (s, c) in enumerate(zip(state_order, state_colors)):
        ax.bar(x + i * w, data[s], w, label=s.value, color=c, alpha=0.85)
    ax.set_xlabel('Scenario / Fault Type', fontsize=12)
    ax.set_ylabel('Count',                 fontsize=12)
    ax.set_title('Fig. 6b — ASI-PLC Decision Outcomes by Scenario Type\n(n=200, seed=2025)', fontsize=11)
    ax.set_xticks(x + w * 2)
    ax.set_xticklabels(fault_labels, fontsize=10)
    ax.legend(title='PLC State', fontsize=9, title_fontsize=9)
    plt.tight_layout()
    plt.savefig('Images/Figure_2.png', dpi=150, bbox_inches='tight')
    plt.close()
    print("  Fig. 6b saved")


def fig6c_compliance_timeline(results: List[PLCCycleResult]):
    """Fig. 6c — Compliance Bit Timeline & Latency (First 40 decisions)"""
    first40   = results[:40]
    cb_vals   = [1 if r.compliance_bit else 0 for r in first40]
    latencies = [r.latency_ms for r in first40]
    xs        = list(range(1, 41))
    valid_lats = [r.latency_ms for r in results if r.fault_type == FaultType.NONE]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 7), sharex=True)
    ax1.step(xs, cb_vals, where='post', color=COLORS['compliant'], lw=2)
    ax1.fill_between(xs, cb_vals, step='post', alpha=0.25, color=COLORS['compliant'])
    ax1.set_ylabel('Compliance Bit', fontsize=11)
    ax1.set_yticks([0, 1])
    ax1.set_yticklabels(['FALSE', 'TRUE'])
    ax1.set_title('Fig. 6c — Compliance Bit Timeline & Latency (First 40 Decision Cycles)\n(n=200, seed=2025)', fontsize=11)
    ax2.bar(xs, latencies, color=COLORS['compliant'], alpha=0.7, width=0.8)
    ax2.axhline(500,                     color=COLORS['threshold'], lw=1.8, ls='--', label='500 ms threshold')
    ax2.axhline(np.mean(valid_lats),     color=COLORS['mean_line'], lw=1.5, ls=':',  label=f'Mean valid = {np.mean(valid_lats):.1f} ms')
    ax2.set_xlabel('Decision Cycle',     fontsize=11)
    ax2.set_ylabel('Latency (ms)',        fontsize=11)
    ax2.legend(fontsize=9, loc='upper right')
    plt.tight_layout()
    plt.savefig('Images/Figure_3.png', dpi=150, bbox_inches='tight')
    plt.close()
    print("  Fig. 6c saved")


def fig6d_latency_cdf(results: List[PLCCycleResult]):
    """Fig. 6d — Latency CDF: Valid vs. Timeout Scenarios"""
    valid_lats   = sorted(r.latency_ms for r in results if r.fault_type == FaultType.NONE)
    timeout_lats = sorted(r.latency_ms for r in results if r.fault_type == FaultType.TIMEOUT)

    fig, ax = plt.subplots(figsize=(9, 5))
    for lats, color, ls, label in [
        (valid_lats,   COLORS['compliant'], '-',  f'Valid (n={len(valid_lats)})'),
        (timeout_lats, COLORS['timeout'],   '--', f'Timeout (n={len(timeout_lats)})'),
    ]:
        cdf = np.arange(1, len(lats) + 1) / len(lats)
        ax.plot(lats, cdf, color=color, lw=2, ls=ls, label=label)

    ax.axvline(500, color=COLORS['threshold'], lw=1.8, ls=':', label='500 ms threshold')
    ax.set_xlabel('Latency (ms)', fontsize=12)
    ax.set_ylabel('CDF',          fontsize=12)
    ax.set_title('Fig. 6d — ASI-PLC Latency CDF: Valid vs. Timeout Scenarios\n(n=200, seed=2025)', fontsize=11)
    ax.legend(fontsize=10)
    plt.tight_layout()
    plt.savefig('Images/Figure_4.png', dpi=150, bbox_inches='tight')
    plt.close()
    valid_p95 = np.percentile(valid_lats, 95)
    print(f"  Fig. 6d saved  (valid P95={valid_p95:.1f} ms)")


def fig6e_detection_rate(results: List[PLCCycleResult]):
    """Fig. 6e — Non-Compliance & Attack Detection Rate"""
    categories = {
        'Non-Compliant\n(50)': [r for r in results if r.fault_type == FaultType.NON_COMPLY],
        'MitM\n(10)':          [r for r in results if r.fault_type == FaultType.MITM],
        'Replay\n(10)':        [r for r in results if r.fault_type == FaultType.REPLAY],
        'Timeout\n(10)':       [r for r in results if r.fault_type == FaultType.TIMEOUT],
    }
    detected = [sum(1 for r in v if not r.compliance_bit) for v in categories.values()]
    totals   = [len(v) for v in categories.values()]
    rates    = [d / t * 100 for d, t in zip(detected, totals)]

    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(list(categories.keys()), rates,
                  color=[COLORS['non_compliant'], COLORS['hard_lock'],
                         COLORS['hard_lock'], COLORS['soft_lock']],
                  alpha=0.85, width=0.5)
    for bar, rate in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f'{rate:.0f}%', ha='center', va='bottom', fontsize=11, fontweight='bold')
    ax.set_ylim(0, 115)
    ax.set_ylabel('Detection Rate (%)', fontsize=12)
    ax.set_title('Fig. 6e — Non-Compliance & Attack Detection Rate\n'
                 '(n=200, seed=2025; zero false permits — relay never energised on non-compliant weld)', fontsize=11)
    ax.axhline(100, color='#1B5E20', lw=1.2, ls='--', alpha=0.6, label='100% detection')
    ax.legend(fontsize=9)
    plt.tight_layout()
    plt.savefig('Images/Figure_5.png', dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Fig. 6e saved  (detection rates: {[f'{r:.0f}%' for r in rates]})")


def fig6f_state_machine():
    """Fig. 6f — ASI-PLC Safety State Machine diagram"""
    fig, ax = plt.subplots(figsize=(12, 8))
    ax.set_xlim(0, 10); ax.set_ylim(0, 8); ax.axis('off')
    ax.set_title('Fig. 6f — ASI-PLC Safety State Machine\n'
                 '(IEC 61131-3 / IEC 61511-1 SIL 2 — Fail-Locked Design)', fontsize=12)

    states = {
        'IDLE':          (5.0, 6.5, COLORS['neutral']),
        'COMPLIANT':     (2.0, 3.5, COLORS['compliant']),
        'NON_COMPLIANT': (5.0, 3.5, COLORS['non_compliant']),
        'SOFT_LOCK':     (8.0, 3.5, COLORS['soft_lock']),
        'HARD_LOCK':     (5.0, 1.0, COLORS['hard_lock']),
    }
    r = 0.7
    for name, (x, y, color) in states.items():
        circ = plt.Circle((x, y), r, color=color, alpha=0.85, zorder=3)
        ax.add_patch(circ)
        ax.text(x, y, name.replace('_', '\n'), ha='center', va='center',
                fontsize=8.5, fontweight='bold', color='white', zorder=4)

    # arrows: (src, dst, label, color, label_offset_x, label_offset_y)
    arrows = [
        ('IDLE',          'COMPLIANT',     'All checks pass\n+ Oracle TRUE',    '#2E7D32',  -0.5,  0.0),
        ('IDLE',          'NON_COMPLIANT', 'Oracle FALSE\n(e.g. preheat fail)', '#C62828',   0.0,  0.35),
        ('IDLE',          'SOFT_LOCK',     'Latency\n>500 ms',                  '#E65100',   0.55, 0.0),
        ('IDLE',          'HARD_LOCK',     'HMAC / nonce fail',                 '#4A148C',  -0.65, 0.0),
        ('COMPLIANT',     'NON_COMPLIANT', 'Oracle FALSE',                      '#C62828',   0.0,  0.3),
        ('NON_COMPLIANT', 'COMPLIANT',     'Next valid cycle',                  '#2E7D32',   0.0, -0.3),
        ('SOFT_LOCK',     'IDLE',          'Heartbeat\nrestored',               '#E65100',   0.55, 0.0),
    ]

    def mid(x1, y1, x2, y2):
        return (x1 + x2) / 2, (y1 + y2) / 2

    # Slightly curve COMPLIANT↔NON_COMPLIANT arrows so they don't overlap
    curve_pairs = {('COMPLIANT', 'NON_COMPLIANT'), ('NON_COMPLIANT', 'COMPLIANT')}

    for src, dst, label, color, lox, loy in arrows:
        x1, y1, _ = states[src]
        x2, y2, _ = states[dst]
        dx, dy = x2 - x1, y2 - y1
        dist   = (dx ** 2 + dy ** 2) ** 0.5
        sx     = x1 + r * dx / dist
        sy     = y1 + r * dy / dist
        ex     = x2 - r * dx / dist
        ey     = y2 - r * dy / dist

        if (src, dst) in curve_pairs:
            # Use a curved arrow via connectionstyle
            sign = 1 if (src, dst) == ('COMPLIANT', 'NON_COMPLIANT') else -1
            ax.annotate('', xy=(ex, ey), xytext=(sx, sy),
                        arrowprops=dict(arrowstyle='->', color=color, lw=1.5,
                                        connectionstyle=f'arc3,rad={sign*0.3}'))
        else:
            ax.annotate('', xy=(ex, ey), xytext=(sx, sy),
                        arrowprops=dict(arrowstyle='->', color=color, lw=1.5))

        mx, my = mid(sx, sy, ex, ey)
        ax.text(mx + lox, my + loy, label, ha='center', va='center',
                fontsize=7.5, color=color,
                bbox=dict(boxstyle='round,pad=0.25', fc='white', ec=color, alpha=0.9, lw=0.8))

    # Hard lock note
    ax.text(5.0, 0.15, 'HARD_LOCK: Authenticated admin reset required (Step 4a)',
            ha='center', va='center', fontsize=8, color=COLORS['hard_lock'],
            style='italic')
    ax.text(0.3, 0.3, 'Default: ComplianceBit := FALSE (Fail-Locked)',
            ha='left', va='bottom', fontsize=8.5, color='#B71C1C', fontweight='bold')

    plt.tight_layout()
    plt.savefig('Images/Figure_6.png', dpi=150, bbox_inches='tight')
    plt.close()
    print("  Fig. 6f saved")


# ─────────────────────────────────────────────
# Summary table (Table 8 equivalent)
# ─────────────────────────────────────────────

def print_summary(results: List[PLCCycleResult]):
    valid    = [r for r in results if r.fault_type == FaultType.NONE]
    nc       = [r for r in results if r.fault_type == FaultType.NON_COMPLY]
    mitm     = [r for r in results if r.fault_type == FaultType.MITM]
    replay   = [r for r in results if r.fault_type == FaultType.REPLAY]
    timeout  = [r for r in results if r.fault_type == FaultType.TIMEOUT]

    lats    = [r.latency_ms for r in valid]
    fp      = sum(1 for r in nc + mitm + replay if r.compliance_bit)
    fn      = sum(1 for r in valid if not r.compliance_bit)

    print("\n" + "=" * 60)
    print("  ASI-PLC Monte Carlo Summary  (n=200, seed=2025)")
    print("=" * 60)
    print(f"  Valid scenarios  : {len(valid):>4}  → COMPLIANT: {sum(1 for r in valid if r.state == PLCState.COMPLIANT)}")
    print(f"  Non-compliant    : {len(nc):>4}  → NON_COMPLIANT: {sum(1 for r in nc if r.state == PLCState.NON_COMPLIANT)}")
    print(f"  MitM attacks     : {len(mitm):>4}  → HARD_LOCK: {sum(1 for r in mitm if r.state == PLCState.HARD_LOCK)}")
    print(f"  Replay attacks   : {len(replay):>4}  → HARD_LOCK: {sum(1 for r in replay if r.state == PLCState.HARD_LOCK)}")
    print(f"  Timeout scenarios: {len(timeout):>4}  → SOFT_LOCK: {sum(1 for r in timeout if r.state == PLCState.SOFT_LOCK)}")
    print("-" * 60)
    print(f"  Mean valid latency : {np.mean(lats):.1f} ms")
    print(f"  P95  valid latency : {np.percentile(lats, 95):.1f} ms")
    print(f"  False permits      : {fp}  (relay energised on non-compliant weld)")
    print(f"  False negatives    : {fn}  (compliant weld blocked)")
    print("=" * 60 + "\n")


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == '__main__':
    print("ATC Phase 4 — ASI-PLC Simulation (seed=2025)")
    print("Generating figures to Images/ ...\n")

    results = run_simulation(seed=2025)
    print_summary(results)

    fig6a_latency_hist(results)
    fig6b_decision_outcomes(results)
    fig6c_compliance_timeline(results)
    fig6d_latency_cdf(results)
    fig6e_detection_rate(results)
    fig6f_state_machine()

    print("\nDone. Six figures saved to Images/")
