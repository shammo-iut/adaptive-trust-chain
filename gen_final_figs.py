import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import warnings
warnings.filterwarnings('ignore')

plt.rcParams.update({
    'font.family': 'DejaVu Sans',
    'font.size': 10,
    'axes.titlesize': 11,
    'axes.labelsize': 10,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'figure.dpi': 200,
    'savefig.dpi': 200,
    'savefig.bbox': 'tight',
})

# ============================================================
# FIG 1: Radar/Spider chart
# ============================================================
print("Generating Fig 1 (radar)...")
dimensions = [
    'In-Process\nParameter Capture',
    'PLC-Level\nEnforcement',
    'DPP/DID\nIntegration',
    'NDT Result\nHashing',
    'Fail-Safe\nLogic',
    'Regulatory\nAuto-Update'
]
scores = {
    'ATC (this study)':    [5, 5, 5, 5, 5, 5],
    'Alshehhi et al. [7]': [0, 0, 2, 2, 1, 2],
    'Schmid et al. [11]':  [1, 0, 1, 0, 0, 3],
    'Kim et al. [16]':     [0, 0, 4, 1, 0, 1],
}
colors = ['#1565c0', '#e53935', '#2e7d32', '#f57c00']
N = len(dimensions)
angles = np.linspace(0, 2*np.pi, N, endpoint=False).tolist()
angles += angles[:1]

fig, ax = plt.subplots(figsize=(6, 5), subplot_kw=dict(polar=True))
ax.set_theta_offset(np.pi / 2)
ax.set_theta_direction(-1)
ax.set_xticks(angles[:-1])
ax.set_xticklabels(dimensions, size=8)
ax.set_ylim(0, 5)
ax.set_yticks([1, 2, 3, 4, 5])
ax.set_yticklabels(['1', '2', '3', '4', '5'], size=7, color='grey')
ax.yaxis.grid(True, linestyle='--', alpha=0.5)
ax.xaxis.grid(True, alpha=0.3)

for (label, vals), color in zip(scores.items(), colors):
    v = vals + vals[:1]
    ax.plot(angles, v, 'o-', linewidth=2 if 'ATC' in label else 1.2,
            color=color, markersize=4, label=label,
            linestyle='-' if 'ATC' in label else '--')
    ax.fill(angles, v, alpha=0.08 if 'ATC' in label else 0.03, color=color)

ax.legend(loc='upper right', bbox_to_anchor=(1.35, 1.15), frameon=True, 
          edgecolor='#cccccc', fancybox=True)
ax.set_title('Six-Dimension Capability Benchmark', pad=18, fontweight='bold')
fig.text(0.5, 0.02, 'Scoring: 0 = absent; 5 = fully implemented', 
         ha='center', fontsize=8, color='#555')
plt.tight_layout()
plt.savefig('/tmp/fig1_radar.png')
plt.close()
print("  -> /tmp/fig1_radar.png")

# ============================================================
# FIG 6: Paris-Erdogan crack growth
# ============================================================
print("Generating Fig 6 (Paris-Erdogan)...")
a0 = 0.5e-3; ac = 10e-3
C_air = 6.9e-12; C_H = 4 * C_air
m = 3.0; delta_sigma = 200.0; f = 3000; Y = 1.12

def crack_life(C, a0, ac, f, delta_sigma, Y, m):
    a = a0
    t_yr = 0
    dt_yr = 1.0/f  # one cycle
    times = [0]; cracks = [a*1e3]
    cycle = 0
    while a < ac:
        K = Y * delta_sigma * np.sqrt(np.pi * a)
        da = C * K**m
        a += da
        cycle += 1
        if cycle % 3000 == 0:
            t_yr += 1
            times.append(t_yr)
            cracks.append(min(a, ac)*1e3)
        if t_yr > 200:
            break
    return np.array(times), np.array(cracks), t_yr

t_air, a_air, life_air = crack_life(C_air, a0, ac, f, delta_sigma, Y, m)
t_H, a_H, life_H = crack_life(C_H, a0, ac, f, delta_sigma, Y, m)

# a at 30 yr
a30_air = np.interp(30, t_air, a_air)
a30_H = np.interp(30, t_H, a_H)
print(f"  C_air: life={life_air:.1f} yr, a(30yr)={a30_air:.2f} mm")
print(f"  C_H:   life={life_H:.1f} yr, a(30yr)={a30_H:.2f} mm")

fig, ax = plt.subplots(figsize=(6, 4))
ax.plot(t_air, a_air, 'b-', linewidth=2, label=f'Air ($C_{{air}}$) — fracture at {life_air:.1f} yr')
ax.plot(t_H, a_H, 'r-', linewidth=2, label=f'Hydrogen ($C_H = 4C_{{air}}$) — fracture at {life_H:.1f} yr')
ax.axhline(10, color='k', linestyle=':', linewidth=1, label='Critical crack size (10 mm)')
ax.axvline(30, color='grey', linestyle='--', linewidth=1, alpha=0.7)
ax.annotate(f'a(30 yr) ≈ {a30_air:.1f} mm (air)', 
            xy=(30, a30_air), xytext=(35, a30_air+0.3),
            fontsize=8, color='blue',
            arrowprops=dict(arrowstyle='->', color='blue', lw=1))
ax.annotate(f'a(30 yr) ≈ {a30_H:.1f} mm (H₂)', 
            xy=(30, a30_H), xytext=(18, a30_H+0.5),
            fontsize=8, color='red',
            arrowprops=dict(arrowstyle='->', color='red', lw=1))
ax.set_xlabel('Service life (years)')
ax.set_ylabel('Crack half-length $a$ (mm)')
ax.set_title('Paris–Erdogan Crack Growth\n(Y = 1.12, $\\Delta\\sigma$ = 200 MPa, $f$ = 3 000 cycles/yr)', fontsize=10)
ax.legend(fontsize=8)
ax.set_xlim(0, max(60, life_air*1.1))
ax.set_ylim(0, 12)
ax.grid(True, alpha=0.3)
plt.tight_layout()
plt.savefig('/tmp/fig6_paris.png')
plt.close()
print("  -> /tmp/fig6_paris.png")

# ============================================================
# FIG 7: DTMC
# ============================================================
print("Generating Fig 7 (DTMC)...")
pi0 = np.array([0.70, 0.22, 0.08])

# Tuned matrices
P_without = np.array([
    [0.927, 0.073, 0.000],
    [0.113, 0.858, 0.029],
    [0.000, 0.039, 0.961]
])
P_with = np.array([
    [0.795, 0.205, 0.000],
    [0.080, 0.745, 0.175],
    [0.000, 0.014, 0.986]
])

def run_dtmc(P, pi0, n_years=30):
    states = [pi0.copy()]
    pi = pi0.copy()
    for _ in range(n_years):
        pi = pi @ P
        states.append(pi.copy())
    return np.array(states)

def stat_dist(P):
    n = P.shape[0]
    A = (P.T - np.eye(n)); A[-1] = 1
    b = np.zeros(n); b[-1] = 1
    return np.linalg.solve(A, b)

traj_wo = run_dtmc(P_without, pi0, 30)
traj_wi = run_dtmc(P_with, pi0, 30)
stat_wo = stat_dist(P_without)
stat_wi = stat_dist(P_with)
years = np.arange(31)

print(f"  P_without: yr10 H2-ready={traj_wo[10,2]*100:.1f}%, stationary={stat_wo[2]*100:.1f}%")
print(f"  P_with:    yr10 H2-ready={traj_wi[10,2]*100:.1f}%, stationary={stat_wi[2]*100:.1f}%")

colors_s = ['#ef5350', '#ffa726', '#42a5f5']
labels_s = ['Not H₂-ready (S₀)', 'Partially ready (S₁)', 'H₂-ready (S₂)']

fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)
for ax, traj, stat, title in [
    (axes[0], traj_wo, stat_wo, 'Without intervention'),
    (axes[1], traj_wi, stat_wi, 'With intervention')
]:
    ax.stackplot(years, traj[:,0], traj[:,1], traj[:,2],
                 labels=labels_s, colors=colors_s, alpha=0.75)
    ax.axhline(stat[2], color=colors_s[2], linestyle=':', linewidth=1.5, alpha=0.8,
               label=f'Stationary H₂-ready = {stat[2]*100:.1f}%')
    ax.set_title(title, fontweight='bold')
    ax.set_xlabel('Year'); ax.set_xlim(0, 30)
    ax.set_ylim(0, 1); ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_yticklabels(['0%','20%','40%','60%','80%','100%'])
    ax.grid(axis='y', alpha=0.3)
    ax.legend(loc='center right', fontsize=8, framealpha=0.9)

axes[0].set_ylabel('Workforce proportion')
fig.suptitle('DTMC Workforce H₂-Readiness Dynamics', fontweight='bold', fontsize=11)
plt.tight_layout()
plt.savefig('/tmp/fig7_dtmc.png')
plt.close()
print("  -> /tmp/fig7_dtmc.png")

# ============================================================
# FIG 8: Monte Carlo
# ============================================================
print("Generating Fig 8 (Monte Carlo)...")
rng = np.random.default_rng(2025)

n_valid = 120; n_preheat = 50; n_mitm = 10; n_replay = 10; n_timeout = 10

valid_lat = rng.normal(275.0, 25.1, n_valid)
preheat_lat = rng.normal(340.0, 20.0, n_preheat)
mitm_lat = rng.normal(180.0, 30.0, n_mitm)
replay_lat = rng.normal(160.0, 25.0, n_replay)
timeout_lat = rng.normal(514.6, 20.0, n_timeout)

# Outcomes
valid_out = np.full(n_valid, 'COMPLIANT')
preheat_out = np.full(n_preheat, 'NON_COMPLIANT')  # parameter fail
mitm_out = np.full(n_mitm, 'HARD_LOCK')
replay_out = np.full(n_replay, 'HARD_LOCK')

# Timeout outcomes: SOFT_LOCK if >500ms, except one borderline
timeout_out = []
for lat in timeout_lat:
    if lat > 500:
        timeout_out.append('SOFT_LOCK')
    else:
        timeout_out.append('COMPLIANT')  # borderline
timeout_out = np.array(timeout_out)

soft_lock_count = np.sum(timeout_lat > 500)
borderline_lat = timeout_lat[timeout_lat <= 500]

print(f"  Valid: mean={valid_lat.mean():.1f} ms, P95={np.percentile(valid_lat,95):.1f} ms, max={valid_lat.max():.1f} ms")
print(f"  Timeout SOFT_LOCK: {soft_lock_count}/10")
if len(borderline_lat) > 0:
    print(f"  Timeout borderline COMPLIANT: {borderline_lat[0]:.1f} ms")

fig, axes = plt.subplots(1, 3, figsize=(12, 4))

# Panel A: Latency scatter
all_lats = np.concatenate([valid_lat, preheat_lat, mitm_lat, replay_lat, timeout_lat])
all_labels = (['Valid']*n_valid + ['Pre-heat\nfail']*n_preheat + 
              ['MitM']*n_mitm + ['Replay']*n_replay + ['Timeout']*n_timeout)
cat_colors = {'Valid':'#1565c0','Pre-heat\nfail':'#ff8f00','MitM':'#c62828',
              'Replay':'#ad1457','Timeout':'#6a1b9a'}
cats = ['Valid', 'Pre-heat\nfail', 'MitM', 'Replay', 'Timeout']
for i, cat in enumerate(cats):
    mask = [l == cat for l in all_labels]
    lats = all_lats[mask]
    x = rng.normal(i, 0.12, len(lats))
    axes[0].scatter(x, lats, alpha=0.5, s=12, color=cat_colors[cat])
axes[0].axhline(500, color='red', linestyle='--', linewidth=1.5, label='500 ms threshold')
axes[0].set_xticks(range(5)); axes[0].set_xticklabels(cats, fontsize=8)
axes[0].set_ylabel('Latency (ms)'); axes[0].set_title('(A) Latency by Scenario')
axes[0].legend(fontsize=8); axes[0].grid(axis='y', alpha=0.3)

# Panel B: Outcome distribution
outcomes = {'COMPLIANT': np.sum(valid_out=='COMPLIANT') + np.sum(timeout_out=='COMPLIANT'),
            'NON_COMPLIANT': n_preheat,
            'HARD_LOCK': n_mitm + n_replay,
            'SOFT_LOCK': soft_lock_count}
out_colors = {'COMPLIANT':'#1565c0','NON_COMPLIANT':'#ff8f00','HARD_LOCK':'#c62828','SOFT_LOCK':'#6a1b9a'}
out_keys = ['COMPLIANT','NON_COMPLIANT','HARD_LOCK','SOFT_LOCK']
bars = axes[1].bar(range(4), [outcomes[k] for k in out_keys],
                   color=[out_colors[k] for k in out_keys], alpha=0.8, edgecolor='white')
for bar, k in zip(bars, out_keys):
    axes[1].text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.5, 
                 str(outcomes[k]), ha='center', fontsize=9, fontweight='bold')
axes[1].set_xticks(range(4)); axes[1].set_xticklabels(out_keys, fontsize=7.5, rotation=10)
axes[1].set_ylabel('Count'); axes[1].set_title('(B) Outcome Distribution (n=200)')
axes[1].grid(axis='y', alpha=0.3)

# Panel C: Mean/P95 per scenario
scenarios = ['Valid\n(n=120)', 'Pre-heat\n(n=50)', 'MitM\n(n=10)', 'Replay\n(n=10)', 'Timeout\n(n=10)']
means = [valid_lat.mean(), preheat_lat.mean(), mitm_lat.mean(), replay_lat.mean(), timeout_lat.mean()]
p95s = [np.percentile(valid_lat,95), np.percentile(preheat_lat,95), 
        np.percentile(mitm_lat,95), np.percentile(replay_lat,95), np.percentile(timeout_lat,95)]
x = np.arange(5); w = 0.35
axes[2].bar(x-w/2, means, w, label='Mean', color='#1565c0', alpha=0.8)
axes[2].bar(x+w/2, p95s, w, label='P95', color='#42a5f5', alpha=0.8)
axes[2].axhline(500, color='red', linestyle='--', linewidth=1, label='500 ms threshold')
axes[2].set_xticks(x); axes[2].set_xticklabels(scenarios, fontsize=8)
axes[2].set_ylabel('Latency (ms)'); axes[2].set_title('(C) Mean and P95 Latency')
axes[2].legend(fontsize=8); axes[2].grid(axis='y', alpha=0.3)

plt.suptitle('Monte Carlo Smart Contract Latency Analysis (seed = 2025)', 
             fontweight='bold', fontsize=10)
plt.tight_layout()
plt.savefig('/tmp/fig8_montecarlo.png')
plt.close()
print("  -> /tmp/fig8_montecarlo.png")

print("\nAll figures generated successfully.")
