(*
 * ASI_ComplianceBit.st
 * IEC 61131-3 Structured Text — ASI-PLC Compliance Bit Safety Interlock
 *
 * Implements Algorithm 2 from:
 *   Sk. Riad Bin Ashraf, Hasibur Rahman, Bernd Noche, Tan Gürpinar —
 *   "Adaptive Trust Chain (ATC): A Blockchain-Based Weld Certification
 *    Framework for Structural Integrity Assurance in Green Hydrogen
 *    Infrastructure", IEEE Access (under review).
 *
 * Target:  SIL 2-rated Safety PLC (IEC 61511-1)
 *          Cycle time: 500 ms (aligned with QBFT finality window)
 *
 * State machine:
 *   IDLE → COMPLIANT / NON_COMPLIANT (normal operation)
 *          SOFT_LOCK  (heartbeat timeout > 500 ms)
 *          HARD_LOCK  (HMAC/signature failure or replay — manual reset required)
 *
 * Fail-safe design: ComplianceBit := FALSE by default.
 *                   Relay energises ONLY when ComplianceBit := TRUE (COMPLIANT).
 *)

PROGRAM ASI_ComplianceBit

(* ─────────────────────────────────────────────────────────────────────── *)
(* Constants                                                               *)
(* ─────────────────────────────────────────────────────────────────────── *)
CONST
    HEARTBEAT_TIMEOUT_MS : UINT := 500;   (* QBFT finality window, ms     *)
    ADMIN_TOKEN          : DWORD := 16#A1C2B3D4;  (* Hardware-provisioned *)
    MAX_NONCE_HISTORY    : UINT := 1024;  (* Anti-replay nonce window      *)
END_CONST

(* ─────────────────────────────────────────────────────────────────────── *)
(* PLC State Enumeration                                                   *)
(* ─────────────────────────────────────────────────────────────────────── *)
TYPE PLCState :
(
    PLC_IDLE          := 0,
    PLC_COMPLIANT     := 1,
    PLC_NON_COMPLIANT := 2,
    PLC_SOFT_LOCK     := 3,
    PLC_HARD_LOCK     := 4
);
END_TYPE

(* ─────────────────────────────────────────────────────────────────────── *)
(* Oracle Payload Structure                                                *)
(* (received over OPC-UA from Hyperledger Besu Oracle Gateway)            *)
(* ─────────────────────────────────────────────────────────────────────── *)
TYPE OraclePayload :
STRUCT
    compliant      : BOOL;     (* checkCompliance() return value           *)
    reason         : STRING;   (* Coded failure reason or "COMPLIANT"      *)
    weld_id        : STRING;   (* keccak256 weld identifier (hex string)   *)
    nonce          : DWORD;    (* Monotonically increasing anti-replay nonce *)
    timestamp      : DWORD;    (* Unix timestamp (seconds)                 *)
    hmac_sha256    : ARRAY[0..31] OF BYTE;  (* HMAC-SHA256 over payload body *)
    oracle_sig     : ARRAY[0..63] OF BYTE;  (* Ed25519 Oracle identity sig  *)
    latency_ms     : UINT;     (* Measured Oracle round-trip latency        *)
END_STRUCT
END_TYPE

(* ─────────────────────────────────────────────────────────────────────── *)
(* Variable Declarations                                                   *)
(* ─────────────────────────────────────────────────────────────────────── *)
VAR
    (* Inputs — from OPC-UA UA-Server subscription *)
    OraclePayloadIn    : OraclePayload;   (* Latest Oracle payload         *)
    NewPayloadFlag     : BOOL := FALSE;   (* TRUE when new payload arrived *)
    AdminResetToken    : DWORD := 0;      (* Admin reset credential        *)

    (* Outputs — to Safety Relay / DCS *)
    ComplianceBit      : BOOL := FALSE;   (* FALSE = fail-locked (safe state) *)
    WeldingRelayEnable : BOOL := FALSE;   (* Physical relay output         *)
    PLCStateOut        : PLCState := PLC_IDLE;
    AlarmActive        : BOOL := FALSE;

    (* Internal state *)
    CurrentState       : PLCState := PLC_IDLE;
    HardLockActive     : BOOL := FALSE;
    SoftLockActive     : BOOL := FALSE;
    SessionMaxNonce    : DWORD := 0;      (* Highest accepted nonce        *)
    LastPayloadTime    : DWORD := 0;      (* Timestamp of last payload     *)
    CycleTimer         : TON;             (* 500 ms cycle timer            *)

    (* Security verification flags (set by external HSM sub-program) *)
    HMAC_Valid         : BOOL := FALSE;
    SigValid           : BOOL := FALSE;

    (* Diagnostics *)
    HardLockCount      : DINT := 0;
    SoftLockCount      : DINT := 0;
    TotalCycles        : DINT := 0;
    FalsePermitCount   : DINT := 0;  (* Must remain 0 — safety KPI *)
END_VAR

(* ─────────────────────────────────────────────────────────────────────── *)
(* Main cyclic body — executes every 500 ms                               *)
(* ─────────────────────────────────────────────────────────────────────── *)

TotalCycles := TotalCycles + 1;

(* Default outputs: fail-safe state *)
ComplianceBit      := FALSE;
WeldingRelayEnable := FALSE;
AlarmActive        := FALSE;

(* ─────────────────────────────────────────────────────────────────────── *)
(* Algorithm 2 Step 4: HARD_LOCK admin reset (authenticated intervention)  *)
(* ─────────────────────────────────────────────────────────────────────── *)
IF (AdminResetToken = ADMIN_TOKEN) AND HardLockActive THEN
    HardLockActive  := FALSE;
    SoftLockActive  := FALSE;
    CurrentState    := PLC_IDLE;
    AdminResetToken := 0;           (* Consume token — one-shot           *)
END_IF;

(* ─────────────────────────────────────────────────────────────────────── *)
(* Algorithm 2: Five-step Compliance Bit decision cycle                   *)
(* ─────────────────────────────────────────────────────────────────────── *)

IF NOT HardLockActive THEN

    (* ── Step 1: Heartbeat / Latency Monitoring ───────────────────────── *)
    (* SOFT_LOCK if Oracle latency exceeds 500 ms permissive window        *)
    IF NewPayloadFlag THEN
        IF OraclePayloadIn.latency_ms > HEARTBEAT_TIMEOUT_MS THEN
            SoftLockActive := TRUE;
            SoftLockCount  := SoftLockCount + 1;
            CurrentState   := PLC_SOFT_LOCK;
            AlarmActive    := TRUE;
            GOTO CYCLE_END;
        ELSE
            (* Latency within window — clear soft lock if previously set   *)
            SoftLockActive := FALSE;
        END_IF;
    ELSE
        (* No new payload received — connectivity loss *)
        SoftLockActive := TRUE;
        CurrentState   := PLC_SOFT_LOCK;
        AlarmActive    := TRUE;
        GOTO CYCLE_END;
    END_IF;

    (* ── Step 2: HMAC-SHA256 and Signature Verification ─────────────── *)
    (* Algorithm 2 Step 2: cryptographic integrity before replay check.    *)
    (* HMAC_Valid and SigValid are set by the hardware HSM sub-program.    *)
    (* PLC halts if HSM has not completed — fail-safe default.             *)
    IF NOT HMAC_Valid THEN
        HardLockActive := TRUE;
        HardLockCount  := HardLockCount + 1;
        CurrentState   := PLC_HARD_LOCK;
        AlarmActive    := TRUE;
        GOTO CYCLE_END;
    END_IF;

    IF NOT SigValid THEN
        HardLockActive := TRUE;
        HardLockCount  := HardLockCount + 1;
        CurrentState   := PLC_HARD_LOCK;
        AlarmActive    := TRUE;
        GOTO CYCLE_END;
    END_IF;

    (* ── Step 3: Anti-Replay Nonce Check ─────────────────────────────── *)
    (* HARD_LOCK if incoming nonce ≤ highest accepted nonce in session.    *)
    (* Checked after HMAC/SIG to avoid side-channel oracle on replays.     *)
    IF OraclePayloadIn.nonce <= SessionMaxNonce THEN
        HardLockActive := TRUE;
        HardLockCount  := HardLockCount + 1;
        CurrentState   := PLC_HARD_LOCK;
        AlarmActive    := TRUE;
        GOTO CYCLE_END;
    END_IF;

    (* ── Step 5: Compliance Bit Evaluation ───────────────────────────── *)
    (* All security checks passed — evaluate checkCompliance() result.     *)
    SessionMaxNonce := OraclePayloadIn.nonce;   (* Advance nonce ledger    *)
    LastPayloadTime := OraclePayloadIn.timestamp;

    IF OraclePayloadIn.compliant THEN
        (* Relay energises — weld operation permitted                       *)
        ComplianceBit      := TRUE;
        WeldingRelayEnable := TRUE;
        CurrentState       := PLC_COMPLIANT;
    ELSE
        (* checkCompliance() returned FALSE — relay stays de-energised     *)
        ComplianceBit      := FALSE;
        WeldingRelayEnable := FALSE;
        CurrentState       := PLC_NON_COMPLIANT;
        AlarmActive        := TRUE;
    END_IF;

ELSE
    (* HARD_LOCK state — relay locked, alarm, await admin reset            *)
    CurrentState := PLC_HARD_LOCK;
    AlarmActive  := TRUE;
END_IF;

(* ─────────────────────────────────────────────────────────────────────── *)
(* Cycle end — update diagnostic outputs                                   *)
(* ─────────────────────────────────────────────────────────────────────── *)
CYCLE_END:
    PLCStateOut := CurrentState;
    NewPayloadFlag := FALSE;   (* Consume payload flag — cleared each cycle *)

    (* Safety KPI guard: FalsePermitCount must remain 0                    *)
    (* (relay must NEVER energise on a non-compliant or locked payload)    *)
    IF WeldingRelayEnable AND (
        CurrentState = PLC_NON_COMPLIANT OR
        CurrentState = PLC_SOFT_LOCK     OR
        CurrentState = PLC_HARD_LOCK
    ) THEN
        FalsePermitCount   := FalsePermitCount + 1;
        WeldingRelayEnable := FALSE;   (* Safety override                  *)
        ComplianceBit      := FALSE;
    END_IF;

END_PROGRAM
