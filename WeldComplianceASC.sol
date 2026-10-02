// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title  WeldComplianceASC — Adaptive Smart Contract
 * @notice Regulatory-enforcement kernel of the Adaptive Trust Chain (ATC).
 *         Implements Algorithm 1 of:
 *
 *         Sk. Riad Bin Ashraf, Hasibur Rahman, Bernd Noche, Tan Gürpinar —
 *         "Adaptive Trust Chain: Blockchain-Anchored Weld-Parameter Compliance
 *          for Green Hydrogen Infrastructure"
 *         Frontiers in Blockchain (under review)
 *
 * @dev    EVIDENTIARY STATUS — EXECUTABLE SPECIFICATION ONLY.
 *         This contract has NOT been deployed to a live network, formally
 *         verified, or externally audited.  It is released so that Algorithm 1
 *         can be inspected in its target language (Solidity 0.8.20) for an
 *         EVM-compatible permissioned ledger (e.g. Hyperledger Besu under
 *         QBFT consensus).  Do NOT use in any production or safety-critical
 *         context without independent audit and formal verification.
 *
 * @dev    KEY DESIGN NOTES (see paper Section 4.3 and Table 4)
 *
 *         1. PRE-WELD PERMISSIVE CHECK ONLY.
 *            checkCompliance() evaluates parameters available at authorisation
 *            time.  It is NOT a full in-process state machine; inter-pass
 *            temperature, for example, can change materially after arc-start.
 *            A production deployment requires a fully-specified state machine
 *            covering arc-start, continuous monitoring, arc-end, NDT
 *            attachment, inspector sign-off, and certificate revocation
 *            (paper Section 4.5).
 *
 *         2. SINGLE ILLUSTRATIVE THRESHOLD OBJECT.
 *            Thresholds here are a single global set for expository clarity.
 *            A deployment MUST resolve thresholds[WPS_ID] per the applicable
 *            qualified Welding Procedure Specification / Procedure Qualification
 *            Record so that each joint is checked against its own material-,
 *            joint-, and process-specific limits (paper Section 5, Table 4).
 *
 *         3. NDT INPUTS ARE NON-GATING AT PRE-WELD STAGE.
 *            ndtHash and ipfsCid are recorded for traceability but do NOT
 *            affect the Boolean return at this stage; they gate final
 *            Structural Passport closure (post-weld, outside this function).
 *
 *         4. "ADAPTIVE" MEANS GOVERNED THRESHOLD UPDATES.
 *            The word "adaptive" denotes that threshold parameters are
 *            governed on-chain parameters updatable only through the
 *            multi-signature council process (updateThreshold, below) — e.g.
 *            when a WPS is re-qualified or an applicable standard is revised.
 *            It does NOT denote autonomous or learning-based limit adjustment.
 *
 * @custom:not-a-safety-function
 *         The Compliance Bit produced by this contract is a production-
 *         permissive interlock signal, not a certified Safety Instrumented
 *         Function under IEC 61511-1.  See paper Section 4.4.
 */
contract WeldComplianceASC {

    // ─────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────

    event ComplianceGranted(bytes32 indexed welderDID, bytes32 indexed weldID);
    event ComplianceDenied (bytes32 indexed welderDID, bytes32 indexed weldID,
                            FailureReason reason);
    event ThresholdUpdated (string param, uint256 oldValue, uint256 newValue,
                            address updatedBy);
    event WelderRegistered (bytes32 indexed welderDID, uint256 expiry,
                            address registeredBy);
    event EquipmentUpdated (bytes32 indexed equipmentID, bool calibrated,
                            address updatedBy);
    event GovernanceProposal(uint256 indexed proposalID, string param,
                             uint256 proposedValue);
    event GovernanceApproved(uint256 indexed proposalID);

    // ─────────────────────────────────────────────────────────────
    // Enumerations
    // ─────────────────────────────────────────────────────────────

    enum FailureReason {
        NONE,
        CERT_NOT_FOUND,
        CERT_EXPIRED,
        EQUIPMENT_NOT_CALIBRATED,
        PREHEAT_BELOW_MIN,
        INTERPASS_ABOVE_MAX,
        HUMIDITY_ABOVE_MAX
    }

    // ─────────────────────────────────────────────────────────────
    // Structs
    // ─────────────────────────────────────────────────────────────

    /// @dev Welder credential entry — keyed by DID hash (bytes32 keccak256).
    struct WelderCredential {
        uint256 expiry;       // Unix timestamp; 0 = not registered
        bytes32 certHash;     // SHA-256 of the ISO 9606-1 certificate
        bool    active;
    }

    /// @dev Weld record written to the ledger on PROVISIONALLY_COMPLIANT.
    struct WeldRecord {
        bytes32 weldID;
        bytes32 welderDID;
        bytes32 equipmentID;
        uint256 preheatTemp;   // °C × 10 (one decimal place)
        uint256 interpassTemp; // °C × 10
        uint256 humidity;      // %RH × 10
        bytes32 batchID;
        bytes32 ndtHash;       // SHA-256 of NDT file; may be 0 pre-NDT
        string  ipfsCid;       // IPFS CID of NDT file; may be "" pre-NDT
        bool    compliant;
        uint256 timestamp;
    }

    /**
     * @dev  Illustrative single-threshold object for expository clarity.
     *       A deployment MUST replace this with a per-WPS mapping:
     *           mapping(bytes32 => ProcessThresholds) public thresholds;
     *       keyed by WPS_ID so each joint is checked against its own limits.
     */
    struct ProcessThresholds {
        uint256 minPreheat;    // °C × 10  (ISO 15614-1 minimum)
        uint256 maxInterpass;  // °C × 10  (EN 1011-2 clause 8.3 ceiling)
        uint256 maxHumidity;   // %RH × 10 (EN 1011-2 ambient envelope)
    }

    /// @dev Multi-signature governance proposal.
    struct Proposal {
        string  param;
        uint256 proposedValue;
        uint256 approvalCount;
        bool    executed;
        mapping(address => bool) approved;
    }

    // ─────────────────────────────────────────────────────────────
    // State variables
    // ─────────────────────────────────────────────────────────────

    address public owner;

    /// @dev Governance council addresses (≥2/3 must approve threshold updates).
    address[] public councilMembers;
    uint256   public requiredApprovals;   // = ⌈2/3 × councilMembers.length⌉

    /// @dev Welder credential registry — DID hash → credential.
    mapping(bytes32 => WelderCredential) public welderRegistry;

    /// @dev Equipment calibration registry — equipment ID hash → calibrated.
    mapping(bytes32 => bool) public calibrationRegistry;

    /// @dev Weld records — weld ID → record.
    mapping(bytes32 => WeldRecord) public weldRecords;

    /**
     * @dev  Global illustrative threshold set (see design note 2 above).
     *       Initialised with representative values; updated only via
     *       multi-signature governance (proposeThresholdUpdate / approveProposal).
     */
    ProcessThresholds public thresholds;

    /// @dev Pending governance proposals.
    uint256 public proposalCount;
    mapping(uint256 => Proposal) private _proposals;

    // ─────────────────────────────────────────────────────────────
    // Modifiers
    // ─────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        require(msg.sender == owner, "ATC: not owner");
        _;
    }

    modifier onlyCouncil() {
        bool isMember = false;
        for (uint256 i = 0; i < councilMembers.length; i++) {
            if (councilMembers[i] == msg.sender) { isMember = true; break; }
        }
        require(isMember, "ATC: not a council member");
        _;
    }

    // ─────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────

    /**
     * @param _councilMembers   Initial governance council (≥3 recommended).
     * @param _minPreheat       Minimum pre-heat temperature °C × 10.
     * @param _maxInterpass     Maximum inter-pass temperature °C × 10.
     * @param _maxHumidity      Maximum ambient humidity %RH × 10.
     *
     * @dev  Representative defaults for illustration only.  A deployment
     *       MUST populate these from the applicable qualified WPS/PQR.
     */
    constructor(
        address[] memory _councilMembers,
        uint256 _minPreheat,
        uint256 _maxInterpass,
        uint256 _maxHumidity
    ) {
        require(_councilMembers.length >= 3, "ATC: need >= 3 council members");
        owner          = msg.sender;
        councilMembers = _councilMembers;
        // Require ⌈2/3⌉ approvals
        requiredApprovals = (_councilMembers.length * 2 + 2) / 3;

        thresholds = ProcessThresholds({
            minPreheat:   _minPreheat,
            maxInterpass: _maxInterpass,
            maxHumidity:  _maxHumidity
        });
    }

    // ─────────────────────────────────────────────────────────────
    // Algorithm 1 — checkCompliance  (paper Section 4.3)
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice  Pre-weld compliance check.  Invoked by the Oracle gateway
     *          before each weld operation.  Returns a PROVISIONALLY_COMPLIANT
     *          flag (true) when all five conditions are satisfied, together
     *          with the coded failure reason on any non-compliance.
     *
     * @dev     See EVIDENTIARY STATUS and design notes in contract header.
     *
     * @param welderDID     keccak256 of the welder's W3C DID string.
     * @param equipmentID   keccak256 of the equipment identifier.
     * @param preheatTemp   Measured pre-heat temperature (°C × 10).
     * @param interpassT    Measured inter-pass temperature (°C × 10).
     * @param humidity      Measured ambient humidity (%RH × 10).
     * @param batchID       keccak256 of electrode batch/lot identifier.
     * @param ndtHash       SHA-256 hash of NDT file (may be bytes32(0) pre-NDT).
     * @param ipfsCid       IPFS content identifier of NDT file (may be "" pre-NDT).
     *
     * @return compliant    True if all five pre-weld checks pass.
     * @return reason       Coded failure reason (NONE on success).
     */
    function checkCompliance(
        bytes32 welderDID,
        bytes32 equipmentID,
        uint256 preheatTemp,
        uint256 interpassT,
        uint256 humidity,
        bytes32 batchID,
        bytes32 ndtHash,
        string  calldata ipfsCid
    )
        external
        returns (bool compliant, FailureReason reason)
    {
        // Step 1: Derive deterministic weld ID (Algorithm 1, line 1)
        bytes32 weldID = keccak256(
            abi.encodePacked(welderDID, equipmentID, block.timestamp)
        );

        // Step 2: Welder DID registered? (Algorithm 1, line 2)
        if (welderRegistry[welderDID].expiry == 0) {
            emit ComplianceDenied(welderDID, weldID, FailureReason.CERT_NOT_FOUND);
            return (false, FailureReason.CERT_NOT_FOUND);
        }

        // Step 3: Credential not expired? (Algorithm 1, line 3)
        // ISO 9606-1 two-year validity window enforced here
        if (block.timestamp > welderRegistry[welderDID].expiry) {
            emit ComplianceDenied(welderDID, weldID, FailureReason.CERT_EXPIRED);
            return (false, FailureReason.CERT_EXPIRED);
        }

        // Step 4: Equipment calibrated? (Algorithm 1, line 4)
        if (!calibrationRegistry[equipmentID]) {
            emit ComplianceDenied(welderDID, weldID,
                                  FailureReason.EQUIPMENT_NOT_CALIBRATED);
            return (false, FailureReason.EQUIPMENT_NOT_CALIBRATED);
        }

        // Step 5: Pre-heat meets ISO 15614-1 minimum? (Algorithm 1, line 5)
        // NOTE: uses global illustrative threshold; deployment should use
        //       thresholds[WPS_ID].minPreheat
        if (preheatTemp < thresholds.minPreheat) {
            emit ComplianceDenied(welderDID, weldID,
                                  FailureReason.PREHEAT_BELOW_MIN);
            return (false, FailureReason.PREHEAT_BELOW_MIN);
        }

        // Step 6: Inter-pass below EN 1011-2 ceiling? (Algorithm 1, line 6)
        if (interpassT > thresholds.maxInterpass) {
            emit ComplianceDenied(welderDID, weldID,
                                  FailureReason.INTERPASS_ABOVE_MAX);
            return (false, FailureReason.INTERPASS_ABOVE_MAX);
        }

        // Step 7: Humidity within EN 1011-2 envelope? (Algorithm 1, line 7)
        if (humidity > thresholds.maxHumidity) {
            emit ComplianceDenied(welderDID, weldID,
                                  FailureReason.HUMIDITY_ABOVE_MAX);
            return (false, FailureReason.HUMIDITY_ABOVE_MAX);
        }

        // Step 8: Record weld and emit event (Algorithm 1, lines 8–9)
        // ndtHash and ipfsCid are recorded for traceability but are NON-GATING
        // at this pre-weld stage (see design note 3 in contract header).
        weldRecords[weldID] = WeldRecord({
            weldID:       weldID,
            welderDID:    welderDID,
            equipmentID:  equipmentID,
            preheatTemp:  preheatTemp,
            interpassTemp: interpassT,
            humidity:     humidity,
            batchID:      batchID,
            ndtHash:      ndtHash,
            ipfsCid:      ipfsCid,
            compliant:    true,
            timestamp:    block.timestamp
        });

        emit ComplianceGranted(welderDID, weldID);
        // Compliance Bit = TRUE → Oracle sets PLC relay via OPC-UA
        return (true, FailureReason.NONE);
    }

    // ─────────────────────────────────────────────────────────────
    // Governed threshold update — multi-signature council
    // (paper Section 4.3: "adaptive" = governed on-chain parameter)
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice  Propose a threshold update.  Any council member may propose;
     *          execution requires ≥2/3 approvals via approveProposal().
     *          Called when a WPS is re-qualified or an applicable standard
     *          (ISO 3834, EN 13445, EU Hydrogen Package) is revised.
     *
     * @param param          Name of threshold ("minPreheat" | "maxInterpass" |
     *                       "maxHumidity").
     * @param proposedValue  New value (same units as constructor).
     * @return proposalID    ID to pass to approveProposal().
     */
    function proposeThresholdUpdate(
        string calldata param,
        uint256 proposedValue
    )
        external
        onlyCouncil
        returns (uint256 proposalID)
    {
        proposalID = proposalCount++;
        Proposal storage p = _proposals[proposalID];
        p.param         = param;
        p.proposedValue = proposedValue;
        p.executed      = false;
        p.approvalCount = 0;
        emit GovernanceProposal(proposalID, param, proposedValue);
    }

    /**
     * @notice  Approve a pending threshold proposal.  When ≥2/3 council
     *          members have approved, the threshold is updated automatically
     *          and the on-chain audit trail records the change.
     *
     * @param proposalID   ID returned by proposeThresholdUpdate().
     */
    function approveProposal(uint256 proposalID) external onlyCouncil {
        Proposal storage p = _proposals[proposalID];
        require(!p.executed,          "ATC: already executed");
        require(!p.approved[msg.sender], "ATC: already approved by caller");

        p.approved[msg.sender] = true;
        p.approvalCount++;

        if (p.approvalCount >= requiredApprovals) {
            p.executed = true;
            _applyThresholdUpdate(p.param, p.proposedValue);
            emit GovernanceApproved(proposalID);
        }
    }

    /**
     * @dev  Internal — apply a threshold update and emit audit event.
     */
    function _applyThresholdUpdate(
        string memory param,
        uint256 newValue
    ) internal {
        bytes32 paramHash = keccak256(bytes(param));
        if (paramHash == keccak256("minPreheat")) {
            uint256 old = thresholds.minPreheat;
            thresholds.minPreheat = newValue;
            emit ThresholdUpdated(param, old, newValue, msg.sender);
        } else if (paramHash == keccak256("maxInterpass")) {
            uint256 old = thresholds.maxInterpass;
            thresholds.maxInterpass = newValue;
            emit ThresholdUpdated(param, old, newValue, msg.sender);
        } else if (paramHash == keccak256("maxHumidity")) {
            uint256 old = thresholds.maxHumidity;
            thresholds.maxHumidity = newValue;
            emit ThresholdUpdated(param, old, newValue, msg.sender);
        } else {
            revert("ATC: unknown threshold parameter");
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Registry management — owner / authorised notified body
    // ─────────────────────────────────────────────────────────────

    /**
     * @notice  Register or update a welder credential.
     * @param welderDID   keccak256 of the welder's W3C DID string.
     * @param expiry      Unix timestamp of ISO 9606-1 certificate expiry.
     * @param certHash    SHA-256 hash of the certificate document.
     */
    function registerWelder(
        bytes32 welderDID,
        uint256 expiry,
        bytes32 certHash
    )
        external
        onlyOwner
    {
        welderRegistry[welderDID] = WelderCredential({
            expiry:   expiry,
            certHash: certHash,
            active:   true
        });
        emit WelderRegistered(welderDID, expiry, msg.sender);
    }

    /**
     * @notice  Update equipment calibration status.
     * @param equipmentID  keccak256 of the equipment identifier.
     * @param calibrated   True if calibration is current; false to revoke.
     */
    function setCalibrationStatus(
        bytes32 equipmentID,
        bool    calibrated
    )
        external
        onlyOwner
    {
        calibrationRegistry[equipmentID] = calibrated;
        emit EquipmentUpdated(equipmentID, calibrated, msg.sender);
    }

    // ─────────────────────────────────────────────────────────────
    // View helpers
    // ─────────────────────────────────────────────────────────────

    /// @notice  Returns the current threshold set.
    function getThresholds()
        external
        view
        returns (uint256 minPreheat, uint256 maxInterpass, uint256 maxHumidity)
    {
        return (
            thresholds.minPreheat,
            thresholds.maxInterpass,
            thresholds.maxHumidity
        );
    }

    /// @notice  Returns true if the welder DID is registered and not expired.
    function isWelderValid(bytes32 welderDID)
        external
        view
        returns (bool)
    {
        WelderCredential storage cred = welderRegistry[welderDID];
        return cred.expiry > 0 && block.timestamp <= cred.expiry && cred.active;
    }

    /// @notice  Returns the number of council members and required approvals.
    function governanceInfo()
        external
        view
        returns (uint256 members, uint256 required)
    {
        return (councilMembers.length, requiredApprovals);
    }
}
