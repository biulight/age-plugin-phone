import { invoke } from "@tauri-apps/api/core";
import "./styles.css";

interface ProjectStatus {
  stage: string;
  protocolVersion: number;
  qrTransport: string;
  bleTransport: string;
  keyBackend: string;
  doctorEnabled: boolean;
}

interface CapabilityReport {
  androidRelease: string;
  apiLevel: number;
  sdkExtensionLevel: number;
  strongboxFeature: boolean;
  strongBiometric: string;
  secureLockScreen: boolean;
  keyAgreementCryptoObject: boolean;
  leftoverProbeKey: boolean;
  errorCategory: string | null;
}

interface IdentityCustodyReport {
  noBackupStorage: boolean;
  identityStrongBox: boolean;
  identityAgreeOnly: boolean;
  identityAuthPerUse: boolean;
  identityBiometricStrong: boolean;
  signingStrongBox: boolean;
  signingPurposeSignOnly: boolean;
  signingNoUserAuth: boolean;
  privateKeysNonExportable: boolean;
  keysDistinct: boolean;
  metadataBound: boolean;
  reopened: boolean;
  duplicateRejected: boolean;
  preparingRecovered: boolean;
  cleanupComplete: boolean;
  errorCategory: string | null;
}

interface ProbeKeyReport {
  generated: boolean;
  securityLevel: string;
  originGenerated: boolean;
  purposeAgreeKey: boolean;
  userAuthenticationRequired: boolean;
  authPerUse: boolean;
  authenticationType: string;
  authEnforcedBySecureHardware: boolean;
  privateKeyFormatIsNull: boolean;
  privateKeyEncodedIsNull: boolean;
  errorCategory: string | null;
}

interface AgreementReport {
  authenticated: boolean;
  agreementMatch: boolean;
  responseEnvelopeMatch: boolean;
  errorCategory: string | null;
}

interface CleanupReport {
  probeKeyExisted: boolean;
  probeKeyDeleted: boolean;
  probeKeyAbsentAfterDelete: boolean;
  errorCategory: string | null;
}

interface PairingStorageReport {
  noBackupStorage: boolean;
  qrFragmented: boolean;
  qrOutOfOrderReassembled: boolean;
  qrCorruptionRejected: boolean;
  qrTimeoutRejected: boolean;
  transcriptVerified: boolean;
  fingerprintMismatchRejected: boolean;
  cancellationRejected: boolean;
  confirmationCommitted: boolean;
  duplicateConfirmationRejected: boolean;
  atomicStateCreated: boolean;
  verifiedBeforeConsume: boolean;
  replayRejectedAfterReopen: boolean;
  wrongScopeRejected: boolean;
  missingStateRejectedAfterDelete: boolean;
  cleanupComplete: boolean;
  errorCategory: string | null;
}

interface PairingOfferScanReport {
  scannerStarted: boolean;
  messageVerified: boolean;
  desktopLabel: string | null;
  offerFingerprint: string | null;
  framesAccepted: number;
  errorCategory: string | null;
}

interface PhonePairingReport {
  paired: boolean;
  desktopLabel: string | null;
  transcriptFingerprint: string | null;
  errorCategory: string | null;
}

interface PhoneUnwrapReport {
  authenticated: boolean;
  responseDisplayed: boolean;
  requestFingerprint: string | null;
  errorCategory: string | null;
}

type DoctorReport =
  | CapabilityReport
  | IdentityCustodyReport
  | ProbeKeyReport
  | AgreementReport
  | CleanupReport
  | PairingStorageReport
  | PairingOfferScanReport
  | PhonePairingReport
  | PhoneUnwrapReport;

const app = document.querySelector<HTMLElement>("#app");

if (!app) {
  throw new Error("missing application root");
}

app.innerHTML = `
  <section class="shell">
    <p class="eyebrow">OFFLINE AGE IDENTITY</p>
    <h1>Phone identity</h1>
    <p class="summary">
      Long-term keys will stay on this phone. Every unwrap will require a fresh system confirmation.
    </p>
    <dl class="status" id="status">
      <div><dt>Stage</dt><dd>Loading</dd></div>
    </dl>
    <p class="warning">
      Prototype only. Raw QR frames and signed protocol bytes stay in Android native memory; the
      WebView receives only a verified display label, fingerprint, counters, and error categories.
    </p>
    <section class="doctor" id="doctor" hidden>
      <div class="doctor-heading">
        <div>
          <p class="eyebrow">DEVELOPMENT BUILD</p>
          <h2>Android StrongBox Doctor</h2>
        </div>
        <span class="activity" id="activity">Idle</span>
      </div>
      <div class="actions" aria-label="StrongBox probe actions">
        <button data-action="capabilities">Check capabilities</button>
        <button data-action="identityCustody">Test production key custody</button>
        <button data-action="create">Create probe key</button>
        <button data-action="agreement1">Run tagged unwrap #1</button>
        <button data-action="agreement2">Run tagged unwrap #2</button>
        <button data-action="cancel">Run and cancel</button>
        <button data-action="restart">Verify after restart</button>
        <button data-action="pairingStorage">Test pairing QR + replay</button>
        <button data-action="scanPairingOffer">Scan pairing offer</button>
        <button data-action="pairPhone">Pair this phone</button>
        <button data-action="unwrapPhone">Scan and approve unwrap</button>
        <button class="danger" data-action="cleanup">Delete probe key</button>
      </div>
      <pre id="doctor-report" aria-live="polite">No probe has run.</pre>
      <button class="copy" id="copy-report" disabled>Copy non-sensitive report</button>
    </section>
  </section>
`;

const statusElement = document.querySelector<HTMLElement>("#status");
const doctorElement = document.querySelector<HTMLElement>("#doctor");
const activityElement = document.querySelector<HTMLElement>("#activity");
const reportElement = document.querySelector<HTMLElement>("#doctor-report");
const copyButton = document.querySelector<HTMLButtonElement>("#copy-report");
const actionButtons = Array.from(document.querySelectorAll<HTMLButtonElement>("[data-action]"));
const doctorReports: Record<string, DoctorReport> = {};
let busy = false;

function renderStatus(status: ProjectStatus): void {
  if (!statusElement) return;

  const rows: Array<[string, string]> = [
    ["Stage", status.stage],
    ["Protocol", `v${status.protocolVersion}`],
    ["QR", status.qrTransport],
    ["BLE", status.bleTransport],
    ["Hardware key", status.keyBackend],
  ];

  statusElement.innerHTML = rows
    .map(([label, value]) => `<div><dt>${label}</dt><dd>${value}</dd></div>`)
    .join("");
}

function setBusy(value: boolean): void {
  busy = value;
  actionButtons.forEach((button) => {
    button.disabled = value;
  });
  if (activityElement) activityElement.textContent = value ? "Working" : "Idle";
}

function showReport(name: string, report: DoctorReport): void {
  doctorReports[name] = report;
  if (reportElement) reportElement.textContent = JSON.stringify(doctorReports, null, 2);
  if (copyButton) copyButton.disabled = false;
}

async function runDoctor<T extends DoctorReport>(command: string, reportName = command): Promise<T> {
  if (busy) throw new Error("doctor operation already active");
  setBusy(true);
  try {
    const report = await invoke<T>(`plugin:phone-identity|${command}`);
    showReport(reportName, report);
    return report;
  } finally {
    setBusy(false);
  }
}

actionButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const action = button.dataset.action;
    const commands: Record<string, string> = {
      capabilities: "doctor_capabilities",
      identityCustody: "doctor_identity_custody",
      create: "doctor_create_probe",
      agreement1: "doctor_run_agreement",
      agreement2: "doctor_run_agreement",
      cancel: "doctor_run_agreement",
      restart: "doctor_run_agreement",
      pairingStorage: "doctor_pairing_storage",
      scanPairingOffer: "scan_pairing_offer",
      pairPhone: "pair_phone",
      unwrapPhone: "unwrap_phone",
      cleanup: "doctor_cleanup",
    };
    if (!action || !commands[action]) return;
    void runDoctor(commands[action], action).catch(() => {
      if (action === "scanPairingOffer") {
        showReport(action, {
          scannerStarted: false,
          messageVerified: false,
          desktopLabel: null,
          offerFingerprint: null,
          framesAccepted: 0,
          errorCategory: "bridge_unavailable",
        });
        return;
      }
      if (action === "pairPhone") {
        showReport(action, {
          paired: false,
          desktopLabel: null,
          transcriptFingerprint: null,
          errorCategory: "bridge_unavailable",
        });
        return;
      }
      if (action === "unwrapPhone") {
        showReport(action, {
          authenticated: false,
          responseDisplayed: false,
          requestFingerprint: null,
          errorCategory: "bridge_unavailable",
        });
        return;
      }
      if (action === "pairingStorage") {
        showReport(action, {
          noBackupStorage: false,
          qrFragmented: false,
          qrOutOfOrderReassembled: false,
          qrCorruptionRejected: false,
          qrTimeoutRejected: false,
          transcriptVerified: false,
          fingerprintMismatchRejected: false,
          cancellationRejected: false,
          confirmationCommitted: false,
          duplicateConfirmationRejected: false,
          atomicStateCreated: false,
          verifiedBeforeConsume: false,
          replayRejectedAfterReopen: false,
          wrongScopeRejected: false,
          missingStateRejectedAfterDelete: false,
          cleanupComplete: false,
          errorCategory: "bridge_unavailable",
        });
        return;
      }
      if (action === "identityCustody") {
        showReport(action, {
          noBackupStorage: false,
          identityStrongBox: false,
          identityAgreeOnly: false,
          identityAuthPerUse: false,
          identityBiometricStrong: false,
          signingStrongBox: false,
          signingPurposeSignOnly: false,
          signingNoUserAuth: false,
          privateKeysNonExportable: false,
          keysDistinct: false,
          metadataBound: false,
          reopened: false,
          duplicateRejected: false,
          preparingRecovered: false,
          cleanupComplete: false,
          errorCategory: "bridge_unavailable",
        });
        return;
      }
      showReport(action, {
        authenticated: false,
        agreementMatch: false,
        responseEnvelopeMatch: false,
        errorCategory: "bridge_unavailable",
      });
    });
  });
});

copyButton?.addEventListener("click", () => {
  if (Object.keys(doctorReports).length === 0) return;
  void navigator.clipboard.writeText(JSON.stringify(doctorReports, null, 2));
});

invoke<ProjectStatus>("project_status")
  .then((status) => {
    renderStatus(status);
    if (doctorElement) doctorElement.hidden = !status.doctorEnabled;
    if (status.doctorEnabled) {
      void runDoctor<CapabilityReport>("doctor_capabilities").catch(() => undefined);
    }
  })
  .catch(() => {
    renderStatus({
      stage: "unavailable",
      protocolVersion: 1,
      qrTransport: "disabled",
      bleTransport: "disabled",
      keyBackend: "disabled",
      doctorEnabled: false,
    });
  });
