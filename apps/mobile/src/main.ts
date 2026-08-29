import { invoke } from "@tauri-apps/api/core";
import "./styles.css";

interface ProjectStatus { stage: string; protocolVersion: number; bleTransport: string; doctorEnabled: boolean; }
interface PairedDesktopSummary { handle: string; displayLabel: string; transcriptFingerprint: string; deletionPending: boolean; }
interface IdentityStatusReport {
  state: "ready" | "not_configured" | "deletion_pending" | "unavailable" | "unsupported";
  publicRecipient: string | null; pairedDesktops: PairedDesktopSummary[];
  recoveryRequired: boolean; errorCategory: string | null;
}
interface PhonePairingReport { paired: boolean; transcriptFingerprint: string | null; errorCategory: string | null; }
interface PhoneUnwrapReport { authenticated: boolean; requestFingerprint: string | null; errorCategory: string | null; }
interface LifecycleReport { completed: boolean; state: string; errorCategory: string | null; }

const root = document.querySelector<HTMLElement>("#app");
if (!root) throw new Error("missing application root");
root.innerHTML = `
<main class="shell">
  <header class="hero"><div><p class="eyebrow">AGE IDENTITY · ALPHA</p><h1>Phone identity</h1></div><span class="state state-loading" id="identity-state">Loading</span></header>
  <p class="summary">Your long-term identity stays in StrongBox. Every file-key unwrap needs a fresh phone biometric.</p>
  <section class="card"><div class="card-heading"><div><p class="kicker">IDENTITY</p><h2>Public recipient</h2></div><button class="quiet compact" id="copy-recipient" hidden>Copy</button></div><p class="recipient empty" id="recipient">Checking this phone…</p><button class="primary full" id="create-identity" hidden>Create StrongBox identity</button></section>
  <section class="card"><div class="card-heading"><div><p class="kicker">ONE-SHOT ACTIONS</p><h2>Pair or approve</h2></div></div><p class="card-copy">Developer USB unwrap opens this app automatically. Pairing remains explicit, and QR is the offline fallback using the same authenticated protocol.</p><div class="action-grid"><button class="primary" data-product-action="pair_phone_usb">Pair · USB</button><button data-product-action="pair_phone">Pair · QR</button><button data-product-action="unwrap_phone">Approve · QR</button></div><p class="result" id="operation-result" aria-live="polite">No operation is active.</p></section>
  <section class="card"><div class="card-heading"><div><p class="kicker">ACCESS</p><h2>Paired desktops</h2></div><span class="count" id="desktop-count">0</span></div><div class="desktop-list" id="desktop-list"><p class="empty">No paired desktops.</p></div></section>
  <section class="card recovery"><p class="kicker">RECOVERY</p><h2>Keep an independent recipient</h2><p class="card-copy">Important data must also be encrypted to a recovery recipient that does not depend on this phone or the paired desktop TPM. Replacing either device does not migrate old ciphertext.</p></section>
  <details class="card danger-zone"><summary>Identity deletion and recovery guidance</summary><p>Deleting the app or identity permanently removes access through this phone. Ciphertexts are not deleted. Verify recovery first.</p><button class="danger full" id="delete-identity">Delete phone identity…</button></details>
  <details class="card doctor" id="doctor" hidden><summary>Development Doctor</summary><p class="card-copy">Synthetic diagnostics only. Reports exclude paths, aliases, protocol payloads, QR contents, and key material.</p><div class="doctor-actions"><button data-doctor="doctor_capabilities">Capabilities</button><button data-doctor="doctor_identity_custody">Key custody</button><button data-doctor="doctor_pairing_storage">Pairing storage</button><button data-doctor="doctor_create_probe">Create probe</button><button data-doctor="doctor_run_agreement">Run unwrap probe</button><button class="danger" data-doctor="doctor_cleanup">Delete probe</button></div><pre id="doctor-report">No diagnostic has run.</pre></details>
  <footer id="build-status">Protocol status unavailable.</footer>
</main>`;

const byId = <T extends HTMLElement>(id: string): T | null => document.querySelector<T>(`#${id}`);
const stateBadge = byId<HTMLElement>("identity-state");
const recipient = byId<HTMLElement>("recipient");
const copyRecipient = byId<HTMLButtonElement>("copy-recipient");
const createIdentity = byId<HTMLButtonElement>("create-identity");
const desktopList = byId<HTMLElement>("desktop-list");
const desktopCount = byId<HTMLElement>("desktop-count");
const operationResult = byId<HTMLElement>("operation-result");
const deleteIdentity = byId<HTMLButtonElement>("delete-identity");
const doctor = byId<HTMLElement>("doctor");
const doctorReport = byId<HTMLElement>("doctor-report");
const buildStatus = byId<HTMLElement>("build-status");
const productButtons = Array.from(document.querySelectorAll<HTMLButtonElement>("[data-product-action]"));
const doctorButtons = Array.from(document.querySelectorAll<HTMLButtonElement>("[data-doctor]"));
let currentStatus: IdentityStatusReport | null = null;
let busy = false;

function setBusy(value: boolean): void {
  busy = value;
  [...productButtons, ...doctorButtons].forEach((button) => { button.disabled = value; });
  if (createIdentity) createIdentity.disabled = value;
  if (deleteIdentity) deleteIdentity.disabled = value;
}

function shortFingerprint(value: string): string {
  return `${value.slice(0, 16)} ${value.slice(16, 32)}\n${value.slice(32, 48)} ${value.slice(48)}`;
}

function renderIdentity(status: IdentityStatusReport): void {
  currentStatus = status;
  const labels: Record<string, string> = { ready: "Ready", not_configured: "Not configured", deletion_pending: "Deletion pending", unavailable: "Unavailable", unsupported: "Unsupported" };
  if (stateBadge) { stateBadge.textContent = labels[status.state] ?? "Unavailable"; stateBadge.className = `state state-${status.state}`; }
  if (recipient) {
    recipient.textContent = status.publicRecipient ?? (status.state === "not_configured" ? "Create a hardware-backed identity to begin." : "Identity unavailable. Use recovery; no fallback key will be created.");
    recipient.classList.toggle("empty", !status.publicRecipient);
  }
  if (copyRecipient) copyRecipient.hidden = !status.publicRecipient;
  if (createIdentity) createIdentity.hidden = status.state !== "not_configured";
  productButtons.forEach((button) => { button.disabled = busy || status.state !== "ready"; });
  if (deleteIdentity) deleteIdentity.disabled = busy || !["ready", "deletion_pending"].includes(status.state);
  renderDesktops(status.pairedDesktops);
}

function renderDesktops(desktops: PairedDesktopSummary[]): void {
  if (desktopCount) desktopCount.textContent = String(desktops.length);
  if (!desktopList) return;
  desktopList.replaceChildren();
  if (desktops.length === 0) { const empty = document.createElement("p"); empty.className = "empty"; empty.textContent = "No paired desktops."; desktopList.append(empty); return; }
  desktops.forEach((desktop) => {
    const row = document.createElement("article"); row.className = "desktop";
    const text = document.createElement("div");
    const label = document.createElement("h3"); label.textContent = desktop.displayLabel || "Unnamed desktop";
    const warning = document.createElement("span"); warning.textContent = "Untrusted display label"; warning.className = "hint";
    const fingerprint = document.createElement("code"); fingerprint.textContent = shortFingerprint(desktop.transcriptFingerprint);
    text.append(label, warning, fingerprint);
    const revoke = document.createElement("button"); revoke.className = "danger compact"; revoke.textContent = desktop.deletionPending ? "Finish cleanup" : "Revoke"; revoke.disabled = busy;
    revoke.addEventListener("click", () => void revokeDesktop(desktop.handle));
    row.append(text, revoke); desktopList.append(row);
  });
}

async function refreshIdentity(): Promise<void> { renderIdentity(await invoke<IdentityStatusReport>("plugin:phone-identity|identity_status")); }

async function runProduct(command: string): Promise<void> {
  if (busy) return; setBusy(true); if (operationResult) operationResult.textContent = "Waiting for the native phone flow…";
  try {
    if (command.startsWith("pair")) {
      const report = await invoke<PhonePairingReport>(`plugin:phone-identity|${command}`);
      if (operationResult) operationResult.textContent = report.paired ? `Paired. Transcript ${report.transcriptFingerprint ?? "verified"}.` : `Pairing stopped: ${report.errorCategory ?? "not completed"}.`;
    } else {
      const report = await invoke<PhoneUnwrapReport>(`plugin:phone-identity|${command}`);
      if (operationResult) operationResult.textContent = report.authenticated ? `Approved one request: ${report.requestFingerprint ?? "verified"}.` : `Approval stopped: ${report.errorCategory ?? "not completed"}.`;
    }
  } catch { if (operationResult) operationResult.textContent = "Native operation unavailable."; }
  finally { setBusy(false); await refreshIdentity().catch(() => undefined); }
}

async function revokeDesktop(handle: string): Promise<void> {
  if (busy) return; setBusy(true);
  try {
    const report = await invoke<LifecycleReport>("plugin:phone-identity|revoke_pairing", { handle });
    if (operationResult) operationResult.textContent = report.completed ? "Desktop revoked. Old ciphertext may need recovery and re-encryption." : `Revocation stopped: ${report.errorCategory ?? "not completed"}.`;
  } finally { setBusy(false); await refreshIdentity().catch(() => undefined); }
}

productButtons.forEach((button) => button.addEventListener("click", () => { const action = button.dataset.productAction; if (action) void runProduct(action); }));
createIdentity?.addEventListener("click", async () => { if (busy) return; setBusy(true); try { renderIdentity(await invoke<IdentityStatusReport>("plugin:phone-identity|provision_identity")); } finally { setBusy(false); } });
copyRecipient?.addEventListener("click", () => { if (currentStatus?.publicRecipient) void navigator.clipboard.writeText(currentStatus.publicRecipient); });
deleteIdentity?.addEventListener("click", async () => {
  if (busy) return; setBusy(true);
  try { const report = await invoke<LifecycleReport>("plugin:phone-identity|delete_identity"); if (operationResult) operationResult.textContent = report.completed ? "Identity deleted. Recover old ciphertext through an independent recipient." : `Deletion stopped: ${report.errorCategory ?? "not completed"}.`; }
  finally { setBusy(false); await refreshIdentity().catch(() => undefined); }
});
doctorButtons.forEach((button) => button.addEventListener("click", async () => {
  const command = button.dataset.doctor; if (!command || busy) return; setBusy(true);
  try { const report = await invoke<Record<string, unknown>>(`plugin:phone-identity|${command}`); if (doctorReport) doctorReport.textContent = JSON.stringify(report, null, 2); }
  catch { if (doctorReport) doctorReport.textContent = "Diagnostic unavailable."; } finally { setBusy(false); }
}));

Promise.all([invoke<ProjectStatus>("project_status"), refreshIdentity()]).then(([project]) => {
  if (doctor) doctor.hidden = !project.doctorEnabled;
  if (buildStatus) buildStatus.textContent = `Experimental protocol v${project.protocolVersion} · ${project.stage} · BLE ${project.bleTransport}`;
}).catch(() => renderIdentity({ state: "unavailable", publicRecipient: null, pairedDesktops: [], recoveryRequired: true, errorCategory: "bridge_unavailable" }));
