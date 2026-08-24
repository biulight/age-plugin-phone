import { invoke } from "@tauri-apps/api/core";
import "./styles.css";

interface ProjectStatus {
  stage: string;
  protocolVersion: number;
  qrTransport: string;
  bleTransport: string;
  keyBackend: string;
}

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
      Scaffold only. Pairing and secret operations are disabled until the protocol is reviewed.
    </p>
  </section>
`;

const statusElement = document.querySelector<HTMLElement>("#status");

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

invoke<ProjectStatus>("project_status")
  .then(renderStatus)
  .catch(() => {
    renderStatus({
      stage: "unavailable",
      protocolVersion: 1,
      qrTransport: "disabled",
      bleTransport: "disabled",
      keyBackend: "disabled",
    });
  });

