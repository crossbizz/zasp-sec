"use client";

import { useEffect, useRef, useState } from "react";
import { APIProductError } from "../../../apps/web/api/client";
import type { EndpointFleetAPI } from "../../../apps/web/api/endpoint-fleet";
import type { EndpointDevice, EndpointSigned } from "../../../apps/web/api/generated";
import { Button, Field } from "../../components/ui";

type Action = "publish" | "rotate" | "retire";
type Policy = { envelope: EndpointSigned; revision: number; mode: "monitor" | "enforce" };
const productID = /^pid_[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const maxFileBytes = 48 * 1024;
const actionLabels: Record<Action, string> = {
  publish: "Publish signed policy",
  rotate: "Rotate device credential",
  retire: "Retire device",
};

// Only the two base64 fields emitted by the endpoint signer may leave the browser.
// Reject repeated fields before JSON parsing can collapse them.
function previewPolicy(source: string, row: EndpointDevice, scope: string | undefined): Policy {
  const match =
    /^\s*\{\s*"(payload|signature)"\s*:\s*"([A-Za-z0-9+/=]+)"\s*,\s*"(payload|signature)"\s*:\s*"([A-Za-z0-9+/=]+)"\s*\}\s*$/.exec(
      source,
    );
  if (!match || match[1] === match[3] || !scope) throw Error();
  const envelope =
    match[1] === "payload"
      ? { payload: match[2], signature: match[4] }
      : { payload: match[4], signature: match[2] };
  const payload = atob(envelope.payload),
    signature = atob(envelope.signature);
  if (
    payload.length > 32768 ||
    signature.length !== 64 ||
    btoa(payload) !== envelope.payload ||
    btoa(signature) !== envelope.signature
  )
    throw Error();
  // The server verifies the original signed bytes against the registered issuer.
  const policy = JSON.parse(payload);
  const binding = policy?.binding;
  if (
    !binding ||
    !["zasp.endpoint-policy.v1", "zasp.endpoint-policy.v2"].includes(policy.audience) ||
    [binding.organization_id, binding.workspace_id, binding.environment_id].join("/") !== scope ||
    binding.device_id !== row.id ||
    binding.credential_generation !== row.credential_generation ||
    !Number.isSafeInteger(policy.revision) ||
    policy.revision <= row.policy_revision ||
    (policy.mode !== "monitor" && policy.mode !== "enforce")
  )
    throw Error();
  return { envelope, revision: policy.revision, mode: policy.mode };
}

type Props = {
  api: EndpointFleetAPI;
  row: EndpointDevice;
  scope?: string;
  fresh: boolean;
  reauthenticate(): void;
  refresh(): Promise<void>;
  notify(text: string): void;
  setBusy(value: boolean): void;
};
export function DeviceActions({ api, row, scope, fresh, reauthenticate, refresh, notify, setBusy }: Props) {
  const [action, setAction] = useState<Action | null>(null),
    [sending, setSending] = useState(false);
  const [credential, setCredential] = useState(""),
    [publicKey, setPublicKey] = useState("");
  const [file, setFile] = useState<File | null>(null),
    [policy, setPolicy] = useState<Policy | null>(null);
  const [fileError, setFileError] = useState("");
  const request = useRef<AbortController | null>(null);
  const retryKey = useRef("");
  useEffect(
    () => () => {
      if (request.current) {
        request.current.abort();
        setBusy(false);
      }
    },
    [setBusy],
  );
  useEffect(() => {
    if (!file || file.size === 0 || file.size > maxFileBytes) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        setPolicy(previewPolicy(String(reader.result), row, scope));
      } catch {
        setFileError(
          "Choose a signed policy for this Environment, device, credential generation and a newer revision.",
        );
      }
    };
    reader.onerror = () => setFileError("The signed envelope could not be read.");
    reader.readAsText(file);
    return () => {
      reader.onload = reader.onerror = null;
      reader.abort();
    };
  }, [file, row, scope]);

  function chooseFile(value: File | null) {
    retryKey.current = "";
    setFile(value);
    setPolicy(null);
    setFileError(
      value && (value.size === 0 || value.size > maxFileBytes)
        ? "Choose a nonempty signed envelope of up to 48 KiB."
        : "",
    );
  }
  function start(value: Action | null) {
    if (request.current) return;
    if (value && !fresh) {
      reauthenticate();
      return;
    }
    chooseFile(null);
    setCredential("");
    setPublicKey("");
    notify("");
    setAction(value);
  }
  const validRotation =
    productID.test(credential) && /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(publicKey);
  async function submit() {
    if (
      !action ||
      !fresh ||
      request.current ||
      (action === "publish" && !policy) ||
      (action === "rotate" && !validRotation)
    )
      return;
    const key = (retryKey.current ||= crypto.randomUUID());
    const controller = new AbortController();
    request.current = controller;
    setSending(true);
    setBusy(true);
    notify("");
    let reload = false;
    try {
      if (action === "publish" && policy) {
        const result = await api.publish(row, policy.envelope, policy.revision, key, controller.signal);
        if (!controller.signal.aborted)
          notify(
            `Policy revision ${result.policy_revision} assigned. Check the device’s reported revision for acknowledgment.`,
          );
      } else if (action === "rotate") {
        const result = await api.rotate(
          row,
          { credential_id: credential, device_public_key: publicKey },
          key,
          controller.signal,
        );
        if (!controller.signal.aborted)
          notify(
            `Credential generation ${result.credential_generation} assigned. Device check-in with the replacement credential is pending.`,
          );
      } else {
        await api.retire(row, key, controller.signal);
        if (!controller.signal.aborted) notify("Device retired. MDM removal is a separate step.");
      }
      reload = true;
    } catch (err) {
      if (!controller.signal.aborted) {
        reload = err instanceof APIProductError && [409, 412].includes(err.status);
        notify(
          reload
            ? "The current device state conflicts with this request. Review the refreshed device before trying again."
            : "The change could not be confirmed. Check your permissions and inputs, then retry the same request.",
        );
      }
    } finally {
      if (!controller.signal.aborted) {
        request.current = null;
        setSending(false);
        setBusy(false);
      }
    }
    if (reload && !controller.signal.aborted) {
      retryKey.current = "";
      setAction(null);
      await refresh();
    }
  }

  if (!action)
    return (
      <div className="page-actions">
        {(["publish", "rotate", "retire"] as const).map((value) => (
          <Button key={value} onClick={() => start(value)}>
            {actionLabels[value]}
          </Button>
        ))}
      </div>
    );
  return (
    <section aria-label={actionLabels[action]}>
      <h3>{actionLabels[action]}</h3>
      {action === "publish" && (
        <>
          <p>
            Select the JSON envelope from your endpoint policy signer. The server verifies the signature and
            device binding before assigning the revision. For ticket canaries, promotion and rollback, use
            Staging ticket cohort.
          </p>
          <label className="field">
            Signed policy envelope
            <input
              type="file"
              accept=".json,application/json"
              disabled={sending}
              onChange={(e) => chooseFile(e.target.files?.[0] ?? null)}
            />
          </label>
          {fileError && <p role="alert">{fileError}</p>}
          {policy && (
            <p>
              Revision {policy.revision} · {policy.mode} mode · credential generation{" "}
              {row.credential_generation}.
            </p>
          )}
        </>
      )}
      {action === "rotate" && (
        <>
          <p>
            Provision a dedicated replacement endpoint credential and device signing key through MDM. Rotation
            removes the existing binding and requires a new check-in and signed policy for this generation.
          </p>
          <Field
            label="Replacement endpoint credential ID"
            value={credential}
            maxLength={40}
            disabled={sending}
            onChange={(e) => {
              retryKey.current = "";
              setCredential(e.target.value.trim());
            }}
          />
          <Field
            label="Replacement device public key"
            value={publicKey}
            maxLength={44}
            disabled={sending}
            onChange={(e) => {
              retryKey.current = "";
              setPublicKey(e.target.value.trim());
            }}
          />
        </>
      )}
      {action === "retire" && (
        <p>
          Revoke this device’s server access? Historical observations remain available to authorized
          reviewers.
        </p>
      )}
      {fresh ? (
        <Button
          disabled={sending || (action === "publish" && !policy) || (action === "rotate" && !validRotation)}
          onClick={() => void submit()}
        >
          {action === "publish"
            ? policy
              ? `Publish revision ${policy.revision}`
              : "Publish revision"
            : action === "rotate"
              ? "Confirm credential rotation"
              : "Confirm retirement"}
        </Button>
      ) : (
        <Button onClick={reauthenticate}>Reauthenticate</Button>
      )}{" "}
      <Button disabled={sending} onClick={() => start(null)}>
        Cancel
      </Button>
    </section>
  );
}
