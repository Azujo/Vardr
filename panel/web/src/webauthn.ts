// SPDX-License-Identifier: AGPL-3.0-or-later

// Klucze bezpieczeństwa i passkeys (WebAuthn): zamiana opcji z serwera
// (base64url w JSON) na obiekty przeglądarki i odpowiedzi z powrotem.

/* eslint-disable @typescript-eslint/no-explicit-any */

export function webauthnSupported(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential && window.isSecureContext;
}

function fromB64(s: string): ArrayBuffer {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function toB64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const descriptors = (list: any[] | undefined) => (list ?? []).map((d) => ({ ...d, id: fromB64(d.id) }));

// Logowanie: podpis wyzwania kluczem.
export async function getAssertion(publicKey: any): Promise<{
  id: string;
  client_data_json: string;
  authenticator_data: string;
  signature: string;
}> {
  const cred = (await navigator.credentials.get({
    publicKey: { ...publicKey, challenge: fromB64(publicKey.challenge), allowCredentials: descriptors(publicKey.allowCredentials) },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("no credential");
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: toB64(cred.rawId),
    client_data_json: toB64(r.clientDataJSON),
    authenticator_data: toB64(r.authenticatorData),
    signature: toB64(r.signature),
  };
}

// Rejestracja nowego klucza.
export async function createCredential(publicKey: any): Promise<{ client_data_json: string; attestation_object: string }> {
  const cred = (await navigator.credentials.create({
    publicKey: {
      ...publicKey,
      challenge: fromB64(publicKey.challenge),
      user: { ...publicKey.user, id: fromB64(publicKey.user.id) },
      excludeCredentials: descriptors(publicKey.excludeCredentials),
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("no credential");
  const r = cred.response as AuthenticatorAttestationResponse;
  return { client_data_json: toB64(r.clientDataJSON), attestation_object: toB64(r.attestationObject) };
}

// Anulowanie przez użytkownika albo upłynięcie czasu (NotAllowedError).
export function webauthnCancelled(err: unknown): boolean {
  return err instanceof DOMException && (err.name === "NotAllowedError" || err.name === "AbortError");
}
