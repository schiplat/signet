import { passkeyLoginFinish, passkeyLoginStart, passkeyRegisterFinish, passkeyRegisterStart } from "@/lib/api";
import type { PublicUser } from "@/lib/api";

// --- base64url helpers (RFC 4648 §5, unpadded) ---

function bufToB64url(buf: ArrayBuffer | Uint8Array | null | undefined): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf ?? new ArrayBuffer(0));
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlToBuf(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const binary = atob(b64 + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function b64urlToBufUnsafe(s: unknown): Uint8Array {
  return b64urlToBuf(String(s));
}

/** Enroll a new passkey for the current (authenticated) user. */
export async function enrollPasskey(name: string): Promise<void> {
  const { token, challenge } = await passkeyRegisterStart();
  const pk = (challenge as { publicKey?: Record<string, unknown> }).publicKey ?? {};

  const publicKey: PublicKeyCredentialCreationOptions = {
    rp: pk.rp as PublicKeyCredentialRpEntity,
    user: {
      ...(pk.user as Record<string, unknown>),
      id: b64urlToBufUnsafe((pk.user as { id: unknown }).id),
    } as unknown as PublicKeyCredentialUserEntity,
    challenge: b64urlToBufUnsafe(pk.challenge),
    pubKeyCredParams: pk.pubKeyCredParams as PublicKeyCredentialParameters[],
    timeout: pk.timeout as number | undefined,
    attestation: pk.attestation as AttestationConveyancePreference | undefined,
    excludeCredentials: ((pk.excludeCredentials as Array<Record<string, unknown>>) ?? []).map(
      (c) => ({ ...c, id: b64urlToBufUnsafe(c.id) }) as unknown as PublicKeyCredentialDescriptor,
    ),
    authenticatorSelection: pk.authenticatorSelection as AuthenticatorSelectionCriteria,
    extensions: pk.extensions as AuthenticationExtensionsClientInputs,
  };

  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error("Passkey registration cancelled");

  const response = cred.response as AuthenticatorAttestationResponse;
  await passkeyRegisterFinish({
    token,
    name,
    credential: {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      response: {
        clientDataJSON: bufToB64url(response.clientDataJSON),
        attestationObject: bufToB64url(response.attestationObject),
      },
      type: cred.type,
      extensions: cred.getClientExtensionResults(),
    },
  });
}

/** Sign in with a passkey. Returns the logged-in user. */
export async function loginWithPasskey(email: string, returnTo?: string): Promise<PublicUser> {
  const { token, challenge } = await passkeyLoginStart(email);
  const pk = (challenge as { publicKey?: Record<string, unknown> }).publicKey ?? {};

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: b64urlToBufUnsafe(pk.challenge),
    timeout: pk.timeout as number | undefined,
    rpId: pk.rpId as string | undefined,
    allowCredentials: ((pk.allowCredentials as Array<Record<string, unknown>>) ?? []).map(
      (c) => ({ ...c, id: b64urlToBufUnsafe(c.id) }) as unknown as PublicKeyCredentialDescriptor,
    ),
    userVerification: pk.userVerification as UserVerificationRequirement | undefined,
    extensions: pk.extensions as AuthenticationExtensionsClientInputs,
  };

  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error("Passkey sign-in cancelled");

  const response = cred.response as AuthenticatorAssertionResponse;
  const res = await passkeyLoginFinish({
    token,
    return_to: returnTo,
    credential: {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      response: {
        clientDataJSON: bufToB64url(response.clientDataJSON),
        authenticatorData: bufToB64url(response.authenticatorData),
        signature: bufToB64url(response.signature),
        userHandle: response.userHandle ? bufToB64url(response.userHandle) : null,
      },
      type: cred.type,
      extensions: cred.getClientExtensionResults(),
    },
  });
  return res.user;
}
