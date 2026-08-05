// Supabase Edge Function "fritzbox-sperrliste"
//
// Sperrt Rufnummern in einer FRITZ!Box und liest die Sperrliste aus.
// Nutzt die offizielle TR-064-Schnittstelle, Dienst X_AVM-DE_OnTel:
//   GetCallBarringList        -> alle gesperrten Nummern
//   SetCallBarringEntry       -> Nummer sperren
//   DeleteCallBarringEntryUID -> Sperre aufheben
//
// Benoetigte Secrets:
//   FRITZBOX_URL       Basis-URL der TR-064-Schnittstelle, z.B. https://fritzbox.example.org/tr064
//   FRITZBOX_USER      FRITZ!Box-Benutzer mit dem Recht "Telefonie"
//   FRITZBOX_PASSWORD  dessen Kennwort
//   TOOL_ACCESS_KEY    gemeinsames Geheimnis, das das Frontend mitschickt

import { crypto as stdCrypto } from "jsr:@std/crypto@1/crypto";
import { encodeHex } from "jsr:@std/encoding@1/hex";

const FB_URL = (Deno.env.get("FRITZBOX_URL") ?? "").replace(/\/+$/, "");
const FB_USER = Deno.env.get("FRITZBOX_USER") ?? "";
const FB_PASS = Deno.env.get("FRITZBOX_PASSWORD") ?? "";
const TOOL_KEY = Deno.env.get("TOOL_ACCESS_KEY") ?? "";

const SERVICE = "urn:dslforum-org:service:X_AVM-DE_OnTel:1";
const CONTROL_PATH = "/upnp/control/x_contact";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type, x-tool-key",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

// ---------------------------------------------------------------- Hilfsmittel

class FritzError extends Error {
  constructor(message: string, readonly status = 502) {
    super(message);
  }
}

async function hash(algo: "MD5" | "SHA-256", value: string): Promise<string> {
  const data = new TextEncoder().encode(value);
  return encodeHex(new Uint8Array(await stdCrypto.subtle.digest(algo, data)));
}

function escapeXml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function unescapeXml(value: string): string {
  return value
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function tagValue(xml: string, name: string): string | null {
  const match = xml.match(new RegExp(`<${name}[^>]*>([\\s\\S]*?)</${name}>`));
  return match ? match[1] : null;
}

/** Nur die Ziffern (plus fuehrendes +) — fuer Dublettenvergleich. */
function normalizeNumber(value: string): string {
  const cleaned = value.replace(/[^\d+*#]/g, "");
  return cleaned.startsWith("+49") ? "0" + cleaned.slice(3) : cleaned;
}

// ------------------------------------------------------------- Digest-Auth

function parseChallenge(header: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([a-zA-Z0-9_-]+)=(?:"([^"]*)"|([^,\s]+))/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(header))) out[m[1].toLowerCase()] = m[2] ?? m[3];
  return out;
}

async function buildAuthorization(
  challenge: string,
  method: string,
  uri: string,
): Promise<string> {
  const p = parseChallenge(challenge);
  const realm = p.realm ?? "";
  const nonce = p.nonce ?? "";
  const qop = (p.qop ?? "").split(",")[0].trim();
  const algo: "MD5" | "SHA-256" = (p.algorithm ?? "MD5").toUpperCase().startsWith("SHA-256")
    ? "SHA-256"
    : "MD5";

  const ha1 = await hash(algo, `${FB_USER}:${realm}:${FB_PASS}`);
  const ha2 = await hash(algo, `${method}:${uri}`);
  const cnonce = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
  const nc = "00000001";
  const response = qop
    ? await hash(algo, `${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
    : await hash(algo, `${ha1}:${nonce}:${ha2}`);

  let out = `Digest username="${FB_USER}", realm="${realm}", nonce="${nonce}", ` +
    `uri="${uri}", response="${response}"`;
  if (p.opaque) out += `, opaque="${p.opaque}"`;
  if (p.algorithm) out += `, algorithm=${p.algorithm}`;
  if (qop) out += `, qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
  return out;
}

// ------------------------------------------------------------------- SOAP

async function soap(action: string, inner: string): Promise<string> {
  if (!FB_URL || !FB_USER || !FB_PASS) {
    throw new FritzError(
      "Die FRITZ!Box-Zugangsdaten sind nicht hinterlegt (Secrets FRITZBOX_URL, " +
        "FRITZBOX_USER, FRITZBOX_PASSWORD).",
      500,
    );
  }

  const url = FB_URL + CONTROL_PATH;
  const envelope = `<?xml version="1.0" encoding="utf-8"?>` +
    `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ` +
    `s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
    `<s:Body>${inner}</s:Body></s:Envelope>`;
  const headers: Record<string, string> = {
    "Content-Type": 'text/xml; charset="utf-8"',
    "SoapAction": `${SERVICE}#${action}`,
  };

  let res: Response;
  try {
    res = await fetch(url, { method: "POST", headers, body: envelope });
  } catch (err) {
    throw new FritzError(
      `Die FRITZ!Box ist unter ${FB_URL} nicht erreichbar (${err instanceof Error ? err.message : err}).`,
    );
  }

  // Die Box sieht durch den Reverse Proxy je nach StripPrefix-Einstellung einen
  // anderen Pfad als wir anfragen. Beide Varianten fuer den Digest-URI probieren.
  const uriCandidates = [new URL(url).pathname, CONTROL_PATH];
  for (const uri of uriCandidates) {
    if (res.status !== 401) break;
    const challenge = res.headers.get("www-authenticate");
    await res.body?.cancel();
    if (!challenge) break;
    const authorization = await buildAuthorization(challenge, "POST", uri);
    res = await fetch(url, {
      method: "POST",
      headers: { ...headers, Authorization: authorization },
      body: envelope,
    });
  }

  const text = await res.text();

  if (res.status === 401) {
    throw new FritzError(
      "Die FRITZ!Box hat die Anmeldung abgelehnt. Benutzername/Kennwort pruefen — " +
        "der Benutzer braucht das Recht \"Telefonie\".",
      401,
    );
  }

  if (!res.ok) {
    const code = tagValue(text, "errorCode");
    throw new FritzError(describeSoapError(code, res.status, text), 502);
  }

  return text;
}

function describeSoapError(code: string | null, status: number, body: string): string {
  switch (code) {
    case "504":
      return "Die FRITZ!Box verlangt eine verschluesselte Verbindung (SSL). Der Reverse " +
        "Proxy muss auf https://<Box-IP>:49443 zeigen, nicht auf Port 49000.";
    case "866":
      return "Die FRITZ!Box verlangt eine Zwei-Faktor-Bestaetigung fuer diese Aenderung. " +
        "Bitte in der FRITZ!Box unter System > FRITZ!Box-Benutzer die Bestaetigung " +
        "fuer diesen Benutzer pruefen.";
    case "713":
    case "714":
      return "Der gesuchte Eintrag existiert nicht (mehr).";
    case "600":
    case "402":
      return "Die FRITZ!Box hat die uebergebenen Daten abgelehnt (ungueltige Rufnummer?).";
    case "820":
      return "Interner Fehler in der FRITZ!Box.";
    default: {
      const description = tagValue(body, "errorDescription");
      return `Die FRITZ!Box hat mit HTTP ${status}${code ? ` / Code ${code}` : ""} geantwortet` +
        `${description ? `: ${description}` : ""}.`;
    }
  }
}

// -------------------------------------------------------- Fachliche Aktionen

interface BarredEntry {
  uid: string;
  name: string;
  number: string;
}

function parseContacts(xml: string): BarredEntry[] {
  const entries: BarredEntry[] = [];
  for (const block of xml.match(/<contact>[\s\S]*?<\/contact>/g) ?? []) {
    const numbers = [...block.matchAll(/<number[^>]*>([\s\S]*?)<\/number>/g)]
      .map((m) => unescapeXml(m[1]).trim())
      .filter(Boolean);
    if (!numbers.length) continue;
    const name = unescapeXml(tagValue(block, "realName") ?? "").trim();
    const uid = (tagValue(block, "uniqueid") ?? "").trim();
    for (const number of numbers) entries.push({ uid, name, number });
  }
  return entries;
}

/** Fallback, falls die Telefonbuch-URL nicht durch den Proxy erreichbar ist. */
async function listByIteration(): Promise<BarredEntry[]> {
  const entries: BarredEntry[] = [];
  for (let index = 0; index < 300; index++) {
    let xml: string;
    try {
      xml = await soap(
        "GetCallBarringEntry",
        `<u:GetCallBarringEntry xmlns:u="${SERVICE}">` +
          `<NewPhonebookEntryID>${index}</NewPhonebookEntryID>` +
          `</u:GetCallBarringEntry>`,
      );
    } catch {
      break; // 713 "invalid array index" => Ende der Liste
    }
    const data = tagValue(xml, "NewPhonebookEntryData");
    if (!data) break;
    entries.push(...parseContacts(unescapeXml(data)));
  }
  return entries;
}

async function listBarred(): Promise<BarredEntry[]> {
  const xml = await soap("GetCallBarringList", `<u:GetCallBarringList xmlns:u="${SERVICE}"/>`);
  const rawUrl = tagValue(xml, "NewPhonebookURL");

  if (rawUrl) {
    // Die Box liefert ihre interne Adresse zurueck — auf den Reverse Proxy umschreiben.
    try {
      const original = new URL(unescapeXml(rawUrl).trim());
      const proxied = FB_URL + original.pathname + original.search;
      const res = await fetch(proxied);
      if (res.ok) {
        const body = await res.text();
        if (body.includes("<contact>")) return parseContacts(body);
      } else {
        await res.body?.cancel();
      }
    } catch {
      // faellt unten auf die Einzelabfrage zurueck
    }
  }

  return await listByIteration();
}

async function blockNumber(number: string, name: string): Promise<BarredEntry> {
  const existing = await listBarred();
  const wanted = normalizeNumber(number);
  const duplicate = existing.find((e) => normalizeNumber(e.number) === wanted);
  if (duplicate) {
    throw new FritzError(
      `Die Rufnummer ${duplicate.number} ist bereits gesperrt` +
        `${duplicate.name ? ` (${duplicate.name})` : ""}.`,
      409,
    );
  }

  const entry = `<?xml version="1.0" encoding="utf-8"?>` +
    `<contact><category>0</category>` +
    `<person><realName>${escapeXml(name)}</realName></person>` +
    `<telephony nid="1"><number type="home" prio="0" id="0">${escapeXml(number)}</number></telephony>` +
    `<services /><setup /><uniqueid /></contact>`;

  const xml = await soap(
    "SetCallBarringEntry",
    `<u:SetCallBarringEntry xmlns:u="${SERVICE}">` +
      `<NewPhonebookEntryData>${escapeXml(entry)}</NewPhonebookEntryData>` +
      `</u:SetCallBarringEntry>`,
  );

  return {
    uid: (tagValue(xml, "NewPhonebookEntryUniqueID") ?? "").trim(),
    name,
    number,
  };
}

async function unblockEntry(uid: string): Promise<void> {
  await soap(
    "DeleteCallBarringEntryUID",
    `<u:DeleteCallBarringEntryUID xmlns:u="${SERVICE}">` +
      `<NewPhonebookEntryUniqueID>${escapeXml(uid)}</NewPhonebookEntryUniqueID>` +
      `</u:DeleteCallBarringEntryUID>`,
  );
}

// ----------------------------------------------------------------- Endpunkt

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json; charset=utf-8" },
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "Nur POST wird unterstuetzt." }, 405);

  if (!TOOL_KEY) {
    return json({ error: "Der Zugriffsschluessel ist serverseitig nicht gesetzt (TOOL_ACCESS_KEY)." }, 500);
  }
  const url = new URL(req.url);
  const provided = req.headers.get("x-tool-key") ?? url.searchParams.get("key") ?? "";
  if (provided !== TOOL_KEY) {
    return json({ error: "Kein Zugriff — der Zugriffsschluessel fehlt oder ist falsch." }, 403);
  }

  let payload: { action?: string; number?: string; name?: string; uid?: string };
  try {
    payload = await req.json();
  } catch {
    return json({ error: "Ungueltige Anfrage." }, 400);
  }

  try {
    switch (payload.action) {
      case "list":
        return json({ entries: await listBarred() });

      case "block": {
        const number = (payload.number ?? "").trim();
        if (!/^[+]?[\d\s/()*#-]{3,30}$/.test(number)) {
          return json({ error: "Bitte eine gueltige Rufnummer eingeben." }, 400);
        }
        const cleaned = number.replace(/[\s/()-]/g, "");
        const name = (payload.name ?? "").trim().slice(0, 60) || "Gesperrt";
        return json({ entry: await blockNumber(cleaned, name) });
      }

      case "unblock": {
        const uid = (payload.uid ?? "").trim();
        if (!/^\d+$/.test(uid)) return json({ error: "Ungueltiger Eintrag." }, 400);
        await unblockEntry(uid);
        return json({ ok: true });
      }

      default:
        return json({ error: "Unbekannte Aktion." }, 400);
    }
  } catch (err) {
    if (err instanceof FritzError) return json({ error: err.message }, err.status);
    console.error(err);
    return json({ error: "Unerwarteter Fehler beim Zugriff auf die FRITZ!Box." }, 500);
  }
});
