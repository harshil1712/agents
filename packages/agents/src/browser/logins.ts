/**
 * Saved logins for a persistent `Browser`: a person signs in to a site once,
 * and the browser is signed in again every time it's replaced.
 *
 * - **The person signs in, not the model.** `logins.begin(site)` opens a
 *   separate browser no model code connects to, with a Live View link for
 *   the person. `logins.save(loginId)` captures the site's cookies and
 *   localStorage and closes it.
 * - **Encrypted per agent.** The key is derived from `encryptionKey` and the
 *   agent's class, name and browser name, and each record is bound to its
 *   site, so a record copied anywhere else doesn't decrypt.
 * - **Restored before the model runs.** `Browser.connect()` applies saved
 *   state to a browser that doesn't have it yet.
 * - **The model never sees the values.** Sessions refuse the commands that
 *   read or write cookies and storage, and redact saved values from what
 *   they return. Redaction is best effort (page code can transform a value);
 *   the provider's `guardrails` are what stop a value leaving.
 * - **Only the person creates a saved login.** When a session closes, the
 *   cookies of sites already saved are captured again, so rotated tokens
 *   survive a restart. A login the model makes itself is never saved.
 */

import type { CdpConnection } from "./cdp-connection";
import type { BrowserLiveView, LiveViewMode } from "./live-view";
import type { BrowserProviderAdapter } from "./providers/provider-adapter";

export interface SavedLoginSite {
  /** Shown to the model and your UI. Defaults to the site's key. */
  label?: string;
  /** Where a person signs in. */
  loginUrl: string;
  /**
   * The site's origins: their localStorage is saved, and so are the cookies
   * the browser sends to them. Defaults to the origin of `loginUrl`.
   */
  origins?: string[];
}

export interface SavedLoginsOptions {
  /**
   * At least 32 characters, from a Worker secret. The per-agent keys are
   * derived from it; changing it makes existing saved logins unreadable.
   */
  encryptionKey: string;
  /** The sites a person can save a login for, by key (`[a-z0-9_-]`). */
  sites: Record<string, SavedLoginSite>;
}

/** A saved login, without its values. */
export interface SavedLoginInfo {
  site: string;
  label: string;
  savedAt: number;
  /** When rotated cookies were last captured. */
  refreshedAt: number;
}

/** A login a person is signing in to. */
export interface SavedLoginStart {
  /** Host-only: pass to `save`, `cancel`, `liveView` or `connect`. */
  loginId: string;
  site: string;
  /**
   * Live View links for the person signing in. Bearer credentials with a
   * ~5 minute connect window: show them to the signed-in user only, never
   * the model, and mint fresh ones with `logins.liveView(loginId)`.
   */
  liveView?: BrowserLiveView;
}

/** What the model sees about a site. */
export interface SavedLoginStatus {
  site: string;
  label: string;
  url: string;
  signedIn: boolean;
}

/**
 * What a `BrowserSession` uses on a browser with saved logins.
 * `Browser.logins` implements it.
 */
export interface BrowserSessionLogins {
  /** The configured sites, for the tool description. */
  describe(): Omit<SavedLoginStatus, "signedIn">[];
  /** The configured sites, with whether each has a saved login. */
  status(): Promise<SavedLoginStatus[]>;
  /** Replaces the saved values in anything heading to the model. */
  redactor(): Promise<<T>(value: T) => T>;
  /** Capture rotated cookies of saved sites from the session's browser. */
  refresh(cdp: CdpConnection, sessionId: string): Promise<void>;
}

/** Host-side saved logins, at `browser.logins`. Never hand it to the model. */
export interface BrowserLogins extends BrowserSessionLogins {
  list(): Promise<SavedLoginInfo[]>;
  /** Open a separate browser on the site's `loginUrl` for a person. */
  begin(site: string): Promise<SavedLoginStart>;
  /** Fresh Live View links into a login browser. */
  liveView(
    loginId: string,
    options?: { mode?: LiveViewMode }
  ): Promise<BrowserLiveView | undefined>;
  /**
   * A CDP connection to a login browser, for host code that signs in on the
   * person's behalf. The login browser stays open until `save` or `cancel`.
   */
  connect(loginId: string): Promise<CdpConnection>;
  /**
   * Capture the site's cookies and localStorage, encrypt them, and close the
   * login browser. Throws when the site set no cookies.
   */
  save(loginId: string): Promise<SavedLoginInfo>;
  /** Close a login browser without saving. */
  cancel(loginId: string): Promise<boolean>;
  /** Forget a saved login and close the browser that has it. */
  revoke(site: string): Promise<boolean>;
}

/**
 * Why model code can't send `method` on a browser with saved logins:
 * reading cookies or storage would show saved values, and writing them
 * would change what the next refresh saves.
 */
export function savedLoginRefusal(method: string): string | undefined {
  const [domain] = method.split(".");
  const refused =
    domain === "DOMStorage" ||
    domain === "IndexedDB" ||
    domain === "CacheStorage" ||
    /^(Storage|Network)\.\w*Cookies?$/.test(method) ||
    /^Storage\.clearData/.test(method);
  return refused
    ? "cookies and storage hold the user's saved logins, which the host manages. browser.listLogins() says which sites are signed in."
    : undefined;
}

// ── Saved state ────────────────────────────────────────────────────────────

interface SavedCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires?: number;
  httpOnly: boolean;
  secure: boolean;
  sameSite?: "Strict" | "Lax" | "None";
}

interface LoginState {
  cookies: SavedCookie[];
  /** origin → key → value */
  localStorage: Record<string, Record<string, string>>;
}

/** Metadata in the clear, state encrypted. */
interface StoredLogin extends Omit<SavedLoginInfo, "label"> {
  iv: string;
  ciphertext: string;
}

interface PendingLogin {
  site: string;
  sessionId: string;
  startedAt: number;
}

interface Site {
  site: string;
  label: string;
  loginUrl: string;
  origins: string[];
}

/** What saved logins need from their `Browser`. */
export interface SavedLoginsHost {
  readonly name: string;
  readonly adapter: BrowserProviderAdapter;
  /** The host's storage and identity; throws without Lifecycle. */
  services(): {
    storage: DurableObjectStorage;
    className: string;
    name: string;
  };
  /** The saved-logins version applied to `sessionId`, if it's current. */
  appliedVersion(sessionId: string): Promise<number | undefined>;
  close(): Promise<boolean>;
}

const SITE_KEY = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const AAD_PREFIX = "agents/browser/logins/v1";
/** Long enough for a person to finish a sign-in, 2FA included. */
const LOGIN_KEEP_ALIVE_MS = 600_000;
/** Shorter values aren't redacted: too likely to match by chance. */
const MIN_REDACTED_LENGTH = 6;

/** Check `options` and fill in defaults. Throws on bad config. */
function resolveSites(options: SavedLoginsOptions): Map<string, Site> {
  if ((options.encryptionKey?.length ?? 0) < 32) {
    throw new Error(
      "Saved logins need an encryptionKey of at least 32 characters, from a Worker secret"
    );
  }
  const sites = new Map<string, Site>();
  for (const [site, config] of Object.entries(options.sites ?? {})) {
    if (!SITE_KEY.test(site)) {
      throw new Error(
        `Saved login site "${site}" needs a key of lowercase letters, digits, "-" and "_"`
      );
    }
    const loginUrl = httpUrl(config.loginUrl, site);
    sites.set(site, {
      site,
      label: config.label ?? site,
      loginUrl: loginUrl.href,
      origins: [
        ...new Set(
          (config.origins ?? [loginUrl.origin]).map(
            (origin) => httpUrl(origin, site).origin
          )
        )
      ]
    });
  }
  if (sites.size === 0) throw new Error("Saved logins need at least one site");
  return sites;
}

function httpUrl(value: string, site: string): URL {
  const url = URL.canParse(value) ? new URL(value) : undefined;
  if (url?.protocol !== "http:" && url?.protocol !== "https:") {
    throw new Error(
      `Saved login site "${site}": ${value} isn't an http(s) URL`
    );
  }
  return url;
}

/**
 * The saved logins of one `Browser`, exposed as `browser.logins`.
 */
export class SavedLoginsController implements BrowserLogins {
  readonly #sites: Map<string, Site>;
  readonly #encryptionKey: string;
  readonly #host: SavedLoginsHost;
  #key?: Promise<CryptoKey>;

  constructor(options: SavedLoginsOptions, host: SavedLoginsHost) {
    this.#sites = resolveSites(options);
    this.#encryptionKey = options.encryptionKey;
    this.#host = host;
  }

  // ── host surface ─────────────────────────────────────────────────────────

  async list(): Promise<SavedLoginInfo[]> {
    const out: SavedLoginInfo[] = [];
    for (const [key, record] of await this.#records()) {
      const site = this.#sites.get(key);
      if (!site) continue; // no longer configured
      const { savedAt, refreshedAt } = record;
      out.push({ site: key, label: site.label, savedAt, refreshedAt });
    }
    return out;
  }

  async begin(siteKey: string): Promise<SavedLoginStart> {
    const site = this.#site(siteKey);
    const { adapter } = this.#host;
    await this.#forgetExpiredPending();
    const { sessionId } = await adapter.createLoginSession({
      keepAliveMs: LOGIN_KEEP_ALIVE_MS
    });
    try {
      const cdp = await adapter.connect(sessionId, {});
      try {
        await cdp.send("Target.createTarget", { url: site.loginUrl });
      } finally {
        cdp.disconnect();
      }
    } catch (error) {
      await adapter.close(sessionId).catch(() => undefined);
      throw error;
    }
    const loginId = crypto.randomUUID();
    await this.#storage.put<PendingLogin>(this.#prefix(`pending:${loginId}`), {
      site: site.site,
      sessionId,
      startedAt: Date.now()
    });
    const liveView = await adapter.liveView(sessionId, "tab");
    return { loginId, site: site.site, ...(liveView ? { liveView } : {}) };
  }

  async liveView(loginId: string, options: { mode?: LiveViewMode } = {}) {
    const { sessionId } = await this.#pending(loginId);
    return this.#host.adapter.liveView(sessionId, options.mode ?? "tab");
  }

  async connect(loginId: string): Promise<CdpConnection> {
    const { sessionId } = await this.#pending(loginId);
    return this.#host.adapter.connect(sessionId, {});
  }

  async save(loginId: string): Promise<SavedLoginInfo> {
    const pending = await this.#pending(loginId);
    const site = this.#site(pending.site);
    const cdp = await this.#host.adapter.connect(pending.sessionId, {});
    let state: LoginState;
    try {
      state = await captureState(cdp, site);
    } finally {
      cdp.disconnect();
    }
    if (state.cookies.length === 0) {
      throw new Error(
        `${site.label} set no cookies: finish signing in, then save again`
      );
    }
    const now = Date.now();
    await this.#write(site.site, state, now, now);
    await this.#bumpVersion();
    await this.cancel(loginId);
    return {
      site: site.site,
      label: site.label,
      savedAt: now,
      refreshedAt: now
    };
  }

  async cancel(loginId: string): Promise<boolean> {
    const key = this.#prefix(`pending:${loginId}`);
    const pending = await this.#storage.get<PendingLogin>(key);
    if (!pending) return false;
    await this.#host.adapter.close(pending.sessionId).catch(() => undefined);
    await this.#storage.delete(key);
    return true;
  }

  async revoke(siteKey: string): Promise<boolean> {
    if (!(await this.#storage.delete(this.#prefix(`site:${siteKey}`)))) {
      return false;
    }
    await this.#bumpVersion();
    // Clearing cookies would miss what the page copied elsewhere.
    await this.#host.close();
    return true;
  }

  // ── session surface ──────────────────────────────────────────────────────

  describe() {
    return [...this.#sites.values()].map(({ site, label, loginUrl }) => ({
      site,
      label,
      url: loginUrl
    }));
  }

  async status(): Promise<SavedLoginStatus[]> {
    const saved = new Set((await this.list()).map((info) => info.site));
    return this.describe().map((site) => ({
      ...site,
      signedIn: saved.has(site.site)
    }));
  }

  async redactor() {
    const secrets: [needle: string, label: string][] = [];
    const add = (value: string, label: string) => {
      if (value.length < MIN_REDACTED_LENGTH) return;
      secrets.push([value, label], [encodeURIComponent(value), label]);
    };
    for (const [site, state] of await this.#states()) {
      for (const c of state.cookies)
        add(c.value, `[saved ${site} cookie ${c.name}]`);
      for (const items of Object.values(state.localStorage)) {
        for (const [k, v] of Object.entries(items)) {
          add(v, `[saved ${site} localStorage ${k}]`);
        }
      }
    }
    // Longest first, so a value containing another is replaced whole.
    secrets.sort(([a], [b]) => b.length - a.length);
    const walk = (value: unknown): unknown => {
      if (typeof value === "string") {
        return secrets.reduce(
          (text, [needle, label]) => text.replaceAll(needle, label),
          value
        );
      }
      if (Array.isArray(value)) return value.map(walk);
      if (value instanceof Error) {
        return Object.assign(new Error(walk(value.message) as string), {
          name: value.name
        });
      }
      if (value && typeof value === "object") {
        return Object.fromEntries(
          Object.entries(value).map(([k, v]) => [k, walk(v)])
        );
      }
      return value;
    };
    return <T>(value: T): T => (secrets.length ? (walk(value) as T) : value);
  }

  async refresh(cdp: CdpConnection, sessionId: string): Promise<void> {
    if (
      (await this.#host.appliedVersion(sessionId)) !== (await this.version())
    ) {
      return; // not the browser the saved state was applied to
    }
    for (const [key, record] of await this.#records()) {
      const site = this.#sites.get(key);
      if (!site) continue;
      const cookies = await captureCookies(cdp, site);
      // Signed out, or cleared by the page: keep the login rather than
      // replace it with nothing. The person revokes.
      if (cookies.length === 0) continue;
      const state = await this.#open(key, record);
      if (JSON.stringify(state.cookies) === JSON.stringify(cookies)) continue;
      await this.#write(key, { ...state, cookies }, record.savedAt, Date.now());
    }
  }

  // ── used by Browser ──────────────────────────────────────────────────────

  /** Bumped by every save and revoke, so browsers apply again. */
  async version(): Promise<number> {
    return (await this.#storage.get<number>(this.#prefix("version"))) ?? 0;
  }

  async apply(cdp: CdpConnection): Promise<void> {
    const states = await this.#states();
    await applyCookies(
      cdp,
      [...states.values()].flatMap((state) => state.cookies)
    );
    for (const [site, state] of states) {
      for (const [origin, items] of Object.entries(state.localStorage)) {
        // One unreachable origin shouldn't cost the browser its connection:
        // the cookies are set, and the site may still work without it.
        try {
          await inOrigin(cdp, origin, writeLocalStorage(items));
        } catch (error) {
          console.warn(
            `[agents/browser] Failed to restore localStorage on ${origin} for saved login "${site}" on browser "${this.#host.name}"`,
            error
          );
        }
      }
    }
  }

  // ── internals ────────────────────────────────────────────────────────────

  get #storage() {
    return this.#host.services().storage;
  }

  /** Length-prefixed per browser, like scope records. */
  #prefix(rest: string): string {
    const { name } = this.#host;
    return `browser:logins:${name.length}:${name}:${rest}`;
  }

  #site(key: string): Site {
    const site = this.#sites.get(key);
    if (!site) throw new Error(`No saved login site "${key}"`);
    return site;
  }

  async #pending(loginId: string): Promise<PendingLogin> {
    const pending = await this.#storage.get<PendingLogin>(
      this.#prefix(`pending:${loginId}`)
    );
    if (!pending) throw new Error("No login in progress with that id");
    return pending;
  }

  /**
   * Forget logins nobody saved or cancelled. Their browsers have closed
   * themselves by now (keep-alive); closing again is harmless.
   */
  async #forgetExpiredPending() {
    const cutoff = Date.now() - LOGIN_KEEP_ALIVE_MS;
    const pending = await this.#storage.list<PendingLogin>({
      prefix: this.#prefix("pending:")
    });
    for (const [key, login] of pending) {
      if (login.startedAt > cutoff) continue;
      await this.#host.adapter.close(login.sessionId).catch(() => undefined);
      await this.#storage.delete(key);
    }
  }

  async #bumpVersion() {
    await this.#storage.put(
      this.#prefix("version"),
      (await this.version()) + 1
    );
  }

  async #records(): Promise<[string, StoredLogin][]> {
    const prefix = this.#prefix("site:");
    const stored = await this.#storage.list<StoredLogin>({ prefix });
    return [...stored].map(([key, record]) => [
      key.slice(prefix.length),
      record
    ]);
  }

  /** Every configured site's state. Records that don't decrypt are skipped. */
  async #states(): Promise<Map<string, LoginState>> {
    const states = new Map<string, LoginState>();
    for (const [key, record] of await this.#records()) {
      if (!this.#sites.has(key)) continue;
      try {
        states.set(key, await this.#open(key, record));
      } catch {
        console.warn(
          `[agents/browser] Saved login "${key}" on browser "${this.#host.name}" doesn't decrypt (another agent's, or the key changed); ignoring it`
        );
      }
    }
    return states;
  }

  async #write(
    site: string,
    state: LoginState,
    savedAt: number,
    refreshedAt: number
  ) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: this.#aad(site) },
      await this.#cryptoKey(),
      new TextEncoder().encode(JSON.stringify(state))
    );
    await this.#storage.put<StoredLogin>(this.#prefix(`site:${site}`), {
      site,
      savedAt,
      refreshedAt,
      iv: toBase64(iv),
      ciphertext: toBase64(new Uint8Array(ciphertext))
    });
  }

  async #open(site: string, record: StoredLogin): Promise<LoginState> {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64(record.iv),
        additionalData: this.#aad(site)
      },
      await this.#cryptoKey(),
      fromBase64(record.ciphertext)
    );
    return JSON.parse(new TextDecoder().decode(plaintext)) as LoginState;
  }

  /** This agent and browser: the HKDF info, and with the site, the AAD. */
  #identity(): string {
    const { className, name } = this.#host.services();
    return `${AAD_PREFIX}|${className}|${name}|${this.#host.name}`;
  }

  #aad(site: string) {
    return new TextEncoder().encode(`${this.#identity()}|${site}`);
  }

  #cryptoKey(): Promise<CryptoKey> {
    this.#key ??= crypto.subtle
      .importKey(
        "raw",
        new TextEncoder().encode(this.#encryptionKey),
        "HKDF",
        false,
        ["deriveKey"]
      )
      .then((material) =>
        crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: new TextEncoder().encode(AAD_PREFIX),
            info: new TextEncoder().encode(this.#identity())
          },
          material,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"]
        )
      );
    return this.#key;
  }
}

// ── Capture and apply, over a host-side connection ─────────────────────────

/** Whether the browser sends a cookie for `domain` to one of the origins. */
function cookieBelongsTo(domain: string, site: Site): boolean {
  const bare = domain.replace(/^\./, "");
  return site.origins.some((origin) => {
    const host = new URL(origin).hostname;
    // Host-only cookies match their host; domain cookies match subdomains.
    return host === bare || (domain.startsWith(".") && host.endsWith(domain));
  });
}

async function captureCookies(
  cdp: CdpConnection,
  site: Site
): Promise<SavedCookie[]> {
  const { cookies = [] } = (await cdp.send("Storage.getCookies")) as {
    cookies?: (SavedCookie & { session?: boolean })[];
  };
  return cookies
    .filter((cookie) => cookieBelongsTo(cookie.domain, site))
    .map(
      ({
        name,
        value,
        domain,
        path,
        expires,
        httpOnly,
        secure,
        sameSite,
        session
      }) => ({
        name,
        value,
        domain,
        path,
        ...(session || !expires || expires < 0 ? {} : { expires }),
        httpOnly,
        secure,
        ...(sameSite ? { sameSite } : {})
      })
    );
}

async function applyCookies(cdp: CdpConnection, cookies: SavedCookie[]) {
  if (cookies.length === 0) return;
  await cdp.send("Storage.setCookies", {
    cookies: cookies.map(({ domain, ...cookie }) => ({
      ...cookie,
      // A host-only cookie is set through `url`: with `domain`, Chrome would
      // widen it to subdomains.
      ...(domain.startsWith(".")
        ? { domain }
        : {
            url: `${cookie.secure ? "https" : "http"}://${domain}${cookie.path}`
          })
    }))
  });
}

const READ_LOCAL_STORAGE = "JSON.stringify({ ...localStorage })";

function writeLocalStorage(items: Record<string, string>): string {
  return `(() => { const items = ${JSON.stringify(items)}; for (const [k, v] of Object.entries(items)) localStorage.setItem(k, v); return true; })()`;
}

/**
 * Evaluate `expression` in a throwaway tab on `origin`. localStorage needs a
 * document on the origin (Chrome's DOMStorage refuses an origin with no
 * frame); `/robots.txt` is usually the cheapest one.
 */
async function inOrigin(
  cdp: CdpConnection,
  origin: string,
  expression: string
) {
  const { targetId } = (await cdp.send("Target.createTarget", {
    url: "about:blank"
  })) as { targetId: string };
  try {
    const sessionId = await cdp.attachToTarget(targetId);
    await cdp.send(
      "Page.navigate",
      { url: `${origin}/robots.txt` },
      { sessionId }
    );
    for (let attempt = 0; attempt < 100; attempt++) {
      const loaded = await evaluate(
        cdp,
        sessionId,
        "location.origin + ' ' + document.readyState"
      );
      if (loaded === `${origin} complete`)
        return await evaluate(cdp, sessionId, expression);
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`Timed out loading ${origin} to reach its localStorage`);
  } finally {
    await cdp.send("Target.closeTarget", { targetId }).catch(() => undefined);
  }
}

async function evaluate(
  cdp: CdpConnection,
  sessionId: string,
  expression: string
) {
  const { result, exceptionDetails } = (await cdp.send(
    "Runtime.evaluate",
    { expression, returnByValue: true },
    { sessionId }
  )) as { result?: { value?: unknown }; exceptionDetails?: { text?: string } };
  if (exceptionDetails) {
    throw new Error(`Saved logins: page code failed: ${exceptionDetails.text}`);
  }
  return result?.value;
}

async function captureState(
  cdp: CdpConnection,
  site: Site
): Promise<LoginState> {
  const localStorage: LoginState["localStorage"] = {};
  for (const origin of site.origins) {
    const items = JSON.parse(
      String((await inOrigin(cdp, origin, READ_LOCAL_STORAGE)) ?? "{}")
    );
    if (Object.keys(items).length > 0) localStorage[origin] = items;
  }
  return { cookies: await captureCookies(cdp, site), localStorage };
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
}
