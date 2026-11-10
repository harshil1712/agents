# RFC: Saved logins for the persistent `Browser`

Status: proposed

## The problem

A `Browser` ([browser-sessions.md](./browser-sessions.md)) keeps its logins only while its Browser Run session lives: at most 20 idle minutes, and never across a crash or a release. After that the user signs in again. Saving and restoring cookies fixes that, but `browserTool` gives the model raw CDP, so three things have to hold:

1. The model never sees the saved values.
2. Only the user decides what's saved, not a login the model made by itself.
3. Two agents (two users) can't read each other's saved logins, even after a storage mix-up.

`browserTool` accepts any `BrowserSource`, so this can be built outside the SDK. A prototype did it, but it had to cast a wrapper to `CdpConnection`, check a marker on every `connect()`, hijack `cdp.disconnect()` to run at the end of a session, and it couldn't fix the restart notice, which tells the model its logins are gone after they were restored.

## The proposal

A `logins` option on `Browser`, managed host-side at `browser.logins`:

```ts
browser = new Browser({
  provider: browserRun(this.env.BROWSER, {
    guardrails: { allowedDomains: ["github.com", "*.github.com"] }
  }),
  logins: {
    encryptionKey: this.env.BROWSER_LOGINS_KEY,
    sites: { github: { label: "GitHub", loginUrl: "https://github.com/login" } }
  }
});

const { loginId, liveView } = await this.browser.logins.begin("github");
// …the user signs in through Live View…
await this.browser.logins.save(loginId);
```

- **Signing in** happens in a second Browser Run session (`adapter.createLoginSession`) that no `BrowserSession` connects to. `save` captures the cookies the browser sends to the site's `origins` (the login URL's origin by default) and their localStorage, refuses a login that set no cookies, and closes the login browser. `connect(loginId)` lets host code, never the model, drive it.
- **Encryption** is AES-256-GCM with a key derived (HKDF) from `encryptionKey` and the agent's class, name and browser name. The same string plus the site is the AAD, so a record copied to another agent, browser or site doesn't decrypt and is skipped with a warning.
- **Restoring:** `Browser.connect()` applies saved state before returning. The browser record stores the `loginsVersion` it got. A replaced browser has none, and save and revoke bump it. localStorage needs a document on the origin (Chrome's `DOMStorage` refuses one with no frame), so each origin costs a throwaway tab on `/robots.txt`.
- **Model code:** on a browser with saved logins, `BrowserSession` refuses cookie and storage commands (`Storage`/`Network` cookie commands, `Storage.clearData*`, `DOMStorage`, `IndexedDB`, `CacheStorage`). It redacts saved values from results, errors and the debug log, and `browserTool` redacts its final output. The model gets `browser.listLogins()`, built like the internal hosts functions, and a restart notice that lists what was restored.
- **Rotation:** when a session closes, cookies of sites already saved are captured again. A site with no cookies left keeps its saved login, and a login the model made is never saved.
- **Failures stay contained:** an origin whose localStorage can't be restored is skipped with a warning rather than failing `connect()`, and a sign-in nobody saved or cancelled is forgotten once its browser has expired.
- **Revoke** deletes the record and closes the browser. Clearing cookies would miss what the page copied elsewhere.

### What it protects

HttpOnly cookies are out of the model's reach. JS-readable values are only redacted on exact match, so page code can transform them (`btoa`) first. The boundary that stops a value leaving is the provider's `guardrails`, which the docs should recommend. Saved logins belong to the Durable Object, so the app must name that object from its authenticated identity.

## The alternatives

- **Userland `BrowserSource` wrapper:** it works (prototyped), but it needs the casts and hijacks above, and every app re-derives the security model.
- **Public hooks** (`onCreate`, `onSessionClose`, CDP middleware): they'd make internals public before a second use exists. The seams stay internal, like the provider adapter.
- **Playwright's `storageState()`:** `browserTool` doesn't use Playwright, and `storageState()` captures everything with no model policy.
- **`DOMStorage.setDOMStorageItem` without navigating:** Chrome refuses it without a frame on the origin.

## Follow-ups

- `browser.requestLogin({ site, reason })` with an `onRequest` hook, so the model can ask in a structured way, as #2671 did for internal hosts. Until then the model asks in chat.
- Per-user vaults for apps with one Durable Object per conversation.
- Noticing when a site has expired a saved login.
- Restoring localStorage without a network request (`Fetch.fulfillRequest`), which needs CDP events on `CdpConnection`.

## Verification

`src/tests/browser-logins.test.ts` runs on a fake Browser Run with a cookie jar and localStorage. `src/browser-tests` "saved logins" runs in real Chrome against a fake site with an HttpOnly cookie and a localStorage token: it covers sign-in, redaction and refusals, restore after a restart, rotation, and revoke.

Deployed on Browser Run (a playground Worker, the real `kimi-k2.7-code` model):

- `begin` returns Live View links.
- `connect(loginId)` signs in host-side and `save` captures the login.
- Restore works after a restart, rotation is captured, revoke works, and a second user's Durable Object sees nothing.
- With guardrails on, the model's code read `btoa(token)` past redaction, but `fetch`, image and navigation exfiltration attempts all got Browser Run's 403 ("denied due to guardrails policy") and never reached the target.

## The decision

_Pending discussion._
