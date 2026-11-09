import { Agent, callable, routeAgentRequest, type AgentContext } from "agents";
import {
  CodemodeConnector,
  createCodemodeRuntime,
  DynamicWorkerExecutor,
  type CodemodeRuntimeHandle,
  type ConnectorTools,
  type PendingAction,
  type ProxyToolOutput
} from "@cloudflare/codemode";
import { BrowserConnector } from "../browser/connector";
import { browserFunctions } from "../browser/browser-functions";
import { runBrowserCode } from "../browser/sandbox";
import type { BrowserSessionReport } from "../browser/session";
import { Browser, namedBrowserSessionKey } from "../browser/browser";
// The saved-logins browser is installed on the Agent's Lifecycle, so it must
// come from the same build as `Agent` (the package's dist), not `src`.
import {
  Browser as LifecycleBrowser,
  browserRun as lifecycleBrowserRun
} from "agents/browser";
import { browserTool } from "agents/browser/ai-sdk";
import { browserRun } from "../browser/providers/browser-run";
import {
  DurableBrowserSessionStore,
  type StoredBrowserSession
} from "../browser/session-store";
import {
  listBrowserTargets,
  connectBrowserSession,
  deleteBrowserSession,
  BrowserRenderingError
} from "../browser/browser-run";

// The codemode runtime facet class must be exported from the worker entry so
// `ctx.exports.CodemodeRuntime` resolves (the vite plugin does this in apps).
export { CodemodeRuntime } from "@cloudflare/codemode";

type Env = {
  BROWSER: Fetcher;
  LOADER: WorkerLoader;
  BrowserTestAgent: DurableObjectNamespace<BrowserTestAgent>;
};

type SessionMode = "one-shot" | "reuse" | "dynamic";

/** The named session the persistent-browser tests drive. */
const NAMED_SESSION = "e2e";

/** Test-only key for the saved-logins browser. Real keys come from secrets. */
const LOGINS_TEST_KEY = "browser-e2e-saved-logins-test-key-0123456789";

/**
 * Where the fake Acme site is served. Chrome resolves *.localhost to
 * loopback, so the local browser reaches this `wrangler dev`.
 */
const ACME_ORIGIN = "http://acme.localhost:18798";

/** Approval-gated connector used to pause executions mid-run in tests. */
class GateConnector extends CodemodeConnector<Env> {
  name(): string {
    return "gate";
  }

  protected tools(): ConnectorTools {
    return {
      confirm: {
        description: "Ask the user to confirm before continuing.",
        requiresApproval: true,
        inputSchema: {
          type: "object",
          properties: { label: { type: "string" } }
        },
        execute: async (args) => ({ confirmed: true, args })
      }
    };
  }
}

export class BrowserTestAgent extends Agent<Env> {
  /** A browser with saved logins for the fake Acme site. */
  readonly loginsBrowser = new LifecycleBrowser({
    name: "logins",
    provider: lifecycleBrowserRun(this.env.BROWSER),
    logins: {
      encryptionKey: LOGINS_TEST_KEY,
      sites: { acme: { label: "Acme", loginUrl: `${ACME_ORIGIN}/login` } }
    }
  });

  constructor(ctx: AgentContext, env: Env) {
    super(ctx, env);
    this.lifecycle.use(this.loginsBrowser);
  }

  #store() {
    return new DurableBrowserSessionStore(this.ctx.storage);
  }

  #connector(mode: SessionMode): BrowserConnector {
    return new BrowserConnector(this.ctx, {
      browser: this.env.BROWSER,
      store: this.#store(),
      session: mode === "one-shot" ? undefined : { mode }
    });
  }

  #runtime(mode: SessionMode): CodemodeRuntimeHandle {
    return createCodemodeRuntime({
      ctx: this.ctx,
      executor: new DynamicWorkerExecutor({ loader: this.env.LOADER }),
      connectors: [
        this.#connector(mode),
        new GateConnector(this.ctx, this.env)
      ],
      name: `browser-${mode}`
    });
  }

  async #execute(
    runtime: CodemodeRuntimeHandle,
    code: string
  ): Promise<ProxyToolOutput> {
    const tool = runtime.tool();
    if (!tool.execute) throw new Error("runtime tool is not executable");
    return (await tool.execute(
      { code },
      { toolCallId: crypto.randomUUID(), messages: [] }
    )) as ProxyToolOutput;
  }

  // ── Persistent named browser (BrowserSession + runBrowserCode) ──

  #namedBrowser(): Browser {
    return new Browser({
      provider: browserRun(this.env.BROWSER),
      name: NAMED_SESSION,
      store: this.#store()
    });
  }

  /**
   * Run code against the persistent browser the way `browserTool`
   * does: one session per run, the code in a Dynamic Worker. Includes the
   * session's report.
   */
  @callable()
  async runNamed(
    code: string,
    scope?: string
  ): Promise<
    (
      | { status: "completed"; result: unknown }
      | { status: "error"; error: string }
    ) & { logs: string[]; report: BrowserSessionReport | null }
  > {
    const session = this.#namedBrowser().session({ scope });
    try {
      const ran = await runBrowserCode({
        loader: this.env.LOADER,
        code,
        functions: browserFunctions(session),
        timeoutMs: 60_000
      });
      const report = (await session.close()) ?? null;
      return "error" in ran
        ? { status: "error", error: ran.error, logs: ran.logs, report }
        : { status: "completed", result: ran.result, logs: ran.logs, report };
    } finally {
      // Already closed unless the run threw; a second close does nothing.
      await session.close();
    }
  }

  // ── Saved logins ──

  #logins() {
    const logins = this.loginsBrowser.logins;
    if (!logins) throw new Error("no saved logins");
    return logins;
  }

  @callable()
  async loginsBegin(site: string) {
    const { loginId } = await this.#logins().begin(site);
    return loginId;
  }

  /**
   * Stand in for the person in Live View: type into the login browser over
   * a host-side connection the model never has.
   */
  @callable()
  async loginsSignIn(loginId: string, username: string): Promise<string> {
    const cdp = await this.#logins().connect(loginId);
    const evaluate = async (expression: string) =>
      (
        (await cdp.send(
          "Runtime.evaluate",
          { expression, returnByValue: true },
          { sessionId }
        )) as { result?: { value?: unknown } }
      ).result?.value;
    let sessionId: string | undefined;
    try {
      const { targetInfos } = (await cdp.send("Target.getTargets")) as {
        targetInfos: { targetId: string; type: string; url: string }[];
      };
      const tab = targetInfos.find((t) => t.url.startsWith(ACME_ORIGIN));
      if (!tab) throw new Error("login tab not found");
      sessionId = await cdp.attachToTarget(tab.targetId);
      for (let i = 0; i < 50 && !(await evaluate("!!document.forms[0]")); i++) {
        await new Promise((r) => setTimeout(r, 100));
      }
      await evaluate(
        `document.forms[0].username.value = ${JSON.stringify(username)}; document.forms[0].password.value = "hunter2"; document.forms[0].submit(); true`
      );
      for (let i = 0; i < 50; i++) {
        await new Promise((r) => setTimeout(r, 100));
        const text = await evaluate(
          `location.pathname === "/me" && document.readyState === "complete" ? document.body.innerText : ""`
        ).catch(() => "");
        if (text) return String(text);
      }
      throw new Error("sign-in did not finish");
    } finally {
      cdp.disconnect();
    }
  }

  @callable()
  async loginsSave(loginId: string) {
    return this.#logins().save(loginId);
  }

  @callable()
  async loginsList() {
    return this.#logins().list();
  }

  @callable()
  async loginsRevoke(site: string) {
    return this.#logins().revoke(site);
  }

  /** Run model code through `browserTool`, exactly as the model would. */
  @callable()
  async loginsRun(code: string) {
    return browserTool({
      browser: this.loginsBrowser,
      loader: this.env.LOADER
    }).execute({ code }, {});
  }

  /** Simulate Browser Run reclaiming the logins browser. */
  @callable()
  async loginsLoseBrowser(): Promise<void> {
    const store = this.#store();
    const key = namedBrowserSessionKey("logins");
    const stored = await store.get(key);
    if (!stored) throw new Error("no logins browser yet");
    await store.set(key, {
      ...stored,
      sessionId: "00000000-0000-0000-0000-000000000000"
    });
  }

  @callable()
  async loginsClose(): Promise<void> {
    await this.loginsBrowser.close();
  }

  /** Close the persistent browser so it doesn't outlive the suite. */
  @callable()
  async closeNamed(): Promise<void> {
    await this.#namedBrowser().close();
  }

  /** Storage key of the named session, for corruptStoredSession. */
  @callable()
  async namedSessionKey(): Promise<string> {
    return namedBrowserSessionKey(NAMED_SESSION);
  }

  @callable()
  async run(
    code: string,
    mode: SessionMode = "one-shot"
  ): Promise<ProxyToolOutput> {
    return this.#execute(this.#runtime(mode), code);
  }

  @callable()
  async approve(executionId: string, mode: SessionMode) {
    return this.#runtime(mode).approve({ executionId });
  }

  @callable()
  async pending(mode: SessionMode): Promise<PendingAction[]> {
    return this.#runtime(mode).pending();
  }

  @callable()
  async sessionInfo(mode: SessionMode) {
    return (await this.#connector(mode).sessionInfo()) ?? null;
  }

  @callable()
  async closeSession(mode: SessionMode): Promise<void> {
    await this.#connector(mode).closeSession();
  }

  @callable()
  async sweep(mode: SessionMode, maxIdleMs?: number) {
    return this.#connector(mode).sweep({ maxIdleMs });
  }

  /** All stored session entries (cdp:exec:* and cdp:reuse:*). */
  @callable()
  async storedSessions(): Promise<Record<string, StoredBrowserSession>> {
    return Object.fromEntries(await this.#store().list("cdp:"));
  }

  /** Delete a Browser Run session out-of-band (simulates expiry). */
  @callable()
  async killBrowserSession(sessionId: string): Promise<void> {
    await deleteBrowserSession(this.env.BROWSER, sessionId);
  }

  /**
   * Point a stored entry at a session id that doesn't exist — simulates
   * Browser Run reclaiming the session while a run is paused. (The local
   * simulator treats DELETE as a no-op, so killBrowserSession can't be used
   * to test expiry in `wrangler dev`.)
   */
  @callable()
  async corruptStoredSession(key: string): Promise<void> {
    const store = this.#store();
    const stored = await store.get(key);
    if (!stored) throw new Error(`No stored session under ${key}`);
    await store.set(key, {
      ...stored,
      sessionId: "00000000-0000-0000-0000-000000000000"
    });
  }

  /** Whether a Browser Run session id is still alive. */
  @callable()
  async sessionAlive(sessionId: string): Promise<boolean> {
    try {
      await listBrowserTargets(this.env.BROWSER, sessionId);
      return true;
    } catch (error) {
      if (error instanceof BrowserRenderingError && error.status === 404) {
        return false;
      }
      throw error;
    }
  }

  /**
   * Probe whether Browser Run allows two concurrent WebSocket connections to
   * one session. Platform-dependent — the test records the answer rather than
   * asserting it.
   */
  @callable()
  async multiSocketProbe(sessionId: string): Promise<{
    concurrent: boolean;
    error?: string;
  }> {
    let first: Awaited<ReturnType<typeof connectBrowserSession>> | undefined;
    let second: Awaited<ReturnType<typeof connectBrowserSession>> | undefined;
    try {
      first = await connectBrowserSession(this.env.BROWSER, sessionId);
      second = await connectBrowserSession(this.env.BROWSER, sessionId);
      const [a, b] = await Promise.all([
        first.send("Browser.getVersion"),
        second.send("Browser.getVersion")
      ]);
      return { concurrent: !!a && !!b };
    } catch (error) {
      return {
        concurrent: false,
        error: error instanceof Error ? error.message : String(error)
      };
    } finally {
      first?.disconnect();
      second?.disconnect();
    }
  }
}

/**
 * The fake Acme site: a sign-in form that sets an HttpOnly session cookie
 * and a localStorage token, `/me` that checks both, and `/rotate` that
 * replaces the session cookie like real sites do.
 */
async function acmeSite(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const html = (body: string, headers: HeadersInit = {}) =>
    new Response(`<!doctype html><html><body>${body}</body></html>`, {
      headers: { "Content-Type": "text/html", ...headers }
    });
  const user = /(?:^|;\s*)sid=sid_([a-z]+)_/.exec(
    request.headers.get("Cookie") ?? ""
  )?.[1];
  const sessionCookie = (name: string) =>
    `sid=sid_${name}_${crypto.randomUUID().replaceAll("-", "")}; Path=/; HttpOnly; SameSite=Lax`;
  switch (`${request.method} ${url.pathname}`) {
    case "GET /robots.txt":
      return new Response("User-agent: *\n");
    case "GET /login":
      return html(
        `<form method="POST" action="/login"><input name="username"><input name="password" type="password"><button>Sign in</button></form>`
      );
    case "POST /login": {
      const form = await request.formData();
      const name = String(form.get("username"));
      if (!/^[a-z]+$/.test(name) || form.get("password") !== "hunter2") {
        return html("wrong password");
      }
      return html(
        `<script>localStorage.setItem("api_token", "tok_${name}_${crypto.randomUUID()}"); location.href = "/me";</script>`,
        { "Set-Cookie": sessionCookie(name) }
      );
    }
    case "GET /rotate":
      return user
        ? html("rotated", { "Set-Cookie": sessionCookie(user) })
        : html("not signed in");
    case "GET /me":
      return html(
        `<p id="server">${user ? `Signed in as ${user}` : "Not signed in"}</p><p id="client"></p><script>document.getElementById("client").textContent = localStorage.getItem("api_token") ? "token present" : "no token";</script>`
      );
  }
  return new Response("Not found", { status: 404 });
}

export default {
  async fetch(request: Request, env: Env) {
    if (new URL(request.url).hostname === "acme.localhost") {
      return acmeSite(request);
    }
    return (
      (await routeAgentRequest(request, env)) ||
      new Response("Not found", { status: 404 })
    );
  }
};
