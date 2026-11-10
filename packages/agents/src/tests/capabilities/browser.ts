import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import type { BrowserBinding } from "../../browser/browser-run";
import { Browser } from "../../browser/browser";
import { browserRun } from "../../browser/providers/browser-run";
import type {
  InternalHostMessage,
  InternalHostRouterLoopback
} from "../../browser/internal-hosts";
import { Lifecycle } from "../../lifecycle";
import { z } from "zod";

/** One request the fake Browser Run binding served, in arrival order. */
export interface RecordedBrowserRequest {
  url: string;
  method: string;
  upgrade: boolean;
  /** Parsed JSON request body, when the request carried one. */
  body?: unknown;
}

/**
 * A CDP WebSocket stub: acks accept/close, and answers the handful of CDP
 * commands the browser tool issues. Each session starts with one blank tab,
 * like Browser Run; `Target.createTarget` adds more, shared by every socket
 * on the session.
 */
class FakeBrowserSocket {
  #listeners = new Map<string, Array<(event: unknown) => void>>();
  constructor(
    readonly sessionId: string,
    readonly tabs: string[],
    readonly events: string[]
  ) {}
  accept(): void {}
  send(data: string): void {
    const { id, method, params, sessionId } = JSON.parse(data) as {
      id: number;
      method: string;
      params?: { fakeBytes?: number; expression?: string };
      sessionId?: string;
    };
    const first = `target-${this.sessionId}`;
    const evaluatedIn = sessionId?.replace(/^cdp-/, "") ?? first;
    // `wait:<ms>` (not real JavaScript) delays the reply, so tests can
    // tell overlapping runs from queued ones.
    const wait = Number(params?.expression?.match(/^wait:(\d+)$/)?.[1] ?? 0);
    const result =
      method === "Target.getTargets"
        ? {
            targetInfos: [first, ...this.tabs].map((targetId) => ({
              targetId,
              type: "page",
              url: "about:blank"
            }))
          }
        : method === "Target.createTarget"
          ? { targetId: this.#createTab() }
          : method === "Target.attachToTarget"
            ? {
                sessionId: `cdp-${String((params as { targetId?: unknown })?.targetId)}`
              }
            : method === "Runtime.evaluate"
              ? { result: { value: `evaluated in ${evaluatedIn}` } }
              : method === "Page.captureScreenshot"
                ? // `fakeBytes` (not a CDP param) sizes the base64 data.
                  { data: "A".repeat(params?.fakeBytes ?? 8) }
                : {};
    if (wait) this.events.push(`start ${params?.expression}`);
    setTimeout(() => {
      if (wait) this.events.push(`end ${params?.expression}`);
      for (const fn of this.#listeners.get("message") ?? []) {
        fn({ data: JSON.stringify({ id, result }) });
      }
    }, wait);
  }
  #createTab(): string {
    const targetId = `target-${this.sessionId}-${this.tabs.length + 2}`;
    this.tabs.push(targetId);
    return targetId;
  }
  addEventListener(type: string, fn: (event: unknown) => void): void {
    const list = this.#listeners.get(type) ?? [];
    list.push(fn);
    this.#listeners.set(type, list);
  }
  close(): void {
    for (const fn of this.#listeners.get("close") ?? []) fn({});
  }
}

/** One `acquire()` the fake binding served, with its options. */
export interface RecordedBrowserAcquire {
  sessionId: string;
  outboundByHost?: Record<string, Fetcher>;
}

export interface FakeBrowserBinding {
  browser: BrowserBinding;
  /** Every typed `acquire()`, when made with `{ typed: true }`. */
  acquired: RecordedBrowserAcquire[];
  requests: RecordedBrowserRequest[];
  /** `start`/`end` of each `wait:<ms>` evaluation, in order. */
  events: string[];
  /**
   * Simulate the platform reclaiming a session upstream: subsequent
   * `/json/list` probes for it return 410, like an expired `keep_alive`.
   */
  kill: (sessionId: string) => void;
}

/**
 * An in-memory Browser Run binding. POST acquires mint `session-N` ids,
 * `/json/list` returns one page target whose `devtoolsFrontendUrl` carries a
 * fresh token per response (so tests can prove Live View URLs are minted
 * fresh, never cached), and DELETE marks the session dead.
 */
export function createFakeBrowserBinding(
  options: {
    /** Give the binding a typed `acquire()`, as deployed bindings have. */
    typed?: boolean;
  } = {}
): FakeBrowserBinding {
  const requests: RecordedBrowserRequest[] = [];
  const acquired: RecordedBrowserAcquire[] = [];
  const dead = new Set<string>();
  let created = 0;
  let minted = 0;
  const tabs = new Map<string, string[]>();
  const events: string[] = [];

  const browser: BrowserBinding = {
    async fetch(input: RequestInfo | URL, init?: RequestInit) {
      const url = String(input);
      const method = init?.method ?? "GET";
      const upgrade = new Headers(init?.headers).get("Upgrade") === "websocket";
      const body =
        typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
      requests.push({ url, method, upgrade, body });

      if (upgrade) {
        const sessionId =
          url.match(/\/browser\/([^/?]+)/)?.[1] ?? "session-upgraded";
        let sessionTabs = tabs.get(sessionId);
        if (!sessionTabs) tabs.set(sessionId, (sessionTabs = []));
        const socket = new FakeBrowserSocket(sessionId, sessionTabs, events);
        const response = new Response(null, {
          headers: { "cf-browser-session-id": "session-upgraded" }
        });
        Object.defineProperty(response, "webSocket", { value: socket });
        return response;
      }
      if (method === "POST") {
        created++;
        return Response.json({ sessionId: `session-${created}` });
      }
      const sessionId = url.match(/\/browser\/([^/?]+)/)?.[1];
      if (url.endsWith("/json/list")) {
        if (!sessionId || dead.has(sessionId)) {
          return new Response(null, { status: 410 });
        }
        minted++;
        return Response.json([
          {
            id: `target-${sessionId}`,
            type: "page",
            url: "https://example.com/",
            title: "Example",
            devtoolsFrontendUrl: `https://live.browser.run/${sessionId}?token=fresh-${minted}`
          }
        ]);
      }
      if (method === "DELETE" && sessionId) dead.add(sessionId);
      return new Response(null, { status: 204 });
    }
  };
  if (options.typed) {
    browser.acquire = async (acquireOptions) => {
      created++;
      const sessionId = `session-${created}`;
      acquired.push({
        sessionId,
        outboundByHost: acquireOptions?.outboundByHost
      });
      return { sessionId };
    };
  }

  return {
    browser,
    acquired,
    requests,
    events,
    kill: (sessionId) => dead.add(sessionId)
  };
}

export interface FakeCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  expires: number;
  httpOnly: boolean;
  secure: boolean;
  session: boolean;
  sameSite?: string;
}

export interface FakeSession {
  dead: boolean;
  cookies: FakeCookie[];
  /** origin → key → value */
  localStorage: Map<string, Map<string, string>>;
  /** targetId → url */
  tabs: Map<string, string>;
  /** CDP session id → targetId */
  attached: Map<string, string>;
  /** Every command sent on any socket to this session, in order. */
  commands: { method: string; params?: Record<string, unknown> }[];
}

/**
 * An in-memory Browser Run for saved-logins tests: each session's sockets
 * share a cookie jar, per-origin localStorage, and tabs with URLs, like one
 * real browser. Every command is recorded per session, so tests can check
 * what ran before the caller's first command. DELETE kills a session, and
 * pages on an origin in `unreachable` fail to evaluate, like a host that
 * doesn't resolve.
 */
export function createSavedLoginsFakeBinding() {
  const sessions = new Map<string, FakeSession>();
  const unreachable = new Set<string>();
  let created = 0;

  const session = (id: string) => {
    const found = sessions.get(id);
    if (!found) throw new Error(`no fake session ${id}`);
    return found;
  };

  const originOf = (url: string) => {
    try {
      return new URL(url).origin;
    } catch {
      return "null";
    }
  };

  function handle(
    s: FakeSession,
    method: string,
    params: Record<string, unknown> = {},
    cdpSession?: string
  ): unknown {
    s.commands.push({ method, params });
    const tabUrl = () => s.tabs.get(s.attached.get(cdpSession ?? "") ?? "");
    switch (method) {
      case "Target.getTargets":
        return {
          targetInfos: [...s.tabs].map(([targetId, url]) => ({
            targetId,
            type: "page",
            url
          }))
        };
      case "Target.createTarget": {
        const targetId = `tab-${s.tabs.size + 1}-${Math.random().toString(36).slice(2, 6)}`;
        s.tabs.set(targetId, String(params.url ?? "about:blank"));
        return { targetId };
      }
      case "Target.closeTarget":
        s.tabs.delete(String(params.targetId));
        return { success: true };
      case "Target.attachToTarget": {
        const id = `cdp-${String(params.targetId)}`;
        s.attached.set(id, String(params.targetId));
        return { sessionId: id };
      }
      case "Page.navigate": {
        const targetId = s.attached.get(cdpSession ?? "");
        if (targetId) s.tabs.set(targetId, String(params.url));
        return { frameId: "frame" };
      }
      case "Storage.getCookies":
      case "Network.getAllCookies":
        return { cookies: s.cookies.map((c) => ({ ...c })) };
      case "Storage.setCookies":
        for (const c of params.cookies as Record<string, unknown>[]) {
          const domain = c.url
            ? new URL(String(c.url)).hostname
            : String(c.domain);
          s.cookies = s.cookies.filter(
            (o) => !(o.name === c.name && o.domain === domain)
          );
          s.cookies.push({
            name: String(c.name),
            value: String(c.value),
            domain,
            path: String(c.path ?? "/"),
            expires: Number(c.expires ?? -1),
            httpOnly: Boolean(c.httpOnly),
            secure: Boolean(c.secure),
            session: c.expires === undefined
          });
        }
        return {};
      case "Runtime.evaluate": {
        const expression = String(params.expression);
        const url = tabUrl() ?? "about:blank";
        const origin = originOf(url);
        if (unreachable.has(origin)) {
          return {
            result: {},
            exceptionDetails: { text: "net::ERR_NAME_NOT_RESOLVED" }
          };
        }
        const store =
          s.localStorage.get(origin) ??
          s.localStorage.set(origin, new Map()).get(origin)!;
        if (expression === "location.origin + ' ' + document.readyState") {
          return { result: { value: `${origin} complete` } };
        }
        if (expression === "JSON.stringify({ ...localStorage })") {
          return {
            result: { value: JSON.stringify(Object.fromEntries(store)) }
          };
        }
        const write = expression.match(/const items = (\{.*?\}); for/);
        if (write) {
          for (const [k, v] of Object.entries(
            JSON.parse(write[1]) as Record<string, string>
          )) {
            store.set(k, v);
          }
          return { result: { value: true } };
        }
        const get = expression.match(/^localStorage\.getItem\("(.+)"\)$/);
        if (get) return { result: { value: store.get(get[1]) ?? null } };
        if (expression === "document.cookie") {
          const host = new URL(url).hostname;
          return {
            result: {
              value: s.cookies
                .filter((c) => !c.httpOnly && c.domain === host)
                .map((c) => `${c.name}=${c.value}`)
                .join("; ")
            }
          };
        }
        if (expression === "throw:saved") {
          return {
            result: {},
            exceptionDetails: { text: `Uncaught ${store.get("token")}` }
          };
        }
        return { result: { value: `evaluated ${expression}` } };
      }
      default:
        return {};
    }
  }

  class Socket {
    #listeners = new Map<string, ((event: unknown) => void)[]>();
    constructor(readonly sessionId: string) {}
    accept() {}
    send(data: string) {
      const { id, method, params, sessionId } = JSON.parse(data) as {
        id: number;
        method: string;
        params?: Record<string, unknown>;
        sessionId?: string;
      };
      const result = handle(session(this.sessionId), method, params, sessionId);
      queueMicrotask(() => {
        for (const fn of this.#listeners.get("message") ?? []) {
          fn({ data: JSON.stringify({ id, result }) });
        }
      });
    }
    addEventListener(type: string, fn: (event: unknown) => void) {
      this.#listeners.set(type, [...(this.#listeners.get(type) ?? []), fn]);
    }
    close() {
      for (const fn of this.#listeners.get("close") ?? []) fn({});
    }
  }

  const browser: BrowserBinding = {
    async fetch(input, init) {
      const url = String(input);
      const method = init?.method ?? "GET";
      const id = url.match(/\/browser\/([^/?]+)/)?.[1];
      if (new Headers(init?.headers).get("Upgrade") === "websocket") {
        if (!id || session(id).dead) {
          return new Response(null, { status: 410 });
        }
        const response = new Response(null);
        Object.defineProperty(response, "webSocket", { value: new Socket(id) });
        return response;
      }
      if (method === "POST") {
        const sessionId = `session-${++created}`;
        sessions.set(sessionId, {
          dead: false,
          cookies: [],
          localStorage: new Map(),
          tabs: new Map([["tab-0", "about:blank"]]),
          attached: new Map(),
          commands: []
        });
        return Response.json({ sessionId });
      }
      if (url.endsWith("/json/list")) {
        if (!id || session(id).dead) return new Response(null, { status: 410 });
        return Response.json(
          [...session(id).tabs].map(([targetId, tabUrl]) => ({
            id: targetId,
            type: "page",
            url: tabUrl,
            devtoolsFrontendUrl: `https://live.browser.run/${id}/${targetId}`
          }))
        );
      }
      if (method === "DELETE" && id) session(id).dead = true;
      return new Response(null, { status: 204 });
    }
  };

  return {
    browser,
    sessions,
    session,
    /** Origins whose pages fail to evaluate. */
    unreachable,
    /** The person signs in inside a login browser. */
    signIn(
      sessionId: string,
      cookies: Partial<FakeCookie>[],
      localStorage: Record<string, Record<string, string>> = {}
    ) {
      const s = session(sessionId);
      for (const c of cookies) {
        s.cookies.push({
          name: "sid",
          value: "",
          domain: "acme.test",
          path: "/",
          expires: -1,
          httpOnly: true,
          secure: true,
          session: true,
          ...c
        });
      }
      for (const [origin, items] of Object.entries(localStorage)) {
        s.localStorage.set(origin, new Map(Object.entries(items)));
      }
    },
    kill: (sessionId: string) => {
      session(sessionId).dead = true;
    }
  };
}

/**
 * Minimal real host for capability-level browser tests: a Durable Object
 * whose only capability is a `Browser`, with runtime handlers
 * installed so tests can drive real Lifecycle startup, real storage, and the
 * real job queue and alarm. The binding is the in-memory fake above; its
 * requests are exposed for platform-call assertions.
 */
export class BrowserHarnessObject extends DurableObject<Cloudflare.Env> {
  readonly #binding = createFakeBrowserBinding();
  readonly browserRequests = this.#binding.requests;
  readonly killBrowserSession = this.#binding.kill;
  readonly browser = new Browser({
    provider: browserRun(this.#binding.browser)
  });
  readonly lifecycle = Lifecycle.install(this).use(this.browser);
}

/**
 * A `Browser` named "internal" with one `echo.internal` host, on a typed fake
 * binding, for a plain Durable Object host.
 */
function internalHostsBrowser(ctx: DurableObjectState) {
  const binding = createFakeBrowserBinding({ typed: true });
  const browser = new Browser({
    name: "internal",
    provider: browserRun(binding.browser, {
      internalHosts: {
        router: (ctx as unknown as { exports: Record<string, unknown> }).exports
          .InternalHostRouter as InternalHostRouterLoopback,
        hosts: {
          "echo.internal": {
            fetch: async (request: Request) =>
              new Response(
                `echo ${new URL(request.url).pathname} from ${ctx.id.name}`
              )
          },
          // A Standard Schema with a transform: stored as assigned, passed
          // to fetch as parsed.
          "port.internal": {
            target: z.object({ port: z.coerce.number().int() }),
            fetch: async (_request: Request, { port }) =>
              new Response(`port ${port} (${typeof port})`)
          }
        }
      }
    })
  });
  /** Resolve the browser and fetch `url` through its route. */
  const fetchThroughRoute = async (url: string) => {
    await browser.resolve();
    const route =
      binding.acquired.at(-1)?.outboundByHost?.[new URL(url).hostname];
    if (!route) throw new Error(`no route for ${url}`);
    const response = await route.fetch(url);
    return { status: response.status, text: await response.text() };
  };
  return { browser, fetchThroughRoute };
}

/**
 * A plain Durable Object with internal hostnames: it adds the one
 * `fetchInternalHost()` method the docs show.
 */
export class InternalHostsPlainObject extends DurableObject<Cloudflare.Env> {
  readonly #internal = internalHostsBrowser(this.ctx);
  readonly browser = this.#internal.browser;
  readonly fetchThroughRoute = this.#internal.fetchThroughRoute;
  readonly lifecycle = Lifecycle.install(this).use(this.browser);

  fetchInternalHost(message: InternalHostMessage) {
    return this.browser.fetchInternalHost(message);
  }
}

/** Like {@link InternalHostsPlainObject}, but missing `fetchInternalHost()`. */
export class InternalHostsNoMethodObject extends DurableObject<Cloudflare.Env> {
  readonly #internal = internalHostsBrowser(this.ctx);
  readonly browser = this.#internal.browser;
  readonly fetchThroughRoute = this.#internal.fetchThroughRoute;
  readonly lifecycle = Lifecycle.install(this).use(this.browser);
}

/**
 * A Worker entrypoint served as a `worker` host. Echoes the path and the
 * props it was called with, so tests can see how the route was made.
 */
export class InternalHostsDocsSite extends WorkerEntrypoint {
  override fetch(request: Request): Response {
    return new Response(
      `docs ${new URL(request.url).pathname} props ${JSON.stringify(this.ctx.props)}`
    );
  }
}
