import { env } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import { Browser } from "../browser/browser";
import type { SavedLoginsOptions } from "../browser/logins";
import { browserRun } from "../browser/providers/browser-run";
import { browserTool } from "../browser/tools/ai-sdk";
import { createSavedLoginsFakeBinding } from "./capabilities/browser";
import { withCapabilityHarness } from "./shared/capability-harness";

type Fake = ReturnType<typeof createSavedLoginsFakeBinding>;

const KEY = "a-test-encryption-key-that-is-long-enough";

const SITES: SavedLoginsOptions["sites"] = {
  acme: { label: "Acme", loginUrl: "https://acme.test/login" },
  beta: { label: "Beta", loginUrl: "https://beta.test/login" }
};

function loginsBrowser(fake: Fake, name?: string) {
  return new Browser({
    name,
    provider: browserRun(fake.browser),
    logins: { encryptionKey: KEY, sites: SITES }
  });
}

/** Begin a login, sign in as the person would, and save it. */
async function saveLogin(
  browser: Browser,
  fake: Fake,
  site: "acme" | "beta",
  value = `${site}-session-value-1`
) {
  const { loginId } = await browser.logins!.begin(site);
  fake.signIn(
    [...fake.sessions.keys()].at(-1)!,
    [{ domain: `${site}.test`, value }],
    {
      [`https://${site}.test`]: { token: `${site}-token-secret` }
    }
  );
  return browser.logins!.save(loginId);
}

async function agentSessionId(browser: Browser) {
  return (await browser.resolve()).sessionId;
}

describe("saved logins", () => {
  it("rejects bad config", () => {
    const fake = createSavedLoginsFakeBinding();
    const make = (logins: SavedLoginsOptions) =>
      new Browser({ provider: browserRun(fake.browser), logins });
    expect(() => make({ encryptionKey: "short", sites: SITES })).toThrow(
      /at least 32 characters/
    );
    expect(() => make({ encryptionKey: KEY, sites: {} })).toThrow(
      /at least one site/
    );
    expect(() =>
      make({
        encryptionKey: KEY,
        sites: { "Not OK": { loginUrl: "https://a.test" } }
      })
    ).toThrow(/lowercase/);
    expect(() =>
      make({
        encryptionKey: KEY,
        sites: { a: { loginUrl: "javascript:alert(1)" } }
      })
    ).toThrow(/http\(s\) URL/);
  });

  it("needs Lifecycle", async () => {
    await expect(
      loginsBrowser(createSavedLoginsFakeBinding()).logins!.list()
    ).rejects.toThrow(/Lifecycle\.use/);
  });

  it("signs in through a separate browser, with Live View for the person", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));

      const start = await browser.logins!.begin("acme");

      // Only the login browser exists: the agent's wasn't started.
      expect([...fake.sessions.keys()]).toEqual(["session-1"]);
      expect([...fake.session("session-1").tabs.values()]).toContain(
        "https://acme.test/login"
      );
      expect(start.liveView?.targets[0]?.url).toContain("mode=tab");
      await expect(browser.logins!.liveView("nope")).rejects.toThrow(
        /No login in progress/
      );
    });
  });

  it("saves only the site's state, encrypted, and closes the login browser", async () => {
    await withCapabilityHarness(async ({ install, storage }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      const { loginId } = await browser.logins!.begin("acme");
      fake.signIn(
        "session-1",
        [
          { name: "sid", domain: "acme.test", value: "acme-sid-secret-value" },
          { name: "pref", domain: ".acme.test", value: "dark-mode-on" },
          { name: "sso", domain: "sso.test", value: "sso-secret-value" }
        ],
        {
          "https://acme.test": { token: "acme-token-secret" },
          "https://sso.test": { other: "not-acme-value" }
        }
      );

      expect(await browser.logins!.save(loginId)).toMatchObject({
        site: "acme",
        label: "Acme"
      });
      expect(fake.session("session-1").dead).toBe(true);

      const raw = JSON.stringify([...(await storage.list())]);
      for (const secret of [
        "acme-sid-secret-value",
        "acme-token-secret",
        "sso-secret-value"
      ]) {
        expect(raw).not.toContain(secret);
      }

      // Only Acme's cookies and localStorage reach the agent's browser.
      const connection = await browser.connect();
      connection.cdp.disconnect();
      const agent = fake.session(connection.sessionId);
      expect(agent.cookies.map((c) => c.name).sort()).toEqual(["pref", "sid"]);
      expect([...agent.localStorage.keys()]).not.toContain("https://sso.test");
    });
  });

  it("won't save a login that set no cookies", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      const { loginId } = await browser.logins!.begin("acme");

      await expect(browser.logins!.save(loginId)).rejects.toThrow(
        /set no cookies/
      );
      expect(fake.session("session-1").dead).toBe(false);
      expect(await browser.logins!.cancel(loginId)).toBe(true);
      expect(fake.session("session-1").dead).toBe(true);
    });
  });

  it("forgets a login nobody saved once its browser has expired", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      const abandoned = await browser.logins!.begin("acme");

      const now = Date.now();
      const clock = vi.spyOn(Date, "now").mockReturnValue(now + 11 * 60_000);
      try {
        await browser.logins!.begin("beta");
      } finally {
        clock.mockRestore();
      }

      await expect(browser.logins!.liveView(abandoned.loginId)).rejects.toThrow(
        /No login in progress/
      );
      expect(fake.session("session-1").dead).toBe(true);
      expect(fake.session("session-2").dead).toBe(false);
    });
  });

  it("still connects when one saved origin's localStorage can't be restored", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      await saveLogin(browser, fake, "acme");
      await saveLogin(browser, fake, "beta");
      fake.unreachable.add("https://acme.test");
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      try {
        const connection = await browser.connect();
        connection.cdp.disconnect();
        const agent = fake.session(connection.sessionId);
        expect(agent.cookies.map((c) => c.domain).sort()).toEqual([
          "acme.test",
          "beta.test"
        ]);
        expect(agent.localStorage.get("https://beta.test")?.get("token")).toBe(
          "beta-token-secret"
        );
        expect(warn).toHaveBeenCalledWith(
          expect.stringContaining(
            'Failed to restore localStorage on https://acme.test for saved login "acme"'
          ),
          expect.anything()
        );
      } finally {
        warn.mockRestore();
      }
    });
  });

  it("signs a new browser in before handing out the connection", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      await saveLogin(browser, fake, "acme");

      const connection = await browser.connect();
      const agent = fake.session(connection.sessionId);
      const applied = agent.commands.map((c) => c.method);
      await connection.cdp.send("Target.getTargets");
      connection.cdp.disconnect();

      expect(applied).toContain("Storage.setCookies");
      expect(agent.cookies.map((c) => c.value)).toEqual([
        "acme-session-value-1"
      ]);
      expect(
        Object.fromEntries(agent.localStorage.get("https://acme.test")!)
      ).toEqual({
        token: "acme-token-secret"
      });
    });
  });

  it("applies once per browser, again after a save, and again after a restart", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      await saveLogin(browser, fake, "acme");
      const applies = (sessionId: string) =>
        fake
          .session(sessionId)
          .commands.filter((c) => c.method === "Storage.setCookies").length;
      const connect = async () => {
        const connection = await browser.connect();
        connection.cdp.disconnect();
        return connection.sessionId;
      };

      const first = await connect();
      expect(await connect()).toBe(first);
      expect(applies(first)).toBe(1);

      await saveLogin(browser, fake, "beta");
      expect(await connect()).toBe(first);
      expect(applies(first)).toBe(2);

      fake.kill(first);
      const replaced = await connect();
      expect(replaced).not.toBe(first);
      expect(
        fake
          .session(replaced)
          .cookies.map((c) => c.domain)
          .sort()
      ).toEqual(["acme.test", "beta.test"]);
    });
  });

  it("revoke forgets the login and closes the browser that has it", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      await saveLogin(browser, fake, "acme");
      const signedIn = await agentSessionId(browser);
      (await browser.connect()).cdp.disconnect();

      expect(await browser.logins!.revoke("acme")).toBe(true);
      expect(await browser.logins!.revoke("acme")).toBe(false);
      expect(fake.session(signedIn).dead).toBe(true);
      const next = await browser.connect();
      next.cdp.disconnect();
      expect(fake.session(next.sessionId).cookies).toEqual([]);
    });
  });

  it("doesn't decrypt a record copied into another agent or browser", async () => {
    let copied: [string, unknown][] = [];
    await withCapabilityHarness(async ({ install, storage }) => {
      const fake = createSavedLoginsFakeBinding();
      await saveLogin(install(loginsBrowser(fake)).capability, fake, "acme");
      copied = [...(await storage.list({ prefix: "browser:logins:" }))];
    });

    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    try {
      // Another agent (a fresh Durable Object), same browser name.
      await withCapabilityHarness(async ({ install, storage }) => {
        const fake = createSavedLoginsFakeBinding();
        const { capability: browser } = install(loginsBrowser(fake));
        for (const [key, value] of copied) await storage.put(key, value);
        const connection = await browser.connect();
        connection.cdp.disconnect();
        expect(fake.session(connection.sessionId).cookies).toEqual([]);
      });

      // The same agent's other browser.
      await withCapabilityHarness(async ({ install, storage }) => {
        const fake = createSavedLoginsFakeBinding();
        await saveLogin(install(loginsBrowser(fake)).capability, fake, "acme");
        const { capability: other } = install(loginsBrowser(fake, "other"));
        for (const [key, value] of await storage.list({
          prefix: "browser:logins:7:default:"
        })) {
          await storage.put(key.replace("7:default:", "5:other:"), value);
        }
        const connection = await other.connect();
        connection.cdp.disconnect();
        expect(fake.session(connection.sessionId).cookies).toEqual([]);
      });
      expect(warn).toHaveBeenCalledWith(
        expect.stringContaining("doesn't decrypt")
      );
    } finally {
      warn.mockRestore();
    }
  });

  it("refuses cookie and storage commands only on a browser with saved logins", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      const { capability: plain } = install(
        new Browser({ name: "plain", provider: browserRun(fake.browser) })
      );
      const session = browser.session();
      const plainSession = plain.session();
      try {
        for (const method of [
          "Storage.getCookies",
          "Storage.setCookies",
          "Storage.clearDataForOrigin",
          "Network.getAllCookies",
          "Network.getCookies",
          "Network.deleteCookies",
          "DOMStorage.getDOMStorageItems",
          "IndexedDB.requestData"
        ]) {
          await expect(
            session.send({ method, sessionId: "active" })
          ).rejects.toThrow(`${method} is not available: cookies and storage`);
        }
        await expect(
          plainSession.send({ method: "Storage.getCookies" })
        ).resolves.toEqual({
          cookies: []
        });
      } finally {
        await session.close();
        await plainSession.close();
      }
    });
  });

  it("redacts saved values from results, errors, and the debug log", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      await saveLogin(browser, fake, "acme");
      const session = browser.session();
      const evaluate = (expression: string) =>
        session.send({
          method: "Runtime.evaluate",
          params: { expression },
          sessionId: "active"
        });
      try {
        await session.send({
          method: "Page.navigate",
          params: { url: "https://acme.test/" },
          sessionId: "active"
        });
        expect(await evaluate('localStorage.getItem("token")')).toEqual({
          result: { value: "[saved acme localStorage token]" }
        });
        fake.session(await agentSessionId(browser)).cookies[0]!.httpOnly =
          false;
        expect(await evaluate("document.cookie")).toEqual({
          result: { value: "sid=[saved acme cookie sid]" }
        });
        expect(await evaluate("throw:saved")).toMatchObject({
          exceptionDetails: { text: "Uncaught [saved acme localStorage token]" }
        });
        const log = JSON.stringify(await session.getDebugLog({ limit: 400 }));
        expect(log).not.toContain("acme-token-secret");
        expect(log).not.toContain("acme-session-value-1");
      } finally {
        await session.close();
      }
    });
  });

  it("browserTool: describes the sites, lists them, and redacts logs and errors", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      await saveLogin(browser, fake, "acme");
      const tool = browserTool({ browser, loader: env.LOADER });

      expect(tool.description).toContain("## Saved logins");
      expect(tool.description).toContain(
        "`acme` — Acme (https://acme.test/login)"
      );

      expect(
        await tool.execute({ code: "async () => browser.listLogins()" }, {})
      ).toMatchObject({
        status: "completed",
        result: [
          { site: "acme", label: "Acme", signedIn: true },
          { site: "beta", label: "Beta", signedIn: false }
        ]
      });

      const leaked = await tool.execute(
        {
          code: `async () => {
            await browser.cdp({ method: "Page.navigate", params: { url: "https://acme.test/" }, sessionId: "active" });
            const r = await browser.cdp({ method: "Runtime.evaluate", params: { expression: 'localStorage.getItem("token")' }, sessionId: "active" });
            console.log("token is", r.result.value);
            throw new Error("still " + r.result.value);
          }`
        },
        {}
      );
      expect(JSON.stringify(leaked)).not.toContain("acme-token-secret");
      expect(leaked).toMatchObject({
        status: "error",
        error: expect.stringContaining("[saved acme localStorage token]")
      });
    });
  });

  it("says which saved logins a restarted browser was signed in to", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      await saveLogin(browser, fake, "acme");
      const run = async () => {
        const session = browser.session({ scope: "chat" });
        await session.send({ method: "Target.getTargets" });
        return session.close();
      };

      expect((await run())?.restoredLogins).toBeUndefined();
      fake.kill(await agentSessionId(browser));
      const report = await run();
      expect(report).toMatchObject({
        restarted: true,
        restoredLogins: ["Acme"]
      });
      expect(report?.notices[0]).toContain(
        "signed in again to the saved logins (Acme)"
      );
    });
  });

  it("captures rotated cookies of saved sites, and nothing else", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      await saveLogin(browser, fake, "acme");

      const session = browser.session();
      await session.send({ method: "Target.getTargets" });
      const agent = fake.session(await agentSessionId(browser));
      // The site rotates its cookie, and the model signs in to beta itself.
      agent.cookies[0]!.value = "acme-session-value-2";
      agent.cookies.push({
        ...agent.cookies[0]!,
        domain: "beta.test",
        value: "model-made"
      });
      await session.close();

      expect((await browser.logins!.list()).map((l) => l.site)).toEqual([
        "acme"
      ]);
      fake.kill(await agentSessionId(browser));
      const next = await browser.connect();
      next.cdp.disconnect();
      expect(
        fake.session(next.sessionId).cookies.map((c) => [c.domain, c.value])
      ).toEqual([["acme.test", "acme-session-value-2"]]);
    });
  });

  it("keeps a saved login when the page clears its cookies", async () => {
    await withCapabilityHarness(async ({ install }) => {
      const fake = createSavedLoginsFakeBinding();
      const { capability: browser } = install(loginsBrowser(fake));
      await saveLogin(browser, fake, "acme");

      const session = browser.session();
      await session.send({ method: "Target.getTargets" });
      fake.session(await agentSessionId(browser)).cookies = [];
      await session.close();

      fake.kill(await agentSessionId(browser));
      const next = await browser.connect();
      next.cdp.disconnect();
      expect(fake.session(next.sessionId).cookies.map((c) => c.value)).toEqual([
        "acme-session-value-1"
      ]);
    });
  });
});
