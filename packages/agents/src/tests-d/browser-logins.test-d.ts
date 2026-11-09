/**
 * Type-level tests for `new Browser({ logins })`: the option's shape, the
 * host-side `browser.logins`, and the narrower view a `BrowserSession` gets
 * through `BrowserSource`.
 */
import { expectTypeOf } from "vitest";
import {
  Browser,
  browserRun,
  type BrowserLogins,
  type BrowserSessionLogins,
  type BrowserSource,
  type SavedLoginInfo,
  type SavedLoginStart,
  type SavedLoginStatus
} from "../browser";

declare const env: { BROWSER: Fetcher; BROWSER_LOGINS_KEY: string };

const browser = new Browser({
  provider: browserRun(env.BROWSER),
  logins: {
    encryptionKey: env.BROWSER_LOGINS_KEY,
    sites: {
      github: { label: "GitHub", loginUrl: "https://github.com/login" },
      docs: {
        loginUrl: "https://docs.example.com/login",
        origins: ["https://docs.example.com", "https://api.example.com"]
      }
    }
  }
});

expectTypeOf(browser.logins).toEqualTypeOf<BrowserLogins | undefined>();
expectTypeOf(browser).toExtend<BrowserSource>();
expectTypeOf<BrowserLogins>().toExtend<BrowserSessionLogins>();

declare const logins: BrowserLogins;
expectTypeOf(logins.begin("github")).resolves.toEqualTypeOf<SavedLoginStart>();
expectTypeOf(logins.save("id")).resolves.toEqualTypeOf<SavedLoginInfo>();
expectTypeOf(logins.status()).resolves.toEqualTypeOf<SavedLoginStatus[]>();
// What the model sees carries no values or timestamps.
expectTypeOf<keyof SavedLoginStatus>().toEqualTypeOf<
  "site" | "label" | "url" | "signedIn"
>();

new Browser({
  provider: browserRun(env.BROWSER),
  // @ts-expect-error saved logins need an encryption key
  logins: { sites: { github: { loginUrl: "https://github.com/login" } } }
});

new Browser({
  provider: browserRun(env.BROWSER),
  logins: {
    encryptionKey: env.BROWSER_LOGINS_KEY,
    // @ts-expect-error a site needs a loginUrl
    sites: { github: { label: "GitHub" } }
  }
});
