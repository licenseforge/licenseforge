// Every user-visible string goes through t(). English only for now; another
// language is a second catalogue with the same keys.
const en = {
  "app.name": "LicenseForge",
  "login.title": "Sign in to LicenseForge",
  "login.body": "You sign in with your organization's identity provider. LicenseForge never sees your password.",
  "login.button": "Continue to sign in",
  "login.bannerTitle": "System use notification",
  "login.agree": "I have read and agree to this notice",
  "login.bannerChanged": "The notice changed. Please read and agree to it again.",
  "nav.skip": "Skip to content",
  "tenant.label": "Tenant",
  "tenant.none": "You are not a member of any tenant yet.",
  "user.menu": "Account menu for {name}",
  "user.logout": "Sign out",
  "user.logoutFailed": "Sign-out failed. Try again.",
  "theme.toggle": "Theme: {mode}. Change theme",
  "theme.light": "light",
  "theme.dark": "dark",
  "theme.system": "system",
  "overview.title": "Overview",
  "overview.body": "Active customers, activations and failures for {tenant} will appear here.",
  "error.load": "Something went wrong. Reload the page to try again.",
  "notfound.title": "Page not found",
} as const;

export type MessageKey = keyof typeof en;

export function t(key: MessageKey, vars: Record<string, string> = {}): string {
  return en[key].replace(/\{(\w+)\}/g, (m, k: string) => vars[k] ?? m);
}
