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
  "nav.overview": "Overview",
  "nav.tokens": "API tokens",
  "tokens.title": "API tokens",
  "tokens.body": "Tokens let scripts and integrations call the API as this tenant.",
  "tokens.new": "New token",
  "tokens.empty": "No API tokens yet.",
  "tokens.more": "Load more",
  "tokens.col.name": "Name",
  "tokens.col.role": "Role",
  "tokens.col.products": "Products",
  "tokens.col.token": "Token",
  "tokens.col.expires": "Expires",
  "tokens.col.lastUsed": "Last used",
  "tokens.col.status": "Status",
  "tokens.allProducts": "All products",
  "tokens.someProducts": "{count} products",
  "tokens.never": "Never",
  "tokens.status.active": "Active",
  "tokens.status.revoked": "Revoked",
  "tokens.status.expired": "Expired",
  "tokens.revoke": "Revoke",
  "tokens.revokeTitle": "Revoke {name}?",
  "tokens.revokeBody": "Anything using this token stops working at once. This can't be undone.",
  "tokens.cancel": "Cancel",
  "tokens.create": "Create token",
  "tokens.close": "Close",
  "tokens.field.name": "Name",
  "tokens.field.role": "Role",
  "tokens.field.allProducts": "All products",
  "tokens.field.productIds": "Product IDs (comma-separated)",
  "tokens.field.ttl": "Expires after",
  "tokens.ttl.days": "{days} days",
  "tokens.secretTitle": "Copy your new token",
  "tokens.secretWarning": "This is the only time the token is shown. Store it somewhere safe now; it can't be recovered.",
  "tokens.copy": "Copy",
  "tokens.copied": "Copied",
  "tokens.copyFailed": "Copying failed. Select the token and copy it yourself.",
  "problem.unauthenticated": "Your session has ended. Sign in again.",
  "problem.forbidden": "You don't have permission to do this.",
  "problem.not_found": "Not found. It may have been removed.",
  "problem.csrf_failed": "The request was refused for your security. Reload the page and try again.",
  "problem.validation_failed": "Some fields need fixing.",
  "problem.invalid_request": "The request was not valid.",
  "problem.invalid_cursor": "The list changed. Reload the page.",
  "problem.body_too_large": "The request is too large.",
  "problem.internal": "Something went wrong on our side. Try again.",
  "problem.unknown": "Something went wrong. Try again.",
} as const;

export type MessageKey = keyof typeof en;

export const hasMessage = (key: string): key is MessageKey => Object.hasOwn(en, key);

export function t(key: MessageKey, vars: Record<string, string> = {}): string {
  return en[key].replace(/\{(\w+)\}/g, (m, k: string) => vars[k] ?? m);
}

/** The message for a problem code (ADR-0032); unknown codes get a generic one. */
export function problemMessage(code: string): string {
  const key = `problem.${code}`;
  return t(hasMessage(key) ? key : "problem.unknown");
}
