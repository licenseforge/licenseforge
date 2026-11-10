import type { QueryClient } from "@tanstack/react-query";
import { createRootRouteWithContext, createRoute, createRouter, Outlet, redirect, type RouterHistory } from "@tanstack/react-router";
import { requireSession } from "@/api/session";
import { tenantsQuery } from "@/api/tenants";
import { AppShell } from "@/app-shell";
import { Overview } from "@/overview-page";
import { ErrorPage, LoginPage, NoTenants, NotFound, TenantLayout } from "@/pages";
import { CustomersPage, ProductsPage } from "@/catalog-pages";
import { ProductPage } from "@/product-page";
import { AuditPage } from "@/audit-page";
import { InvitePage } from "@/invite-page";
import { LicensesPage } from "@/licenses-page";
import { inviteWaiting } from "@/invite";
import { MembersPage } from "@/members-page";
import { TokensPage } from "@/tokens-page";
import { WebhooksPage } from "@/webhooks-page";
import { KeysPage } from "@/keys-page";
import { SecurityPage } from "@/security-page";
import { PlatformPage } from "@/platform-page";

const rootRoute = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: Outlet,
  notFoundComponent: NotFound,
  errorComponent: ErrorPage,
});

const loginRoute = createRoute({ getParentRoute: () => rootRoute, path: "login", component: LoginPage });
// Outside the session-required routes: it explains signing in first.
const inviteRoute = createRoute({ getParentRoute: () => rootRoute, path: "invite", component: InvitePage });

// Everything below needs a session; without one, beforeLoad redirects to /login.
const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "app",
  beforeLoad: async ({ context }) => ({ session: await requireSession(context.queryClient) }),
  component: AppShell,
});

const indexRoute = createRoute({
  getParentRoute: () => appRoute,
  path: "/",
  beforeLoad: async ({ context }) => {
    if (inviteWaiting()) throw redirect({ to: "/invite" }); // back from signing in to accept
    const [first] = await context.queryClient.ensureQueryData(tenantsQuery);
    if (first) throw redirect({ to: "/t/$slug", params: { slug: first.slug } });
    if (context.session.platform_admin) throw redirect({ to: "/platform" }); // a new install's admin onboards the first tenant
  },
  component: NoTenants,
});

// Tenant in the URL (ADR-0020): /t/{slug}/..., so links are shareable.
const tenantRoute = createRoute({ getParentRoute: () => appRoute, path: "t/$slug", component: TenantLayout });
const overviewRoute = createRoute({ getParentRoute: () => tenantRoute, path: "/", component: Overview });
const tokensRoute = createRoute({ getParentRoute: () => tenantRoute, path: "settings/api-tokens", component: TokensPage });
const webhooksRoute = createRoute({ getParentRoute: () => tenantRoute, path: "settings/webhooks", component: WebhooksPage });
const keysRoute = createRoute({ getParentRoute: () => tenantRoute, path: "settings/signing-keys", component: KeysPage });
const membersRoute = createRoute({ getParentRoute: () => tenantRoute, path: "settings/members", component: MembersPage });
const auditRoute = createRoute({ getParentRoute: () => tenantRoute, path: "settings/audit", component: AuditPage });
const securityRoute = createRoute({ getParentRoute: () => tenantRoute, path: "settings/security", component: SecurityPage });
const productsRoute = createRoute({ getParentRoute: () => tenantRoute, path: "products", component: ProductsPage });
const productRoute = createRoute({ getParentRoute: () => tenantRoute, path: "products/$id", component: ProductPage });
const customersRoute = createRoute({ getParentRoute: () => tenantRoute, path: "customers", component: CustomersPage });
const licensesRoute = createRoute({ getParentRoute: () => tenantRoute, path: "licenses", component: LicensesPage });
// Platform admins only (ADR-0042); for anyone else the API answers 403.
const platformRoute = createRoute({ getParentRoute: () => appRoute, path: "platform", component: PlatformPage });

const routeTree = rootRoute.addChildren([
  loginRoute,
  inviteRoute,
  appRoute.addChildren([indexRoute, platformRoute, tenantRoute.addChildren([overviewRoute, productsRoute, productRoute, customersRoute, licensesRoute, tokensRoute, webhooksRoute, keysRoute, membersRoute, auditRoute, securityRoute])]),
]);

export function createAppRouter(queryClient: QueryClient, history?: RouterHistory) {
  return createRouter({ routeTree, context: { queryClient }, history });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
