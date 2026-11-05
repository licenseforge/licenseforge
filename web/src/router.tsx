import type { QueryClient } from "@tanstack/react-query";
import { createRootRouteWithContext, createRoute, createRouter, Outlet, redirect, type RouterHistory } from "@tanstack/react-router";
import { requireSession } from "@/api/session";
import { tenantsQuery } from "@/api/tenants";
import { AppShell } from "@/app-shell";
import { Overview } from "@/overview-page";
import { ErrorPage, LoginPage, NoTenants, NotFound, TenantLayout } from "@/pages";
import { CustomersPage, ProductsPage } from "@/catalog-pages";
import { InvitePage } from "@/invite-page";
import { LicensesPage } from "@/licenses-page";
import { inviteWaiting } from "@/invite";
import { MembersPage } from "@/members-page";
import { TokensPage } from "@/tokens-page";

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
  },
  component: NoTenants,
});

// Tenant in the URL (ADR-0020): /t/{slug}/..., so links are shareable.
const tenantRoute = createRoute({ getParentRoute: () => appRoute, path: "t/$slug", component: TenantLayout });
const overviewRoute = createRoute({ getParentRoute: () => tenantRoute, path: "/", component: Overview });
const tokensRoute = createRoute({ getParentRoute: () => tenantRoute, path: "settings/api-tokens", component: TokensPage });
const membersRoute = createRoute({ getParentRoute: () => tenantRoute, path: "settings/members", component: MembersPage });
const productsRoute = createRoute({ getParentRoute: () => tenantRoute, path: "products", component: ProductsPage });
const customersRoute = createRoute({ getParentRoute: () => tenantRoute, path: "customers", component: CustomersPage });
const licensesRoute = createRoute({ getParentRoute: () => tenantRoute, path: "licenses", component: LicensesPage });

const routeTree = rootRoute.addChildren([
  loginRoute,
  inviteRoute,
  appRoute.addChildren([indexRoute, tenantRoute.addChildren([overviewRoute, productsRoute, customersRoute, licensesRoute, tokensRoute, membersRoute])]),
]);

export function createAppRouter(queryClient: QueryClient, history?: RouterHistory) {
  return createRouter({ routeTree, context: { queryClient }, history });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
