import type { QueryClient } from "@tanstack/react-query";
import { createRootRouteWithContext, createRoute, createRouter, Outlet, redirect } from "@tanstack/react-router";
import { requireSession } from "@/api/session";
import { tenantsQuery } from "@/api/tenants";
import { AppShell } from "@/app-shell";
import { ErrorPage, LoginPage, NoTenants, NotFound, Overview } from "@/pages";

const rootRoute = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: Outlet,
  notFoundComponent: NotFound,
  errorComponent: ErrorPage,
});

const loginRoute = createRoute({ getParentRoute: () => rootRoute, path: "login", component: LoginPage });

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
    const [first] = await context.queryClient.ensureQueryData(tenantsQuery);
    if (first) throw redirect({ to: "/t/$slug", params: { slug: first.slug } });
  },
  component: NoTenants,
});

// Tenant in the URL (ADR-0020): /t/{slug}/..., so links are shareable.
const tenantRoute = createRoute({ getParentRoute: () => appRoute, path: "t/$slug", component: Outlet });
const overviewRoute = createRoute({ getParentRoute: () => tenantRoute, path: "/", component: Overview });

const routeTree = rootRoute.addChildren([loginRoute, appRoute.addChildren([indexRoute, tenantRoute.addChildren([overviewRoute])])]);

export function createAppRouter(queryClient: QueryClient) {
  return createRouter({ routeTree, context: { queryClient } });
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
