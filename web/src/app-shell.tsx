import { useMutation, useQuery } from "@tanstack/react-query";
import { getRouteApi, Outlet, useNavigate, useParams } from "@tanstack/react-router";
import { LogOut, Monitor, Moon, Sun, User } from "lucide-react";
import { useState } from "react";
import { logout } from "@/api/session";
import { tenantsQuery } from "@/api/tenants";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { t } from "@/i18n";
import { applyTheme, storedTheme, type ThemeMode } from "@/theme";

const app = getRouteApi("/app");

export function AppShell() {
  return (
    <>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-2 focus:top-2 focus:rounded-md focus:bg-background focus:p-2"
      >
        {t("nav.skip")}
      </a>
      <header className="flex items-center gap-4 border-b px-4 py-2">
        <span className="font-semibold">{t("app.name")}</span>
        <TenantSwitcher />
        <div className="ml-auto flex items-center gap-1">
          <ThemeToggle />
          <UserMenu />
        </div>
      </header>
      <main id="main" tabIndex={-1} className="p-6 outline-none">
        <Outlet />
      </main>
    </>
  );
}

function TenantSwitcher() {
  const { data: tenants = [] } = useQuery(tenantsQuery);
  const { slug } = useParams({ strict: false });
  const navigate = useNavigate();
  if (tenants.length === 0) return null;
  // A native select: keyboard and screen-reader support for free.
  return (
    <label className="flex items-center gap-2 text-sm">
      <span className="sr-only">{t("tenant.label")}</span>
      <select
        className="h-9 rounded-md border bg-background px-2 focus-visible:ring-[3px] focus-visible:ring-ring/50 outline-none"
        value={slug ?? ""}
        onChange={(e) => void navigate({ to: "/t/$slug", params: { slug: e.target.value } })}
      >
        {slug === undefined && <option value="" disabled />}
        {tenants.map((tn) => (
          <option key={tn.slug} value={tn.slug}>
            {tn.name}
          </option>
        ))}
      </select>
    </label>
  );
}

const next: Record<ThemeMode, ThemeMode> = { system: "light", light: "dark", dark: "system" };
const icon = { system: Monitor, light: Sun, dark: Moon };

function ThemeToggle() {
  const [mode, setMode] = useState(storedTheme);
  const Icon = icon[mode];
  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label={t("theme.toggle", { mode: t(`theme.${mode}`) })}
      onClick={() => {
        applyTheme(next[mode]);
        setMode(next[mode]);
      }}
    >
      <Icon aria-hidden />
    </Button>
  );
}

function UserMenu() {
  const { session } = app.useRouteContext();
  const out = useMutation({
    mutationFn: () => logout(session.csrf_token),
    // A full navigation drops every cached query along with the session.
    onSuccess: () => window.location.assign("/login"),
  });
  return (
    <>
      {out.isError && (
        <span role="alert" className="text-sm">
          {t("user.logoutFailed")}
        </span>
      )}
      <DropdownMenu modal={false}>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon" aria-label={t("user.menu", { name: session.user.name || session.user.email })}>
            <User aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel>
            <div>{session.user.name}</div>
            <div className="text-xs font-normal text-muted-foreground">{session.user.email}</div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem disabled={out.isPending} onSelect={() => out.mutate()}>
            <LogOut aria-hidden />
            {t("user.logout")}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </>
  );
}
