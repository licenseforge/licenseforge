import { useQuery } from "@tanstack/react-query";
import { Link, Outlet, useParams } from "@tanstack/react-router";
import { useState } from "react";
import { authConfigQuery, loginHref } from "@/api/session";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

export function LoginPage() {
  const config = useQuery(authConfigQuery);
  const [agreed, setAgreed] = useState(false);
  const href = loginHref(config.data, agreed);
  return (
    <main className="mx-auto flex min-h-svh max-w-xl flex-col justify-center gap-4 p-6">
      <h1 className="text-2xl font-semibold">{t("login.title")}</h1>
      <p className="text-muted-foreground">{t("login.body")}</p>
      {/* Set by the server when the banner changed after the user agreed. */}
      {new URLSearchParams(window.location.search).has("banner_changed") && (
        <p role="alert" className="text-sm font-medium">
          {t("login.bannerChanged")}
        </p>
      )}
      {config.data?.banner && (
        <section aria-labelledby="banner-title" className="rounded-md border p-4">
          <h2 id="banner-title" className="mb-2 font-semibold">
            {t("login.bannerTitle")}
          </h2>
          {/* Plain text, never HTML: React escapes it; line breaks kept. */}
          <p className="whitespace-pre-wrap text-sm">{config.data.banner}</p>
          <label className="mt-4 flex items-center gap-2 text-sm">
            <input type="checkbox" className="size-4" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
            {t("login.agree")}
          </label>
        </section>
      )}
      {config.isError && (
        <p role="alert" className="text-sm">
          {t("error.load")}
        </p>
      )}
      {/* A real link: the server's /auth/login needs a full page navigation. */}
      {href ? (
        <Button asChild className="self-start">
          <a href={href}>{t("login.button")}</a>
        </Button>
      ) : (
        <Button className="self-start" disabled>
          {t("login.button")}
        </Button>
      )}
    </main>
  );
}

export function TenantLayout() {
  const { slug } = useParams({ from: "/app/t/$slug" });
  const link = "rounded-md px-2 py-1 text-sm hover:bg-accent [&.active]:font-semibold [&.active]:underline";
  return (
    <>
      <nav aria-label={t("app.name")} className="mb-6 flex gap-2">
        <Link to="/t/$slug" params={{ slug }} activeOptions={{ exact: true }} className={link}>
          {t("nav.overview")}
        </Link>
        <Link to="/t/$slug/settings/api-tokens" params={{ slug }} className={link}>
          {t("nav.tokens")}
        </Link>
      </nav>
      <Outlet />
    </>
  );
}

export function Overview() {
  const { slug } = useParams({ from: "/app/t/$slug/" });
  return (
    <>
      <h1 className="text-2xl font-semibold">{t("overview.title")}</h1>
      <p className="mt-2 text-muted-foreground">{t("overview.body", { tenant: slug })}</p>
    </>
  );
}

export function NoTenants() {
  return <p className="text-muted-foreground">{t("tenant.none")}</p>;
}

export function NotFound() {
  return <h1 className="p-6 text-2xl font-semibold">{t("notfound.title")}</h1>;
}

export function ErrorPage() {
  return (
    <p role="alert" className="p-6">
      {t("error.load")}
    </p>
  );
}
