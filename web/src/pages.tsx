import { useQuery } from "@tanstack/react-query";
import { Link, Outlet, useParams } from "@tanstack/react-router";
import { useState } from "react";
import { canReadAudit } from "@/api/audit";
import { authConfigQuery, loginHref } from "@/api/session";
import { stepUpHref, tenantsQuery } from "@/api/tenants";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

export function LoginPage() {
  const config = useQuery(authConfigQuery);
  const [agreed, setAgreed] = useState(false);
  const search = new URLSearchParams(window.location.search);
  const href = loginHref(config.data, agreed, window.location.search);
  return (
    <main className="mx-auto flex min-h-svh max-w-xl flex-col justify-center gap-4 p-6">
      <h1 className="text-2xl font-semibold">{t("login.title")}</h1>
      <p className="text-muted-foreground">{t("login.body")}</p>
      {/* Set by the server when the banner changed after the user agreed. */}
      {search.has("banner_changed") && (
        <p role="alert" className="text-sm font-medium">
          {t("login.bannerChanged")}
        </p>
      )}
      {/* Set by the server when the IdP didn't prove the level asked for (ADR-0038). */}
      {search.has("step_up_failed") && (
        <p role="alert" className="text-sm font-medium">
          {t(search.get("step_up_failed") === "phishing_resistant" ? "login.stepUpFailedPhishingResistant" : "login.stepUpFailed")}
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
  const { data: tenants } = useQuery(tenantsQuery);
  const caller = tenants?.find((tn) => tn.slug === slug);
  const link = "rounded-md px-2 py-1 text-sm hover:bg-accent [&.active]:font-semibold [&.active]:underline";
  // The session doesn't meet the tenant's MFA policy (ADR-0038): every
  // tenant route would answer 403, so say why and offer the step-up.
  if (caller && !caller.accessible && caller.mfaPolicy !== "none") {
    const strong = caller.mfaPolicy === "phishing_resistant";
    return (
      <section aria-labelledby="mfa-title" className="mx-auto max-w-xl">
        <h1 id="mfa-title" className="text-2xl font-semibold">{t("mfa.title", { name: caller.name })}</h1>
        <p className="mt-2">{t(strong ? "mfa.bodyPhishingResistant" : "mfa.body")}</p>
        <p className="mt-6">
          {/* A real link: the server's /auth/login needs a full page navigation. */}
          <a href={stepUpHref(caller.mfaPolicy, slug)} className="inline-flex h-9 items-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground">
            {t("mfa.stepUp")}
          </a>
        </p>
      </section>
    );
  }
  return (
    <>
      <nav aria-label={t("app.name")} className="mb-6 flex gap-2">
        <Link to="/t/$slug" params={{ slug }} activeOptions={{ exact: true }} className={link}>
          {t("nav.overview")}
        </Link>
        <Link to="/t/$slug/products" params={{ slug }} className={link}>
          {t("nav.products")}
        </Link>
        <Link to="/t/$slug/customers" params={{ slug }} className={link}>
          {t("nav.customers")}
        </Link>
        <Link to="/t/$slug/licenses" params={{ slug }} className={link}>
          {t("nav.licenses")}
        </Link>
        <Link to="/t/$slug/settings/members" params={{ slug }} className={link}>
          {t("nav.members")}
        </Link>
        <Link to="/t/$slug/settings/api-tokens" params={{ slug }} className={link}>
          {t("nav.tokens")}
        </Link>
        {caller?.role === "owner" && (
          <Link to="/t/$slug/settings/security" params={{ slug }} className={link}>
            {t("nav.security")}
          </Link>
        )}
        {canReadAudit(caller) && (
          <Link to="/t/$slug/settings/audit" params={{ slug }} className={link}>
            {t("nav.audit")}
          </Link>
        )}
      </nav>
      <Outlet />
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
