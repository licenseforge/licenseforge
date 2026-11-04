import { useParams } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { t } from "@/i18n";

export function LoginPage() {
  return (
    <main className="mx-auto flex min-h-svh max-w-md flex-col justify-center gap-4 p-6">
      <h1 className="text-2xl font-semibold">{t("login.title")}</h1>
      <p className="text-muted-foreground">{t("login.body")}</p>
      {/* A real link: the server's /auth/login needs a full page navigation. */}
      <Button asChild className="self-start">
        <a href="/auth/login">{t("login.button")}</a>
      </Button>
    </main>
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
