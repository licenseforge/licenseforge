import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useRouter, useRouterState } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { ApiError } from "@/api/client";
import { acceptInvitation } from "@/api/members";
import { sessionQuery } from "@/api/session";
import { tenantsQuery } from "@/api/tenants";
import { Button } from "@/components/ui/button";
import { errorText } from "@/components/modal";
import { t } from "@/i18n";
import { forgetInviteToken, takeInviteToken } from "@/invite";

export function InvitePage() {
  const hash = useRouterState({ select: (s) => s.location.hash });
  const router = useRouter();
  const [token] = useState(() => takeInviteToken(hash));
  // Off the address bar (and the router's state) once read.
  useEffect(() => {
    if (hash) router.history.replace("/invite");
  }, [hash, router]);
  const session = useQuery(sessionQuery);
  const qc = useQueryClient();
  const navigate = useNavigate();
  const accept = useMutation({
    mutationFn: () => acceptInvitation(token ?? ""),
    onSuccess: async (m) => {
      forgetInviteToken();
      const tenants = await qc.fetchQuery({ ...tenantsQuery, staleTime: 0 });
      const slug = tenants.find((tn) => tn.id === m.tenant_id)?.slug;
      await navigate(slug ? { to: "/t/$slug", params: { slug } } : { to: "/" });
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 422) forgetInviteToken(); // won't work later either
    },
  });
  const refused = accept.error instanceof ApiError && accept.error.status === 422;
  return (
    <main className="mx-auto flex min-h-svh max-w-md flex-col justify-center gap-4 p-6">
      <h1 className="text-2xl font-semibold">{t("invite.title")}</h1>
      {!token ? (
        <p>{t("invite.noToken")}</p>
      ) : session.isPending ? null : !session.data ? (
        <>
          <p className="text-muted-foreground">{t("invite.signIn")}</p>
          <Button asChild className="self-start">
            <a href="/login">{t("login.button")}</a>
          </Button>
        </>
      ) : (
        <>
          <p className="text-muted-foreground">{t("invite.body", { email: session.data.user.email })}</p>
          {accept.isError && (
            <p role="alert" className="text-sm font-medium">
              {refused ? t("invite.refused") : errorText(accept.error)}
            </p>
          )}
          <div className="flex gap-2">
            {/* Only a refusal is final; other errors (network, 5xx) can be retried. */}
            <Button disabled={accept.isPending || refused} onClick={() => accept.mutate()}>
              {t("invite.accept")}
            </Button>
            <Button
              variant="ghost"
              onClick={() => {
                forgetInviteToken(); // else / keeps sending the user back here
                void navigate({ to: "/" });
              }}
            >
              {t("invite.dismiss")}
            </Button>
          </div>
        </>
      )}
    </main>
  );
}
