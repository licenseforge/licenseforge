import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ApiError } from "@/api/client";
import { createAppRouter } from "@/router";
import { applyTheme, storedTheme } from "@/theme";
import "./index.css";

applyTheme(storedTheme());

// A session that ends mid-use (expiry, logout in another tab) sends the user to sign in.
const onError = (e: Error) => {
  if (e instanceof ApiError && e.status === 401) window.location.assign("/login");
};
const queryClient = new QueryClient({
  queryCache: new QueryCache({ onError }),
  mutationCache: new MutationCache({ onError }),
});
const router = createAppRouter(queryClient);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
