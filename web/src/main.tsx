import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { queryRetry } from "@/api/client";
import { queryErrorHandler } from "@/api/tenants";
import { createAppRouter } from "@/router";
import { applyTheme, storedTheme } from "@/theme";
import "./index.css";

applyTheme(storedTheme());

const onError = queryErrorHandler(() => queryClient);
const queryClient: QueryClient = new QueryClient({
  defaultOptions: { queries: { retry: queryRetry } },
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
