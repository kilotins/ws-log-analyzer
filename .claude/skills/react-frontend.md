# React Frontend Patterns

## Stack

- **React 18+** with TypeScript (strict mode)
- **Vite** for build tooling (fast HMR, ESM-native)
- **Tailwind CSS** for styling (utility-first, dark mode with `class` strategy)
- **shadcn/ui** for base components (Button, Dialog, Table, Card, etc.)
- **Tanstack Query** for server state management
- **React Router v6+** for routing
- **react-virtuoso** for virtualized lists (event browser)
- **Recharts** for timeline histograms and charts
- **Monaco Editor** for log file viewing (optional, heavy)

## File Structure

```
frontend/src/
├── components/       # Shared UI components
│   ├── ui/           # shadcn/ui components (auto-generated)
│   ├── IncidentCard.tsx
│   ├── TimelineChart.tsx
│   ├── EventBrowser.tsx
│   └── AIAssistant.tsx
├── views/            # Page-level views (one per route)
│   ├── SessionList.tsx
│   ├── Analysis.tsx
│   ├── WorkspaceSettings.tsx
│   ├── OrgSettings.tsx
│   ├── Login.tsx
│   └── Signup.tsx
├── hooks/            # Custom hooks
│   ├── useApi.ts         # Typed API client
│   ├── useSessions.ts    # Session CRUD hooks
│   ├── useAnalysis.ts    # Analysis data hooks
│   ├── useAI.ts          # AI streaming hooks
│   ├── useWebSocket.ts   # Real-time updates
│   └── useAuth.ts        # Auth state + login/logout
├── lib/              # Utilities and types
│   ├── api.ts            # Base fetch client
│   ├── types.ts          # API response types
│   ├── constants.ts      # Route paths, config
│   └── utils.ts          # Formatters, helpers
└── App.tsx           # Router + QueryClientProvider + AuthProvider
```

## Routing

```tsx
// App.tsx
import { BrowserRouter, Routes, Route } from "react-router-dom";

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/:orgSlug/:wsSlug" element={<WorkspaceLayout />}>
            <Route index element={<SessionList />} />
            <Route path="sessions/:sessionId" element={<Analysis />} />
            <Route path="settings" element={<WorkspaceSettings />} />
          </Route>
          <Route path="/:orgSlug/settings" element={<OrgSettings />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
```

## State Management

### Server State (Tanstack Query)

All API data goes through Tanstack Query. No Redux, no Zustand for server state.

```tsx
// hooks/useSessions.ts
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";

export function useSessions(wsSlug: string) {
  return useQuery({
    queryKey: ["sessions", wsSlug],
    queryFn: () => api.get(`/api/v1/sessions`),
    staleTime: 30_000, // 30s — analysis data doesn't change often
  });
}

export function useCreateSession(wsSlug: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateSessionInput) => api.post(`/api/v1/sessions`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sessions", wsSlug] });
    },
  });
}
```

### Local State (useState only)

Only for UI-specific state: form inputs, expanded/collapsed sections, active tab.

```tsx
const [activeTab, setActiveTab] = useState<"summary" | "incidents" | "timeline" | "events" | "ai" | "export">("summary");
const [eventFilter, setEventFilter] = useState({ level: "", code: "", search: "" });
```

## API Client

```tsx
// lib/api.ts
const BASE_URL = import.meta.env.VITE_API_URL || "";

class ApiClient {
  private token: string | null = null;

  async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const res = await fetch(`${BASE_URL}${path}`, {
      ...options,
      credentials: "include", // send cookies
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });
    if (!res.ok) {
      const error = await res.json().catch(() => ({ detail: res.statusText }));
      throw new ApiError(res.status, error.detail);
    }
    return res.json();
  }

  get<T>(path: string) { return this.request<T>(path); }
  post<T>(path: string, body?: unknown) {
    return this.request<T>(path, { method: "POST", body: JSON.stringify(body) });
  }
  delete(path: string) {
    return this.request(path, { method: "DELETE" });
  }
}

export const api = new ApiClient();
```

## AI Streaming (SSE)

```tsx
// hooks/useAI.ts
export function useAIStream(sessionId: string) {
  const [response, setResponse] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);

  const explain = useCallback(async (prompt: string) => {
    setResponse("");
    setIsStreaming(true);

    const res = await fetch(`/api/v1/sessions/${sessionId}/explain`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt }),
    });

    const reader = res.body!.getReader();
    const decoder = new TextDecoder();

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value);
      // Parse SSE: "data: ..."
      for (const line of chunk.split("\n")) {
        if (line.startsWith("data: ")) {
          const data = line.slice(6);
          if (data === "[DONE]") break;
          setResponse(prev => prev + data);
        }
      }
    }
    setIsStreaming(false);
  }, [sessionId]);

  return { response, isStreaming, explain };
}
```

## WebSocket (Real-time Updates)

```tsx
// hooks/useWebSocket.ts
export function useWebSocket(wsSlug: string) {
  const queryClient = useQueryClient();

  useEffect(() => {
    const ws = new WebSocket(`${WS_URL}/ws/${wsSlug}`);

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      switch (msg.type) {
        case "analysis_complete":
          queryClient.invalidateQueries({ queryKey: ["analysis", msg.session_id] });
          break;
        case "session_updated":
          queryClient.invalidateQueries({ queryKey: ["sessions", wsSlug] });
          break;
      }
    };

    ws.onclose = () => {
      // Reconnect after 3s
      setTimeout(() => useWebSocket(wsSlug), 3000);
    };

    return () => ws.close();
  }, [wsSlug, queryClient]);
}
```

## Virtualized Event Browser

For 100K+ events without DOM explosion:

```tsx
import { Virtuoso } from "react-virtuoso";

function EventBrowser({ events, filter }: { events: LogEvent[], filter: EventFilter }) {
  const filtered = useMemo(
    () => events.filter(e =>
      (!filter.level || e.level === filter.level) &&
      (!filter.code || e.code?.includes(filter.code)) &&
      (!filter.search || e.text.toLowerCase().includes(filter.search.toLowerCase()))
    ),
    [events, filter]
  );

  return (
    <Virtuoso
      data={filtered}
      itemContent={(index, event) => <EventRow event={event} />}
      style={{ height: "600px" }}
      overscan={200}
    />
  );
}
```

## Dark Mode

```tsx
// Tailwind config: darkMode: "class"
// Toggle in layout header
function DarkModeToggle() {
  const [dark, setDark] = useState(
    () => document.documentElement.classList.contains("dark")
  );

  const toggle = () => {
    document.documentElement.classList.toggle("dark");
    setDark(!dark);
    localStorage.setItem("theme", dark ? "light" : "dark");
  };

  return <Button variant="ghost" onClick={toggle}>{dark ? "☀" : "●"}</Button>;
}
```

## Performance

- **Code splitting**: `React.lazy()` + `Suspense` for views (Analysis is heavy)
- **Virtualization**: react-virtuoso for event lists (never render 100K DOM nodes)
- **Debounce**: search/filter inputs debounced at 300ms
- **Memoization**: `useMemo` for filtered/sorted event lists, analysis computations
- **staleTime**: Set to 30s for analysis data (it doesn't change after creation)

```tsx
// Lazy load heavy views
const Analysis = lazy(() => import("./views/Analysis"));
const OrgSettings = lazy(() => import("./views/OrgSettings"));

// In router
<Suspense fallback={<LoadingSpinner />}>
  <Route path="sessions/:sessionId" element={<Analysis />} />
</Suspense>
```

## Testing

- **Vitest** for unit/component tests (fast, Vite-native)
- **Testing Library** for component testing (render + user interaction)
- **MSW** (Mock Service Worker) for API mocking

```tsx
// Example component test
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SessionList } from "./SessionList";

test("shows sessions after loading", async () => {
  // MSW intercepts /api/v1/sessions and returns mock data
  render(
    <QueryClientProvider client={new QueryClient()}>
      <SessionList />
    </QueryClientProvider>
  );

  await waitFor(() => {
    expect(screen.getByText("prod-incident-2026-03-20")).toBeInTheDocument();
  });
});
```

## Vite Config

```ts
// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:8000",  // Proxy API to FastAPI in dev
      "/ws": { target: "ws://localhost:8000", ws: true },
    },
  },
});
```

## Gotchas

- **shadcn/ui components must be installed individually**: `npx shadcn-ui@latest add button`
- **Tanstack Query staleTime default is 0** — set to 30s+ for analysis data to avoid refetching on every focus
- **WebSocket reconnection** needs manual handling — use a reconnect wrapper or `reconnecting-websocket` package
- **Vite proxy** only works in dev — production serves React as static files behind the API
- **SSE parsing** must handle multi-line chunks — split on `\n` and filter for `data:` prefix
- **CORS credentials** — `credentials: "include"` is required for cookie auth, and the API must set `Access-Control-Allow-Credentials: true`
- **TypeScript strict mode** — enable from day one. Fixing thousands of `any` types later is painful.
