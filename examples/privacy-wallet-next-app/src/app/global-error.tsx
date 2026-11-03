"use client";

import { useEffect } from "react";

function reportClientError(error: Error & { digest?: string }): void {
  const body = JSON.stringify({
    name: error.name.slice(0, 100),
    message: error.message.slice(0, 1_000),
    stack: error.stack?.slice(0, 8_000),
    digest: error.digest?.slice(0, 200),
    path: window.location.pathname.slice(0, 500),
  });
  void fetch("/api/client-error", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
    keepalive: true,
  }).catch(() => undefined);
}

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => reportClientError(error), [error]);

  return (
    <html lang="en">
      <body className="flex min-h-screen items-center justify-center bg-white p-6 text-zinc-950 dark:bg-black dark:text-zinc-50">
        <main className="w-full max-w-md rounded-xl border border-zinc-200 p-6 shadow-sm dark:border-zinc-800">
          <h1 className="text-xl font-semibold">The wallet couldn’t open</h1>
          <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
            The error was reported. Retry once; if it happens again, we can now
            identify the failing component from the service logs.
          </p>
          <button
            type="button"
            onClick={reset}
            className="mt-5 rounded-lg bg-[#E84125] px-4 py-2 text-sm font-medium text-white hover:bg-[#d13920]"
          >
            Retry
          </button>
        </main>
      </body>
    </html>
  );
}
