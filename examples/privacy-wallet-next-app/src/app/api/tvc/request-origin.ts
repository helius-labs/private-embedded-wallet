export function sameRequestOrigin(request: Request): string {
  const value = request.headers.get("origin");
  if (!value) throw new Error("CrossOriginRequestDenied");
  const origin = new URL(value);
  if (
    origin.origin !== value ||
    !["http:", "https:"].includes(origin.protocol)
  ) {
    throw new Error("CrossOriginRequestDenied");
  }

  const forwardedHost = request.headers
    .get("x-forwarded-host")
    ?.split(",", 1)[0]
    ?.trim();
  const requestHost = request.headers.get("host");
  const urlHost = new URL(request.url).host;
  if (![forwardedHost, requestHost, urlHost].includes(origin.host)) {
    throw new Error("CrossOriginRequestDenied");
  }
  return origin.origin;
}
