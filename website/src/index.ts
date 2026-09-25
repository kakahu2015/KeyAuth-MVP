const securityHeaders: Record<string, string> = {
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "base-uri 'self'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests"
  ].join("; "),
  "Permissions-Policy": "camera=(), geolocation=(), microphone=()",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-Robots-Tag": "all"
};

function withSecurityHeaders(response: Response, request: Request): Response {
  const headers = new Headers(response.headers);

  for (const [name, value] of Object.entries(securityHeaders)) {
    headers.set(name, value);
  }

  const pathname = new URL(request.url).pathname;
  const isDocument = pathname === "/" || pathname === "/privacy" || pathname.endsWith(".html");
  const isMutableAsset = pathname === "/styles.css" || pathname === "/script.js";

  headers.set(
    "Cache-Control",
    isDocument || isMutableAsset
      ? "public, max-age=0, must-revalidate"
      : "public, max-age=31536000, immutable"
  );

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

export default {
  async fetch(request, env): Promise<Response> {
    const response = await env.ASSETS.fetch(request);
    return withSecurityHeaders(response, request);
  }
} satisfies ExportedHandler<Env>;
