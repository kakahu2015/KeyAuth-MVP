const SITE_ORIGIN = "https://keytop.kakahu.org";
const PUBLIC_PAGES = ["/", "/privacy"] as const;

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

const unsupportedDiscoveryPaths = new Set([
  "/.well-known/api-catalog",
  "/.well-known/openid-configuration",
  "/.well-known/oauth-authorization-server",
  "/.well-known/oauth-protected-resource",
  "/auth.md",
  "/.well-known/mcp/server-card.json"
]);

const markdownPages: Record<(typeof PUBLIC_PAGES)[number], string> = {
  "/": `# KeyAuth

KeyAuth is a local-first TOTP authenticator for iPhone running iOS 26 or later.

- [App Store listing](https://apps.apple.com/us/app/keyauth-otp/id6814867894?l=zh-Hans-CN)
- [Open-source project](https://github.com/kakahu2015/KeyAuth-MVP)
- [Privacy information](https://keytop.kakahu.org/privacy)

## Security model

Account data is encrypted on the iPhone with AES-256-GCM. Face ID or the device passcode protects access to the device-bound key. When optional iCloud sync is enabled, CloudKit receives encrypted account blobs and required sync metadata; it does not receive the account plaintext or generated codes.

TOTP codes are generated locally. Once an account has been configured, code generation does not depend on a network connection.

## Recovery

If recovery is enabled, KeyAuth stores an encrypted recovery envelope in CloudKit. The independent Recovery Key stays with the user and is required to restore the vault on another iPhone.

## Supported devices

KeyAuth currently supports iPhone running iOS 26 or later. It does not support iPad or other platforms.
`,
  "/privacy": `# KeyAuth Privacy

Last updated: September 22, 2026.

KeyAuth is a local-first TOTP authenticator. Account data is encrypted on the device. Optional iCloud sync and recovery store encrypted data, and KeyAuth has no application server that receives plaintext account data or TOTP codes.

## Data inside the app

The issuer, account name, TOTP secret, algorithm, digits, period, and custom name are encrypted together as an account payload on the iPhone. TOTP generation happens locally.

## iCloud sync

When sync is enabled, CloudKit receives encrypted blobs and necessary metadata such as record identifiers, versions, and timestamps. The account plaintext is not stored as CloudKit fields.

## Keys and device authentication

The master key is held in a device Keychain item protected by Face ID, Touch ID, or the device passcode and bound to the current device. System authentication is required before the vault opens.

## iPhone recovery

If recovery is enabled, KeyAuth wraps the master-key ring with an independent Recovery Key and stores only the encrypted envelope in CloudKit. The Recovery Key is never uploaded and must be kept by the user.

## Website requests

This website provides no account, form, or app API and does not add third-party advertising or analytics scripts. Cloudflare may process standard request metadata under its service policies.

## Choices

Users can leave iCloud sync and recovery disabled and use KeyAuth as a local authenticator. Deleting an account removes it locally first and queues its cloud deletion; uninstalling the app does not automatically delete existing CloudKit records.

[View the KeyAuth source on GitHub](https://github.com/kakahu2015/KeyAuth-MVP)
`
};

function acceptsMarkdown(request: Request): boolean {
  const accept = request.headers.get("Accept");
  if (!accept) return false;

  return accept.split(",").some((mediaRange) => {
    const [mediaType, ...parameters] = mediaRange.trim().split(";");
    if (mediaType.trim().toLowerCase() !== "text/markdown") return false;

    const quality = parameters
      .map((parameter) => parameter.trim())
      .find((parameter) => parameter.toLowerCase().startsWith("q="));

    if (!quality) return true;
    const value = Number(quality.slice(2));
    return Number.isFinite(value) && value > 0 && value <= 1;
  });
}

function sitemapXml(): string {
  const entries = PUBLIC_PAGES
    .map((path) => `  <url><loc>${new URL(path, SITE_ORIGIN).href}</loc></url>`)
    .join("\n");

  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${entries}\n</urlset>\n`;
}

function withSecurityHeaders(response: Response, request: Request): Response {
  const headers = new Headers(response.headers);

  for (const [name, value] of Object.entries(securityHeaders)) {
    headers.set(name, value);
  }

  const pathname = new URL(request.url).pathname;
  const isDocument = pathname === "/" || pathname === "/privacy" || pathname.endsWith(".html");
  const isMutableAsset = pathname === "/styles.css" || pathname === "/script.js";
  const isDiscoveryResource = pathname === "/robots.txt" || pathname === "/sitemap.xml" || pathname.startsWith("/.well-known/");

  if (response.status >= 400) {
    headers.set("Cache-Control", "no-store");
  } else if (isDocument || isMutableAsset) {
    headers.set("Cache-Control", "public, max-age=0, must-revalidate");
  } else if (isDiscoveryResource) {
    headers.set("Cache-Control", "public, max-age=3600");
  } else {
    headers.set("Cache-Control", "public, max-age=31536000, immutable");
  }

  if (pathname === "/robots.txt") {
    headers.set("Content-Type", "text/plain; charset=utf-8");
  } else if (pathname === "/sitemap.xml") {
    headers.set("Content-Type", "application/xml; charset=utf-8");
  } else if (pathname === "/.well-known/ai-catalog.json" || pathname === "/.well-known/agent-skills/index.json") {
    headers.set("Content-Type", "application/json; charset=utf-8");
  }

  if (pathname === "/" || pathname === "/privacy") {
    headers.set(
      "Link",
      "</.well-known/ai-catalog.json>; rel=\"describedby\"; type=\"application/json\""
    );
    const vary = headers.get("Vary");
    if (!vary?.split(",").some((value) => value.trim().toLowerCase() === "accept")) {
      headers.set("Vary", vary ? `${vary}, Accept` : "Accept");
    }
  }

  if (pathname === "/.well-known/ai-catalog.json") {
    headers.set("Access-Control-Allow-Origin", "*");
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const headRequest = request.method === "HEAD";

    if ((request.method === "GET" || headRequest) && pathname === "/sitemap.xml") {
      return withSecurityHeaders(
        new Response(headRequest ? null : sitemapXml(), {
          headers: { "Content-Type": "application/xml; charset=utf-8" }
        }),
        request
      );
    }

    if (unsupportedDiscoveryPaths.has(pathname)) {
      return withSecurityHeaders(
        new Response("This origin does not publish this API or agent service.\n", {
          status: 404,
          headers: { "Content-Type": "text/plain; charset=utf-8" }
        }),
        request
      );
    }

    const markdown = markdownPages[pathname as keyof typeof markdownPages];
    if ((request.method === "GET" || headRequest) && markdown && acceptsMarkdown(request)) {
      return withSecurityHeaders(
        new Response(headRequest ? null : markdown, {
          headers: {
            "Content-Type": "text/markdown; charset=utf-8",
            "Content-Signal": "search=yes,ai-train=no,use=reference"
          }
        }),
        request
      );
    }

    const response = await env.ASSETS.fetch(request);
    return withSecurityHeaders(response, request);
  }
} satisfies ExportedHandler<Env>;
