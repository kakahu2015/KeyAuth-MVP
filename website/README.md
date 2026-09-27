# KeyAuth Official Website

Cloudflare Workers Static Assets 官网，Worker 入口统一补充安全响应头，页面本身保持无第三方追踪依赖。

首次访问时，官网根据浏览器首选语言在中文和 English 之间选择；其他语言默认 English。手动切换后的选择会保存在浏览器本地，并优先于浏览器语言。
隐私说明页位于 `/privacy`，同样支持中英文切换。

## Local development

```sh
npm install
npm run dev
```

## Validate and deploy

```sh
npm run types
npm run check
npm run deploy
```

`wrangler.jsonc` 使用 `public/` 作为静态资源目录，`src/index.ts` 通过 `ASSETS` 绑定返回页面资源。

## Public discovery

- `/sitemap.xml` is generated from the canonical page list in `src/index.ts`.
- `/robots.txt` points to that sitemap. Cloudflare continues to supply its managed crawler policy around this origin directive.
- `/` and `/privacy` return Markdown when the request accepts `text/markdown`; HTML remains the default.
- `/.well-known/ai-catalog.json` lists the public site, privacy page, source repository, and App Store listing. `/.well-known/agent-skills/index.json` currently reports no published skills.
- This site has no public API, OAuth authorization server, protected API, agent-registration endpoint, or MCP server. Their corresponding discovery URLs return 404 rather than the SPA fallback page.
