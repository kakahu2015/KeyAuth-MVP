# KeyAuth Official Website

Cloudflare Workers Static Assets 官网，Worker 入口统一补充安全响应头，页面本身保持无第三方追踪依赖。

官网默认显示中文，右上角可切换 English；选择会保存在浏览器本地，下次访问继续使用。
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
