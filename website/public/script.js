const translations = {
  zh: {
    skip_link: "跳到主要内容",
    brand_aria: "KeyAuth 首页",
    footer_brand_aria: "返回 KeyAuth 首页",
    nav_aria: "主导航",
    mobile_nav_aria: "移动端主导航",
    language_toggle: "切换到 English",
    nav_security: "安全架构",
    nav_flow: "工作方式",
    nav_recovery: "iPhone 间恢复",
    nav_faq: "常见问题",
    nav_privacy: "隐私",
    header_cta: "开始使用",
    menu_open: "打开菜单",
    hero_eyebrow: "本地优先验证器",
    hero_title: "验证码，<br /><em>回到</em>你自己的掌控中。",
    hero_lede: "KeyAuth 是一款面向 iOS 26+ iPhone 的 TOTP 验证器。你的密钥在本地生成、加密和使用；云端只负责同步密文。",
    hero_security_cta: "了解安全架构",
    hero_flow_cta: "看它如何工作",
    hero_facts_aria: "KeyAuth 特点",
    fact_ios: "iOS 26+",
    fact_offline: "离线生成",
    fact_serverless: "无应用服务器",
    hero_visual_aria: "KeyAuth 加密保险库示意图",
    encrypted_locally: "本地加密",
    private_vault: "本地保险库",
    local_vault: "本地保险库",
    refreshing: "18 秒后刷新",
    user_presence: "用户验证",
    visual_caption: "你的数据。你的设备。",
    signal_aria: "KeyAuth 设计原则",
    signal_local: "本地优先",
    signal_ciphertext: "密文同步",
    signal_key: "密钥隔离",
    signal_note: "为更安静的安全体验而生。",
    security_eyebrow: "安全设计",
    security_title: "云端可以帮忙，<br /><em>但不应该拥有你的秘密。</em>",
    security_text: "KeyAuth 把“谁能看见什么”设计在系统底层。验证码账户在设备上加密，Face ID 或设备密码保护主密钥；iCloud 只拿到无法直接阅读的密文。",
    node_device_title: "你的设备",
    node_device_text: "密钥和验证码在本地生成、读取与更新。",
    node_key_title: "设备密钥",
    node_key_text: "主密钥绑定当前设备，并由用户存在验证守护。",
    node_cloud_text: "只保存加密 blob 和必要的同步元数据。",
    architecture_footer: "应用服务器不存在于这条链路中",
    manifesto_quote: "安全感不应该来自<br /><span>“相信我们”。</span>",
    manifesto_sub: "它应该来自一个足够清晰的系统：<br />敏感数据在哪里，密钥由谁控制，答案都能被看见。",
    flow_eyebrow: "安静的工作流",
    flow_title: "从扫码开始，<br /><em>每一步都在本地。</em>",
    flow_text: "没有复杂的账户体系，也不需要把日常验证交给一台远方的服务器。KeyAuth 让常用操作保持熟悉，让安全边界保持清晰。",
    step_scan_title: "扫描二维码",
    step_scan_text: "从你正在保护的服务导入 TOTP 配置，快速、直接。",
    step_encrypt_title: "在设备上加密",
    step_encrypt_text: "整个账户 payload 使用 AES-256-GCM 加密后才会离开本地存储。",
    locked: "已锁定",
    step_generate_title: "离线生成验证码",
    step_generate_text: "网络不可用时，已配置的账户仍然可以继续生成当前验证码。",
    step_sync_title: "后台同步密文",
    step_sync_text: "换到另一部 iPhone 时，iCloud 会同步加密数据；本地使用不依赖网络。",
    recovery_eyebrow: "自主选择的恢复",
    recovery_title: "换一部 iPhone，<br /><em>不必交出控制权。</em>",
    recovery_text: "启用恢复后，可在另一部 iPhone 上用独立 Recovery Key 恢复主密钥环。iCloud 保存的仍然只是加密恢复包，真正的恢复密钥只在你手里。",
    recovery_cta: "了解恢复边界",
    recovery_visual_aria: "恢复密钥示意图",
    store_offline: "离线保存",
    one_time_setup: "一次性设置",
    new_device: "新 iPhone",
    local_keychain: "本地钥匙串",
    feature_eyebrow: "更好的默认设置",
    feature_title: "把重要的事情，<br /><em>留在重要的位置。</em>",
    feature_local_title: "本地保险库",
    feature_local_text: "验证码在你的设备上优先存在、优先工作。",
    feature_unlock_title: "系统级解锁",
    feature_unlock_text: "Face ID 或设备密码验证成功，才会拿到主密钥。",
    feature_sync_title: "密文同步",
    feature_sync_text: "云端参与同步，但不拥有读取验证码所需的明文。",
    feature_recovery_title: "清晰的恢复边界",
    feature_recovery_text: "恢复能力是可选的，恢复密钥由你单独保管。",
    faq_eyebrow: "不隐藏重要条款",
    faq_title: "几个直接的<br /><em>答案。</em>",
    faq_intro: "我们相信安全产品应该把边界说清楚。这里是开始使用前最值得知道的几件事。",
    faq_offline_question: "没有网络还能生成验证码吗？",
    faq_offline_answer: "可以。已完成配置的账户保存在本地加密保险库中，TOTP 生成不依赖网络。iCloud 只影响同步和恢复，不影响已经完成配置的本机使用。",
    faq_cloud_question: "iCloud 能看到我的验证码吗？",
    faq_cloud_answer: "不能直接看到。上传的是加密后的 blob 和必要的同步元数据，issuer、账户名、TOTP secret 等明文不会作为 CloudKit 字段保存。",
    faq_device_question: "换 iPhone 需要什么？",
    faq_device_answer: "在旧 iPhone 上启用恢复并妥善保存独立 Recovery Key，然后在新 iPhone 上完成恢复。无论是否恢复，打开保险库仍需要 Face ID 或设备密码。",
    faq_supported_question: "KeyAuth 支持哪些设备？",
    faq_supported_answer: "目前仅支持运行 iOS 26 或更高版本的 iPhone；不支持 iPad 或其他平台。首次使用需要完成系统设备认证。",
    download_title: "把验证码，<br /><em>放回你手里。</em>",
    download_text: "一个更安静、更透明的验证器。专为运行 iOS 26+ 的 iPhone 打造。",
    download_cta: "查看开源项目",
    download_footer: "© 2026 KeyAuth<br />为安静的时刻而做。",
    footer_tagline: "你的验证码，你的掌控。",
    footer_security: "安全",
    footer_source: "源码",
    footer_privacy: "隐私",
    privacy_back: "返回 KeyAuth",
    privacy_eyebrow: "隐私 / 透明",
    privacy_title: "隐私，<br /><em>不藏在脚注里。</em>",
    privacy_intro: "这页用简单的话说明 KeyAuth 当前如何处理你的数据：什么留在设备上，什么会以密文同步，以及官网请求会经过哪里。",
    privacy_updated: "最后更新：2026 年 9 月 22 日",
    privacy_summary_title: "一眼看懂",
    privacy_summary: "KeyAuth 是本地优先的 TOTP 验证器。验证码账户在设备上加密，iCloud 只用于可选的同步和恢复；KeyAuth 没有自己的应用服务器来接收你的明文验证码。",
    privacy_app_title: "App 中的数据",
    privacy_app_text: "你导入的 issuer、账户名、TOTP secret、算法、位数、周期和自定义名称会作为一个账户 payload 在设备上加密保存。TOTP 生成在本地完成，已配置的账户不依赖网络。",
    privacy_cloud_title: "iCloud 只同步密文",
    privacy_cloud_text: "启用同步后，CloudKit 接收记录 UUID、加密 blob、版本和同步时间等必要信息，不接收可直接阅读的账户明文。iCloud 是同步和备份层，不是 KeyAuth 运行验证码的依赖。",
    privacy_key_title: "密钥与设备认证",
    privacy_key_text: "主密钥保存在受 Face ID、Touch ID 或设备密码保护的设备钥匙串中，并绑定当前设备。打开保险库前，系统认证必须成功。",
    privacy_recovery_title: "iPhone 间恢复",
    privacy_recovery_text: "如果你主动启用恢复，KeyAuth 会用独立 Recovery Key 包装主密钥环，并把加密恢复包放入 CloudKit。你可以用它在另一部 iPhone 上恢复。Recovery Key 不会上传，必须由你自行保存。",
    privacy_site_title: "官网请求",
    privacy_site_text: "本官网是由 Cloudflare Workers Static Assets 提供的静态页面，不提供账号、表单或应用接口，也不主动加入第三方广告和分析脚本。Cloudflare 仍可能按其服务政策处理标准网络请求元数据。",
    privacy_choices_title: "你的选择",
    privacy_choices_text: "你可以不启用 iCloud 同步或 iPhone 间恢复，继续把 KeyAuth 当作本地验证器使用。删除账户会先从本地移除并排队同步删除；卸载 App 不会自动删除 CloudKit 中已有记录。",
    privacy_source_title: "可验证的实现",
    privacy_source_text: "KeyAuth 的客户端实现和这份官网内容都公开在 GitHub。你可以查看加密、Keychain、CloudKit 和恢复流程的实际代码。",
    privacy_source_cta: "查看 GitHub 源码",
    privacy_disclaimer: "这是一份产品行为说明。正式发布前，仍应结合 Apple、Cloudflare 和 App Store 的最新条款完成法律审阅。",
    privacy_contact: "返回产品页"
  },
  en: {
    skip_link: "Skip to main content",
    brand_aria: "KeyAuth home",
    footer_brand_aria: "Back to the KeyAuth home page",
    nav_aria: "Primary navigation",
    mobile_nav_aria: "Mobile navigation",
    language_toggle: "切换到中文",
    nav_security: "Security model",
    nav_flow: "How it works",
    nav_recovery: "iPhone recovery",
    nav_faq: "FAQ",
    nav_privacy: "Privacy",
    header_cta: "Get started",
    menu_open: "Open menu",
    hero_eyebrow: "LOCAL-FIRST AUTHENTICATOR",
    hero_title: "Your codes,<br /><em>back</em> in your hands.",
    hero_lede: "KeyAuth is a TOTP authenticator for iPhone running iOS 26 or later. Your secrets are generated, encrypted, and used on-device; the cloud only syncs ciphertext.",
    hero_security_cta: "Explore the security model",
    hero_flow_cta: "See how it works",
    hero_facts_aria: "KeyAuth features",
    fact_ios: "iOS 26+",
    fact_offline: "Works offline",
    fact_serverless: "No app server",
    hero_visual_aria: "KeyAuth encrypted vault illustration",
    encrypted_locally: "ENCRYPTED LOCALLY",
    private_vault: "PRIVATE VAULT",
    local_vault: "LOCAL VAULT",
    refreshing: "refreshing in 18s",
    user_presence: "USER PRESENCE",
    visual_caption: "YOUR DATA. YOUR DEVICE.",
    signal_aria: "KeyAuth principles",
    signal_local: "Local-first",
    signal_ciphertext: "Ciphertext sync",
    signal_key: "Key isolation",
    signal_note: "Built for a quieter kind of security.",
    security_eyebrow: "SECURITY BY DESIGN",
    security_title: "The cloud can help,<br /><em>but it should not own your secrets.</em>",
    security_text: "KeyAuth designs visibility into the system itself. Accounts are encrypted on your device, while Face ID or your passcode protects the master key; iCloud only receives ciphertext it cannot directly read.",
    node_device_title: "Your device",
    node_device_text: "Secrets and codes are generated, read, and updated locally.",
    node_key_title: "Device key",
    node_key_text: "The master key is bound to this device and guarded by user presence.",
    node_cloud_text: "Only encrypted blobs and essential sync metadata are stored.",
    architecture_footer: "No application server sits on this path",
    manifesto_quote: "Security should not come from<br /><span>“Trust us.”</span>",
    manifesto_sub: "It should come from a system clear enough to show where sensitive data lives, who controls the keys, and what happens next.",
    flow_eyebrow: "THE QUIET FLOW",
    flow_title: "Start with a scan,<br /><em>keep every step local.</em>",
    flow_text: "No complex account system, and no distant server handling your daily authentication. KeyAuth keeps the familiar parts simple and the security boundary clear.",
    step_scan_title: "Scan a QR code",
    step_scan_text: "Import a TOTP configuration from the service you are protecting—fast and direct.",
    step_encrypt_title: "Encrypt on-device",
    step_encrypt_text: "The complete account payload is encrypted with AES-256-GCM before it leaves local storage.",
    locked: "LOCKED",
    step_generate_title: "Generate codes offline",
    step_generate_text: "Configured accounts keep generating current codes even when the network is unavailable.",
    step_sync_title: "Sync ciphertext in the background",
    step_sync_text: "When you move to another iPhone, iCloud syncs encrypted data; local use never depends on the network.",
    recovery_eyebrow: "RECOVERY, BY CHOICE",
    recovery_title: "Move to another iPhone,<br /><em>without giving up control.</em>",
    recovery_text: "With recovery enabled, you can restore the master-key ring on another iPhone using an independent Recovery Key. iCloud still stores only an encrypted envelope; the recovery key stays with you.",
    recovery_cta: "Understand the recovery boundary",
    recovery_visual_aria: "Recovery key illustration",
    store_offline: "STORE OFFLINE",
    one_time_setup: "ONE-TIME SETUP",
    new_device: "NEW IPHONE",
    local_keychain: "LOCAL KEYCHAIN",
    feature_eyebrow: "A BETTER DEFAULT",
    feature_title: "Keep important things,<br /><em>in the right place.</em>",
    feature_local_title: "Local vault",
    feature_local_text: "Your codes live and work on your device first.",
    feature_unlock_title: "System-level unlock",
    feature_unlock_text: "The master key is released only after Face ID or passcode verification.",
    feature_sync_title: "Ciphertext sync",
    feature_sync_text: "The cloud helps with sync without holding the plaintext needed to read your codes.",
    feature_recovery_title: "A clear recovery boundary",
    feature_recovery_text: "Recovery is optional, and the recovery key is yours to keep safe.",
    faq_eyebrow: "NO FINE PRINT",
    faq_title: "A few direct<br /><em>answers.</em>",
    faq_intro: "Security products should make their boundaries clear. Here are the things worth knowing before you start.",
    faq_offline_question: "Can I generate codes without a network?",
    faq_offline_answer: "Yes. Configured accounts live in the encrypted local vault, so TOTP generation does not require a network. iCloud affects sync and recovery, not use on an already provisioned device.",
    faq_cloud_question: "Can iCloud see my codes?",
    faq_cloud_answer: "Not directly. KeyAuth uploads encrypted blobs and essential sync metadata; plaintext issuer, account name, TOTP secret, and related settings are not stored as CloudKit fields.",
    faq_device_question: "What do I need to move to another iPhone?",
    faq_device_answer: "Enable recovery on the old iPhone and keep the independent Recovery Key safe, then restore on the new iPhone. Opening the vault still requires Face ID or your passcode.",
    faq_supported_question: "Which devices does KeyAuth support?",
    faq_supported_answer: "KeyAuth currently supports iPhone running iOS 26 or later only. iPad and other platforms are not supported. The first launch requires system device authentication.",
    download_title: "Put your codes,<br /><em>back in your hands.</em>",
    download_text: "A quieter, more transparent authenticator. Made for iPhone running iOS 26 or later.",
    download_cta: "View the open-source project",
    download_footer: "© 2026 KeyAuth<br />Made for the quiet moments.",
    footer_tagline: "Your codes. Your control.",
    footer_security: "Security",
    footer_source: "Source",
    footer_privacy: "Privacy",
    privacy_back: "Back to KeyAuth",
    privacy_eyebrow: "PRIVACY / TRANSPARENCY",
    privacy_title: "Privacy,<br /><em>without the footnotes.</em>",
    privacy_intro: "This page explains, in plain language, how KeyAuth handles your data: what stays on your device, what syncs as ciphertext, and where website requests go.",
    privacy_updated: "Last updated: September 22, 2026",
    privacy_summary_title: "At a glance",
    privacy_summary: "KeyAuth is a local-first TOTP authenticator. Account data is encrypted on your device, while iCloud is used only for optional sync and recovery; KeyAuth has no application server receiving your plaintext codes.",
    privacy_app_title: "Data inside the app",
    privacy_app_text: "The issuer, account name, TOTP secret, algorithm, digits, period, and custom name you import are encrypted together as an account payload on-device. TOTP generation happens locally, so configured accounts do not require a network.",
    privacy_cloud_title: "iCloud syncs ciphertext only",
    privacy_cloud_text: "When sync is enabled, CloudKit receives necessary metadata such as record UUIDs, encrypted blobs, versions, and timestamps—not directly readable account plaintext. iCloud is a sync and backup layer, not a runtime dependency for generating codes.",
    privacy_key_title: "Keys and device authentication",
    privacy_key_text: "The master key is held in a device Keychain item protected by Face ID, Touch ID, or your passcode and bound to the current device. System authentication must succeed before the vault opens.",
    privacy_recovery_title: "iPhone recovery",
    privacy_recovery_text: "If you choose to enable recovery, KeyAuth wraps the master-key ring with an independent Recovery Key and stores only the encrypted envelope in CloudKit. You can use it to restore on another iPhone. The Recovery Key is never uploaded and must be kept by you.",
    privacy_site_title: "Website requests",
    privacy_site_text: "This website is served as Cloudflare Workers Static Assets. It provides no account, form, or app API and does not add third-party advertising or analytics scripts. Cloudflare may still process standard request metadata under its service policies.",
    privacy_choices_title: "Your choices",
    privacy_choices_text: "You can leave iCloud sync and iPhone recovery disabled and use KeyAuth as a local authenticator. Deleting an account removes it locally first and queues the cloud deletion; uninstalling the app does not automatically delete existing CloudKit records.",
    privacy_source_title: "An implementation you can inspect",
    privacy_source_text: "The KeyAuth client implementation and this website are public on GitHub. You can inspect the actual encryption, Keychain, CloudKit, and recovery flows.",
    privacy_source_cta: "View the GitHub source",
    privacy_disclaimer: "This is a product behavior statement. Before release, the latest Apple, Cloudflare, and App Store terms should still be reviewed by counsel.",
    privacy_contact: "Back to the product"
  }
};

const pageMetadata = {
  home: {
    zh: {
      title: "KeyAuth — 你的验证码，你的掌控",
      description: "KeyAuth 是专为运行 iOS 26+ 的 iPhone 打造的本地优先、端到端加密 TOTP 验证器。",
      ogTitle: "KeyAuth — 验证码，回到你自己的掌控中",
      ogDescription: "专为运行 iOS 26+ 的 iPhone 打造。AES-256-GCM 加密、Face ID 保护，iCloud 只同步密文。"
    },
    en: {
      title: "KeyAuth — Your codes, your control",
      description: "KeyAuth is a local-first, end-to-end encrypted TOTP authenticator for iPhone running iOS 26 or later.",
      ogTitle: "KeyAuth — Your codes, back in your hands",
      ogDescription: "Made for iPhone running iOS 26 or later, with AES-256-GCM encryption, Face ID protection, and ciphertext-only iCloud sync."
    }
  },
  privacy: {
    zh: {
      title: "KeyAuth — 隐私说明",
      description: "KeyAuth 隐私说明：了解本地加密、iCloud 密文同步、设备密钥和官网请求如何工作。",
      ogTitle: "KeyAuth — 隐私说明",
      ogDescription: "了解 KeyAuth 如何处理本地数据、iCloud 密文同步、恢复密钥和官网请求。"
    },
    en: {
      title: "KeyAuth — Privacy",
      description: "KeyAuth privacy: learn how local encryption, ciphertext-only iCloud sync, device keys, and website requests work.",
      ogTitle: "KeyAuth — Privacy",
      ogDescription: "How KeyAuth handles local data, ciphertext-only iCloud sync, recovery keys, and website requests."
    }
  }
};

const languageToggle = document.querySelector("[data-language-toggle]");
let currentLanguage = "en";
const pageKey = document.body.dataset.page === "privacy" ? "privacy" : "home";

function applyLanguage(language) {
  currentLanguage = language === "en" ? "en" : "zh";
  const dictionary = translations[currentLanguage];
  const metadata = pageMetadata[pageKey][currentLanguage];

  document.documentElement.lang = currentLanguage === "en" ? "en" : "zh-CN";
  document.title = metadata.title;
  document.querySelector("#meta-description")?.setAttribute("content", metadata.description);
  document.querySelector("#og-title")?.setAttribute("content", metadata.ogTitle);
  document.querySelector("#og-description")?.setAttribute("content", metadata.ogDescription);

  document.querySelectorAll("[data-i18n]").forEach((element) => {
    const value = dictionary[element.dataset.i18n];
    if (value !== undefined) element.textContent = value;
  });

  document.querySelectorAll("[data-i18n-html]").forEach((element) => {
    const value = dictionary[element.dataset.i18nHtml];
    if (value !== undefined) element.innerHTML = value;
  });

  document.querySelectorAll("[data-i18n-attr]").forEach((element) => {
    element.dataset.i18nAttr.split(",").forEach((entry) => {
      const [attribute, key] = entry.split(":");
      const value = dictionary[key];
      if (attribute && value !== undefined) element.setAttribute(attribute.trim(), value);
    });
  });

  if (languageToggle) {
    languageToggle.setAttribute("aria-pressed", String(currentLanguage === "en"));
    languageToggle.querySelector(".language-current").textContent = currentLanguage === "en" ? "EN" : "中";
    languageToggle.querySelector("[data-language-other]").textContent = currentLanguage === "en" ? "中" : "EN";
  }

  try {
    localStorage.setItem("keyauth-language", currentLanguage);
  } catch {
    // Private browsing or blocked storage should not disable language switching.
  }
}

languageToggle?.addEventListener("click", () => {
  applyLanguage(currentLanguage === "zh" ? "en" : "zh");
});

try {
  const storedLanguage = localStorage.getItem("keyauth-language");
  if (storedLanguage === "en" || storedLanguage === "zh") currentLanguage = storedLanguage;
} catch {
  // Use the Chinese default when local storage is unavailable.
}

applyLanguage(currentLanguage);

const menuToggle = document.querySelector(".menu-toggle");
const mobileMenu = document.querySelector(".mobile-menu");

function closeMenu() {
  if (!menuToggle || !mobileMenu) return;
  menuToggle.setAttribute("aria-expanded", "false");
  mobileMenu.hidden = true;
}

menuToggle?.addEventListener("click", () => {
  const isOpen = menuToggle.getAttribute("aria-expanded") === "true";
  menuToggle.setAttribute("aria-expanded", String(!isOpen));
  if (mobileMenu) mobileMenu.hidden = isOpen;
});

mobileMenu?.querySelectorAll("a").forEach((link) => link.addEventListener("click", closeMenu));
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeMenu();
});

const revealItems = document.querySelectorAll(".reveal");
const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

if (prefersReducedMotion || !("IntersectionObserver" in window)) {
  revealItems.forEach((item) => item.classList.add("is-visible"));
} else {
  const observer = new IntersectionObserver(
    (entries, currentObserver) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("is-visible");
        currentObserver.unobserve(entry.target);
      });
    },
    { rootMargin: "0px 0px -9% 0px", threshold: 0.08 }
  );

  revealItems.forEach((item) => observer.observe(item));
}

const sectionLinks = [...document.querySelectorAll('.desktop-nav a, .mobile-menu a')].filter((link) => link.hash);
const trackedSections = [...new Set(sectionLinks.map((link) => document.querySelector(link.hash)).filter(Boolean))];

if ("IntersectionObserver" in window && trackedSections.length > 0) {
  const activeObserver = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        sectionLinks.forEach((link) => {
          link.classList.toggle("is-active", link.hash === `#${entry.target.id}`);
        });
      });
    },
    { rootMargin: "-35% 0px -55% 0px", threshold: 0 }
  );

  trackedSections.forEach((section) => activeObserver.observe(section));
}
