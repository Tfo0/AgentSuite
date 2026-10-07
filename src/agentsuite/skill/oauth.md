## 一、确认 | 认流程阶段与可信面、哪段后端校验

1. **阶段**:authorize(授权)/callback(回调)/token(换发);看 `redirect_uri`/`code`/`state`/`grant_type`/`scope` 哪段进后端(前端回调页取 code 不算)。
2. **可信面**:`redirect_uri` 校验严否(白名单/前缀/精确)、`state` 绑会话否、`code` 一次性否、`scope` 取授权值还是请求值、PKCE 强制否。

## 二、绕过 | 校验不严或凭证泄露才有攻击面 只给思路自由发挥

- **redirect_uri 绕过**:校验严否决定绕过轴——子目录穿越(`callback/../../attacker`)、子域(`attacker.target.com`)、参数污染(`callback?next=attacker`)、开放重定向链(白名单域上的开放重定向)、域名混淆(`target.com@attacker`/`target.com.attacker`/`%2e`)、协议混淆(`javascript:`/`data:`)、前缀匹配(`callbackXSS`)、localhost/`urn:ietf:wg:oauth:2.0:oob`。
- **state 缺失/重放**:`state` 缺失/静态/可预测/可重放 → OAuth CSRF,callback 绑攻击者身份至受害者会话(账号接管)。
- **授权码重放**:code 一次性,换 token 后再用同一 code 换。
- **scope 提升**:换 token 时 `scope=read` 改 `read write admin`。
- **隐式流泄露**:`#access_token=` fragment 经 Referer/浏览器历史/服务端日志泄露;回调页插外站资源看 Referer 是否带 token。
- **PKCE 缺失**:不发 `code_challenge`,换 token 不带 `code_verifier` 仍成功。
- **client_secret 泄露**:前端 JS/APK/git 历史里取出 `client_secret`,自发起授权流程换 token。泄露字段(`nonce`/`secret`/`appKey`)以 `MIIE`/`-----BEGIN` 开头 = PKCS8 私钥(RSA),别当短随机串丢——load 当私钥现签。
- **account linking 滥用**:绑攻击者 OAuth 至受害者同邮箱账号;provider 混乱(Apple ID 绑 Google 位)。
- **代调身份供应商报错截取凭证**:应用代调身份供应商,非法 `pagepath`/`redirect_uri` 外域 → message/报错 URL 拼 `access_token=`/`client_secret=` → 截取(区别于"JS/APK/git 取钥",这条是报错回显)。
- **运营配置跳转 URL 带会话 token**:运营配置跳转 URL(`skipPath`/`jumpUrl`)query 带会话 token → 截取作 `Authorization` 打 `me`/`info`(区别于"隐式流 `#access_token=` fragment",这条是 server-side 跳转 URL query 明文带)。

## 三、证明 | code/token 带到攻击者域或身份写入受害者会话

- redirect_uri 绕过:code/token 跟回调带到攻击者域 = 成立。用 token 打资源 API 证能用。
- state CSRF:受害者授权后攻击者身份写入会话(账号接管)= 成立。
- scope 提升:换出的 token 权限放大(打原本无权资源成功)= 成立。
- 代调报错截取到 access_token/client_secret 打资源口成功 / 跳转 URL 的 token 打 me/info 出他人数据 = 成立。

## 四、误报

- `redirect_uri` 白名单严(精确匹配/不许穿越);`state` 绑会话不可重放;code 真一次性;scope 取授权值非请求值;PKCE 强制缺 verifier 即拒。
- client_secret 服务端持有未泄露;linking 需受害者侧确认、provider 不混。
- 代调报错不回显 token(只回错误码);跳转 URL 不带 token 或 token 一次性已失效;`pagepath`/`redirect_uri` 校验严不回显。
