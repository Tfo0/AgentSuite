## 一、确认鉴权字段 | 删后重放看是否依然响应

1. **定位鉴权字段(哪个是真正影响后端的字段)**:Cookie / `Authorization` / 自定义身份头(`User-Id`/`X-Auth-Token`/`employeeId`)/ 签名 query 参(`sign`/`access_token`)。多个头时二分删定位——只一个是真闸,其余装饰。
2. **删后重放看响应**:200 + 同样数据 = 未授权;302 跳登录 / 401 / 403 = 有校验,走二段;200 但空 / 只回自己 = 部分校验。
3. **探增头轴可用性**(先探后打):增头前先单发探针确认服务端吃这头——URL 覆盖头发 `X-Original-URL: /不存在` 回 404 = 认这头(回原路径响应 = 不认);IP/Host 覆盖头发后看响应/路由是否变。吃哪个打哪个。

## 二、绕过思路 | 删被拒时按轴找不鉴权访问路径 只给思路自由发挥

- **改鉴权字段值**:置空(`Cookie:`/`Authorization:`)、改匿名值、只删 session 不删 csrf token(二分定位真闸)。
- **改 path**:前缀绕闸(登录前缀换 unlogin/guest 前缀,如 `d→n`/`/api→/fapi/n`)、受控口规范化绕 403(网关与后端 normalize 不一致时改写成"后端等价但网关认不出":点号 `./`/`/.`、双斜杠 `//`/`///`、URL 编码 `%2e`/`%2f`、分号 `;/`(Spring strip 分号后段)、反斜杠 `\`(Windows 后端)、混合 `.;`;Kong 特有 `%61dmin` 解码/尾部 `%2f`、Nginx `merge_slashes off` 时 `//` 不合并可绕规则、`proxy_pass http://backend/;` 配错时 `/api/../admin` 转发成 `/admin`)、版本回退(`v2→v1`/去版本,旧版常无鉴权)、删/加段 fallthrough 到更宽口、后缀变体(`.json`/`.xml`)、大小写/尾斜杠。
- **增**:
  - 增 URL 覆盖头(`X-Original-URL`/`X-Rewrite-URL` 覆盖目标 path,如 `GET /` + `X-Original-URL: /admin`;IIS/ASP.NET + 反代后端常见,前端拦 path 但后端认覆盖头)。
  - 增 IP 授权头(`X-Custom-IP-Authorization`/`X-Real-IP`/`X-Originating-IP`/`True-Client-IP`/`X-Remote-IP`/`Forwarded`/`X-Forwarded-For` 填 `127.0.0.1`/内网段,后端信这头做 IP 白名单/内网判定时跳鉴权;同头轮换随机 IP 也破 429 限流/借 XFF 冒充白名单段——注:限流轮换偏滥用非越权)。
  - 增 Host 覆盖头(`X-Forwarded-Host`/`X-Host`/`X-HTTP-Host-Override`/`X-Forwarded-Server`/改 `Host` 本身,后端按覆盖 Host 做鉴权/路由/白名单域放行)。
  - 增免鉴权头(`Auth-Control: no-auth`/`X-Internal: true`,后端信这个头跳鉴权)。
  - 增调试/内部 query 参(`debug=1`/`internal=1`/`admin=true`)。
  - 增匿名会话(先 `anonymous` 签发口拿 session cookie/JWT,再带打本该登录的业务表——BaaS/云开发常见)。
  - 增缺参改头换票:未登录业务口报"缺少 xxx"(Spring 400 点名 `Required String parameter`,缺的其实是 Cookie/头名)→把字段放 HTTP 头/Cookie 再打换票,出别人登录票/姓名。
- **换 method**:POST→GET(GET 不鉴权 POST 鉴权)、verb tampering(GET→`OPTIONS`/`HEAD`/`TRACE`,auth 只校 GET/POST 时换方法绕读)、方法覆盖头(`X-HTTP-Method-Override`/`X-Method-Override`/`X-HTTP-Method`/`X-Method`/`_method`,网关看到 GET 放行、后端按覆盖头执行 DELETE/PUT)、换 content-type(`application/json`→`text/plain` 绕预检)。**GET→`DELETE`/`PUT` 调高权功能 = BFLA(功能级越权)**:方法覆盖头让网关放行 GET、后端按覆盖头执行 DELETE/PUT 打管理员写口(删号/改配置/批量操作),即功能级越权——本轴覆盖。
- **换 host**:同名接口换不鉴权子域(业务前端回登录闸 → 独立身份子域同套接口不要 Cookie;GET 可能 404、POST 才出数)。
- **HPP(参数污染)**:同参重复 `?id=自己&id=他人`、数组 `id[]`、JSON 重复键 `{"id":"自己","id":"他人"}`——网关取首参做鉴权、后端取末参做查询时,网关按首参(自己)放行、后端按末参(他人)返回他人数据。

## 三、漏洞证明 | 不破坏不改删 只证读到

- 任一轴使本该 401 的口返回 200 + 他人 PII / 内部资源 / `total` 暴涨 = 未授权成立。看文件头/体积证真媒体、`role=editor`/超管标记证权限位。
- 过完整链(读到 → 建号 → 改密 → 删探测号)才算 account takeover 级,只读到算未授权读。能撤销的立刻撤,不真删他人号、不真改他人密。

## 四、误报场景

- 删鉴权字段后 302 跳登录 / 401 / 403 = 有校验,不是未授权。
- 200 但空 / 只回自己 = 部分校验,非未授权访问。
- 返回非 401 但删头后仍拒 = 那字段只是展示用,后端有独立鉴权。
- 改 path 规范化后 200 但回公开静态页 / 默认页 = 本就该公开。
- 增头/参后 200 但回公开配置 / 错误码 / 对外协议 = 本就该公开。
- 增覆盖头发 `X-Original-URL: /不存在` 不回 404 / IP·Host 头发后响应没变 = 服务端不认这头,轴未命中。
- 匿名会话签发口本身要登录 / 签发后行权限拒且集合空 = 这路未命中。
- 列表删 Cookie 后 `total` 没暴涨、只出自己刚交的补件 = 部分校验。
