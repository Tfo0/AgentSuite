## 一、确认 | 删除全部鉴权字段二分定位闸为 cookie 还是请求头 + POST→GET 是否受理

1. **删除全部鉴权字段重放**(Cookie+Authorization+自定义身份头+token 参):200=无闸,CSRF 不成立;有闸则二分回填——回填 Cookie 通过=闸为 cookie(浏览器跨站自动携带)= CSRF 成立;回填请求头才通过=跨站不可设置自定义头(CORS 预检拦截)=无利用面,除非 token 可绕或 CORS 反射 Origin+credentials 桥接
2. **POST→GET 覆写重放**(body 参迁移至 query string):后端受理并改状态=GET CSRF 可行(img/Lax);拒绝=仅 form POST 可行

## 二、绕过 | 闸为 cookie 后绕过 SameSite + token

- **无 token**:cookie 唯一闸,直接构造跨站请求
- **token 校验不严**:删除/替换随机值请求仍成立;绑会话不绑用户;double-submit(cookie+header 同值,子域 XSS/cookie tossing 注入);静态/可预测(base64(username)/md5(session_id));token fixation(登录前签发,预置受害者)
- **SameSite=Lax 绕过**(顶栏 GET 携带,POST 不携带):GET 方法(`<img src="delete?confirm=yes">`);method override(`_method`/`X-HTTP-Method-Override`,Lax 放行 GET,框架按覆写执行 POST);2 分钟 Lax+POST 窗口(Chrome cookie 初设);302 链顶栏导航;子域 XSS
- **SameSite=Strict**:子域 XSS;无其他
- **JSON content-type 绕过**:`text/plain` 伪装(`<form enctype=text/plain>` 构造 JSON body);fetch no-cors+text/plain;form-urlencoded 按 JSON 解析
- **CSRF+XSS**:XSS 读取 DOM token 携带提交(同站下限)
- **CSRF+CORS 桥接**:反射 Origin+credentials → fetch 读取 token(CORS 仅作桥接不单报)
- **CSPT2CSRF**:前端 path traversal+victim cookie,同源 JS 绕过 SameSite+token
- **clickjacking**:`X-Frame-Options`/`frame-ancestors` 缺失 → 透明 iframe 同源点击绕过 token

## 三、证明 | 跨站写成功 不真实改写他人账号

- form POST(改邮箱/转账)cookie 自动携带;GET CSRF(`<img>`);JSON(text/plain 伪装/fetch credentials);method override GET(`?_method=DELETE`)
- OAuth CSRF(缺 state):投递 `/oauth/callback?code=ATTACKER_CODE` 至受害者 → 绑攻击者 OAuth → 登录受害者账号
- 扫码 CSRF:无痕模式获取 QR token,投递 `/login?token=...` → 受害者顶栏导航触发绑号(须无痕端登录态生效才算成立)
- 证实跨站写成功即半条,复现后立即改回,不真实修改他人密码/不真实转账

## 四、误报

- 闸为请求头 token(删 cookie 仍受理/删 token 才拒)= 跨站不可设置,无利用面
- token 真实校验;SameSite=Strict 无子域 XSS;JSON 严格 content-type;CORS 不反射;二次确认(密码/验码/2FA);GET 只读;OAuth 有 state;clickjacking 有 X-Frame-Options;扫码须 App 真实确认;pre-session token 登录后真实轮换
