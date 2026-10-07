## 一、确认 | 认算法、密钥来源、验签严否

1. **验签严否(先判)**:改 payload 即拒=严验,不用往下绕;接受 `alg=none` 或剥离签名=不验签,直接改声明。
2. **算法**:`alg` 是 HS256(对称,密钥在服务端)、RS256/ES256(非对称,公钥可得即能验)、`none`。
3. **密钥来源**:HS256 密钥是否弱口令(项目名/常见词);RS256 公钥能否取到(JWKS 端点/`/certs`/`/.well-known/jwks.json`/HTTPS 证书)。

## 二、绕过 | 验签不严或密钥可控才有攻击面 只给思路自由发挥

- **alg=none**:header 改 `{"alg":"none"}`,去 signature 留尾点(`header.payload.`)。服务端不验签,篡改声明被接受。
- **RS256→HS256 混淆**:取公钥(JWKS/`/certs`/HTTPS 证书),header 改 HS256,以公钥当 HMAC secret 签。
- **弱密钥爆破**:HS256 弱口令(`secret`/`password`/项目名相关);爆破出密钥即能自签任意令牌。
- **kid 注入**:`kid` 可控时,SQL(`' UNION SELECT 'secret'--` 让密钥指向已知值)、路径遍历(`../../dev/null` 指空文件当密钥)、命令注入(`key.txt; whoami`)。
- **jku/x5u**:`jku` 指攻击者 JWKS(`https://attacker.com/jwks.json`),自生成 RSA 对,私钥签、公钥入 JWKS。
- **声明篡改**:`role:admin`/`isAdmin:true`/`userId:他人id`/`sub:admin`/`permissions` 加 admin、`tier:premium`。配合上面任一成功后改声明。
- **exp/签名剥离**:`exp` 改未来时间绕过期;去 sig 段留 `header.payload`。
- **发签口不登录冒充**:发签/换票口不校验登录或只校验产品号 → 拿票冒充他人。变体:IM 体验票 `userSig`、共享 JWT 产品号、联合登录 `uin`、互联票、培训绑定、空 `openId`(票里 `userId`/`openid`/`uin` 可控即改成他人)。
- **刷新票提权**:`/refresh` 空 body `{}` 或省字段 → 回 admin token;刷新时改 `scope`/`role` 字段提权。

## 三、证明 | 篡改声明被后端接受 = 提权/换号

- 任一轴使篡改声明(提权/换号/延期)被后端接受 = 成立。证读:打管理口/`me` 看 role 是否真变 admin/他人。
- 命令注入(kid):`whoami` 回显 = 命令执行成立。
- 发签冒充:拿到他人身份的票打资源口成功 = 成立;刷新提权:回的 token 权限放大(打原本无权资源成功)= 成立。

## 四、误报

- 签名严验(改 payload 即拒);公钥不可得;HS256 密钥强爆破不动;`kid`/`jku` 服务端白名单或不可控。
- 前端自塞的 Authorization 头后端不验不算。
- `exp` 服务端独立校验(改了仍拒)。
- 发签口要登录/真产品密钥,票里 `userId`/`uin` 固定不可控;`/refresh` 校验原票 scope,空包/改字段被拒。
