## FUZZ | 黑盒最重要 | 确认影响后端的字段 | 通过后端响应选择合适的其他思路
1. 删除相关字段, 直至剩余正确字段, 测试才有意义
2. 通过fuzz手法可以渐进式发现后端的非预期响应, 包括全表, 相关报错等, 通过此进一步深入

## 1. 删 | 依次删除所见字段 确认真正响应后端的字段 | 不要只尝试一个字段 | 最重要 影响改操作
1. 二分法删除字段: 全部删除->二分->直到最小可行影响后端
2. 直接删除所有query或者body中的字段, 观察这个请求是不是不认参数, 只认cookie
3. 依次删除所有字段, 只保留真正影响后端的字段, 有的字段删除可能有泄露情况
4. 针对留下来的字段尝试各种空值, null, /, *, []等等

## 2. 改 | 改字段值 fuzz的核心 | 提供思路可自由发挥
1. **特殊值**:`0` `-1` `-0` `999999999999999` `空` `null` `undefined` `{}` `[]` `{{}}`。租户/过滤类试 0/-1/空
2. **数值越界**:`-1` `0` `2147483648`(Int32+1) `1e18` `1.5`。
3. **分页拉全表**:`pageNo=0`/`-1`/翻完,`pageSize=0`/`-1`/`999999`。
4. **通配符**:`*` `%` `_` `?` `.*`(SQL LIKE/ES/文件名)。
5. **路径类值**:`/` `\` `/\` `..` `../`(字段值含路径字符,可能触发穿越)。
6. **注入按栈**:`'` `";--` `' OR '1'='1`(SQL);`{{7*7}}` `${7*7}`(SSTI);`{"$ne":""}` `password[$ne]=x`(NoSQL)。
7. **特殊字符**:`$$` `#` `%00`(null byte 截断) `%0a`。
8. **类型/布尔混淆**:`true` `0` `"1"` `[1]`(数组) `{"role":"admin"}`(嵌套)。
10. **空/null/缺省三态**:`""` vs `null` vs 不传,都试。
11. **编码值绕过滤**:`userId=12345`→`0x3039`(16进制)/`%31%32%33%34%35`(URL编码),后端解码后可能绕过对明文 id 的黑名单/过滤

## 3. 增 | 增加字段 fuzz的特色
1. **分页拉全表**:`pageSize=999999`,`pageNo=1..N` 
2. **隐藏过滤参**:`status=all`/`isDeleted=1`/`showHidden=true`/`area=内部区`
3. **提权参数**:`role`/`isAdmin`/`isVerified`/`permissions`/`tenantId`。
4. **排序参**:`orderBy=SQL片段`/`sort=create_time`。
5. **内部标志**:`debug=1`/`internal=1`/`admin=true`。
6. **回包字段回塞**:回包里的字段名塞进请求(响应暴露的可写字段)。
7. **回调/外链**:`callback=`/`webhook=`/`notifyUrl=`
8. **嵌套/原型**:`user.role=admin`/`__proto__`
9. **参污染**:同名参两次(`userId=A&userId=B`)。

## 换 method | update <-> list
1. **POST↔GET 互换**:body 字段挪到 query(GET 无 body)。POST 验权 GET 不验是最常见绕过,直接出他人数据。
2. **PUT/PATCH/DELETE/OPTIONS/HEAD 都试**:OPTIONS 回 `Allow` 暴露隐藏方法;HEAD 看头不返 body;PUT/PATCH 可能绕过 POST 的写校验。
3. **同方法换 content-type**:`application/json`↔`form-urlencoded`↔`multipart`,后端按 CT 走不同校验分支。
4. **方法名大小写/变体**:`get`/`Get`/`GET`、`POST`→`post`,部分路由大小写不敏感。

## 换 path
1. **版本号±**:`/v2/`→`/v1/`/`/v3/`;`/api/`→`/api/v1/`。旧版常缺鉴权或未打越权补丁(v2 修了 v1 没修)。
2. **数字 cmd 邻号**:`/data/123/forward`→`/124/`、`/125/`。
3. **删 path 段**:去掉一段(`/api/user/123/info`→`/api/user/info`),后端可能 fallthrough 到更宽口。
4. **加 path 段**:`/api/users`→`/api/admin/users` 探隐藏管理路由。
5. **后缀变体**:`.json`/`.xml`/`.css`/`.js`/`;.css`。
6. **大小写/尾斜杠**:`/Api/` vs `/api/`、`/api` vs `/api/`,路由可能不一致。


