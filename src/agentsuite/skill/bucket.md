## 申请凭证包 | fuzz key字段/action等字段

1. **key 字段**:值换通配 `*`/`**`/`%2A`/空/`/`/`.`/`/*` ; 删除整个字段; `*` 常匹配空桶,`**`/空常匹配整桶,`/`/`.` 触桶根。
2. **路径字段**(进 OSS Policy 的 path/prefix 段):同填 `*`等统配符; 段换 `../`/`../../../`/`..%2f`/`..%5c`/`../../../&/../../` 扩根。
3. **action 字段**:置 `*`,穷举非预期策略/list 等(后段 Policy 覆盖前段→整桶)。
4. **未授权**:二分法删鉴权字段(`Authorization`/`Cookie`),观察能否仍返回 token;


## 上传包

**探针**
1. **覆盖他人对象**:path/key 设成他人 md5/key(模块响应列表取,搜 `md5`/`md5sum`, 可以用自己的md5猜测;
2. **覆盖官方对象**:对官方已引用资源 PUT 覆盖,原 URL GET 验收;CDN 强刷或等缓存过再判;
3. **竞态(TOCTOU)**:配"不存在则回源"或异步删恶意文件时,边 PUT 边 DELETE 抢占存在性窗口,看删后是否仍能访问不该有对象。

**绕过**
1. **接管头**(按厂商类型自定):加 `x-cos-acl: public-read`(公有读)/`x-cos-grant-full-control: id="你的UIN"`(控制权转你);
2. **CT 绕过**:`Content-Type` 改 `text/HtMl`/`text/html,image/png`(签时没签 CT);CT 锁死走带签读改响应头 CT。
3. **key 穿越逃 prefix**:object key 填 `../`/`../../../`+其他前缀(网关映射文件路径时逃 prefix;原生 S3 扁平串不穿越)。
4. **List/Delete 403 不止步**:去 Auth 换匿名票重放,对任意 key 直接 GET/PUT。


## 带签读 / 下载口包

**探针**
1. **`?key=` 列桶**:key 值换 `/`/`.`;回 ListBucket XML 取业务前缀 GET 同口;
2. **换桶(host 没进签)**:看签名头(`q-header-list`/`SignedHeaders`/`X-Amz-SignedHeaders`)没 `host` 时,主机段换同账号其他桶域(同模块报错/证书 SAN 取;没有 inconclusive),path 和签名 query 不动,加 `?uploads` 请求 ListMultipartUploads;
3. **fileKey 重放**:流量里密文 `fileKey`(下载口 query),站点根可能 301 到新域、旧 host 下载口可能仍可用;从流量取 fileKey 请求旧 host 下载口,乱填应空/错、真实 key 返回原文件;
4. **猜短文件名**:无"文件已存在"预言时,猜短原名(`1.jpg`/`2.png`/`5.jpg`)匿名 GET CDN;`filename=*` 常下发 appId+bucket,CDN 前缀拼出下载他人未公开原文件。
5. **提取码明文回显**:分享详情 JSON 一边 `need_pwd`/`auth_level` 要码,一边 auth 对象明文码放 `pass_word`,或响应正文内联明文码;空码请求查看口(列表应空/闸字段要码),同份回包取明文 `pass_word` 填回,或响应正文已有明文码直接取;用 `file_id`+码请求下载口跟到真实文件头(PDF/ZIP)。

**绕过**
1. **匿名列桶**:去登录头/Cookie 重放,看网关纯匿名是否照样代理 list。
2. **改响应头 CT(存储 XSS)**:对象内容可控 + CT 锁死 + 有临时钥/能再签时,带 `response-content-type=text/html` 的 GET(COS/OSS 签名能覆盖响应头),新签 URL GET 看是否当 HTML 执行。
3. **下载口鉴权**:DownloadURL 的 `uin`/`skey` 源自 Cookie;带 `uin=1`(不要 skey)重发详情,空 uin 也返回 URL 时取回带签 URL 验文件头(ELF/PK)。
4. **分享鉴权 false**:鉴权口有 `download_enable`/`view_minutes_enable` 开关或没鉴权口(404 不止步);下载口+签名口重放要 `auth_share_id`+`resource_type`;POST 缺参改 GET query 写入 `record_id`/`auth_share_id`;网关缺 `sharing_id` 只回参数非法,两个 id 一起带才签发;没鉴权口直接请求 public 路径;COS 无 Referer 403 带分享页 Referer 再 GET。

## 桶根 / 匿名全开桶

**探针**
1. 桶域根 GET 或 `?policy`/GetBucketPolicy 全 Allow——匿名直接读写,不用钥。桶根 LIST(无 AK)取业务前缀;对官方已引用对象 PUT 覆盖,原 URL GET 验收(CDN 强刷或等缓存过再判);不改桶策略,只覆盖已引用对象。(与申请凭证 `*` 区别:本条匿名全开不用钥。)

## supabase 场景

流量响应有 `role=anon` JWT + `apikey` 头(`/rest/v1/` 或 `/storage/v1/` 路径)时为 supabase 后端,双 REST 口分口鉴权:表数据口 `/rest/v1/`(PostgREST)anon 常被 RLS 拦 403,不止步;存储对象口 `/storage/v1/` 常对 anon 另开。

从流量取 `apikey` + `anon JWT`,`POST /storage/v1/object/{桶}/{探测key}` 上传探测文件,头带 `apikey` + `Authorization: Bearer <anon JWT>` + `x-upsert: true`(覆盖已存在对象必须带,不带拒同名),正文传唯一标记;公开 GET 同对象 URL 对照,取回标记(不真覆盖官方运营对象,只测探测文件,测完 DELETE)。

## 边界

区分三条接管路径:**临时凭证**(后段 Policy 覆盖前段,key 通配整桶)、**永久钥**(AK/SK 明文,自算签)、**匿名全开桶**(桶策略全 Allow,不用钥)。
