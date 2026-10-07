### 目录(按关键词频率从高到低)

三列:**语义**(自然语言,描述正则/值形态/响应内容这类不好当关键词的信号) | **clean**(能字面匹配的关键词/正则,含 path 段、body key、body/response 里的值模式) | **skill**(主靶+副靶,逗号分隔,一行可多目标)。
行按**关键词簇**拆,同模块可多行;fuzz 是基础,所有流量都可以尝试分发至 fuzz。

| 语义 | clean | skill |
| --- | --- | --- |
| 用户标识符,纯数字值,手机号,号段,时间戳,响应含敏感信息(PII/证件/金额/地址) | `\w*[Ii]d,\w*user` | idor,fuzz |
| 存储桶凭证类,响应回显凭证/policy | action,policy,getToken,getUrl,/sts,/assumeRole,/getUploadSign,credential,AccessKeyId,SecretKey,SecurityToken | bucket |
| 带签名访问类 | sign,signature,aksk,X-Amz,expires,q-sign-algorithm,/api/storage/sign | bucket |
| 文件key类,对象key/下载口鉴权参数 | fileKey,filename,object,prefix,dir,key,uin,skey,record_id,auth_share_id | bucket,idor,fuzz |
| 上传类 | /upload,/putFile | bucket |
| 公共状态字段,MassAssignment | is\w*,hidden,publish,edit,preview,role,isAdmin,permissions,verified | massassign,fuzz,csrf |
| 未登录前缀端点,内部口/admin | /n/,/d/,/fapi/n/,/guest,/unlogin,/internal,/admin | noauth |
| 列表接口,响应含他人数据 | total,list,rows,pager,isDelete | noauth |
| 账号安全,登录/改密 | login,reset,exists,checkPhone,password,oldPwd,newPwd,/logout | account,csrf |
| 支付逻辑,下单/绑券 | price,amount,quantity,coupon,order,discount,points,/pay,/order,/checkout | pay,fuzz,csrf |
| 竞态(TOCTOU) | balance,limit,stock | pay,fuzz,csrf |
| 支付/签约签名口子 | calculateSign,signKey,sign_data,mch_id,/merchant,/open | pay |
| 验证码/短信,手机号字段,响应回显验证码 | verifyCode,sms,sendCode,sendSms,code,/sendsms,/sendCode,phone,mobile,telephone,tel | phone |
| 业务流程/状态机,注册/找回密码多步流程 | step,state,status,flow,next,complete,process,/step,/process,register,forgot | setup,fuzz,csrf |
| 状态改写口(改密/改邮箱/改手机/支付/绑券/申请/个人资料修改/回帖/点赞/登出等敏感写操作) | csrf,csrfToken,_csrf,/logout,/profile,/comment,/like | csrf |
| 服务端按URL拉取,代理/网关入口,PDF/截图/渲染/预览/头像,响应含远端内容/标题 | url,callback,webhook,target,host,src,avatar,/proxy,/fetch,/import,/render,/preview,/screenshot,/thumbnail,/pdf,/metadata | ssrf |
| 开放重定向参数 | url,redir\w*,return\w*,back\w*,dest\w*,jump\w*,skip\w*,rurl,next,forward,continue,go,target,out,link,view,to,ref,callback,path | redirect |
| SQL搜索/排序/筛选 | search,keyword,orderBy,sort,filter,like,sidx,where | sqli |
| NoSQL运算符 | $ne,$gt,$gte,$lt,$where,$regex,$or,$nin | sqli |
| 报错栈含SQL | SQLSTATE,mysql_,pg_,sqlite_,ODBC,SQL syntax,ORA-,Traceback,exception | sqli |
| 评论/昵称/富文本/搜索回显,markdown/编辑器,响应回显输入/HTML标签或模板引擎报错 | comment,nickname,bio,content,markdown,richText,editor | xss,ssti |
| 文件下载/穿越/LFI,文件路径/本地文件参数,响应报错含路径/文件内容回显 | /download,/file,filename,include,read | path |
| 配置/备份/静态目录/swagger | /config,package.json,.env,/backup,/dump,swagger,openapi,/static,/assets,/web.config,.yml | path |
| 令牌签发/刷新端点,响应回显 JWT(eyJ)/JWKS,alg/kid/jku/x5u | /refresh,/token,/auth,/jwks,eyJ,Bearer,alg,kid,jku,x5u | jwt |
| OAuth授权流程,授权码/PKCE | /sso,/authorize,/callback,redirect_uri,grant_type,scope,client_id,code,state,response_type,code_challenge | oauth |
| SAML断言,身份/条件字段 | SAMLRequest,SAMLResponse,Assertion,RelayState,NameID,Conditions | saml |
| GraphQL端点 | /graphql,/graphiql,/gql,query,mutation,operationName,__typename,__schema | graphql |
| LLM 对话口 | /chat,/createTask,/api/llm,/v1/completions,/v1/messages,/assistant,/prompt,/agent,tool_calls,function_call | llm |
| XML/SOAP接口,SVG/RSS/Atom | xml,soap,xmlns,doctype,entity,wsdl,application/xml,svg,rss,atom,gpx,xhtml | xxe |
| 文档处理类,OOXML/PDF 转换·预览·解析 | docx,xlsx,pptx,pdf,/convert,/preview,/export | dos,xxe |
| 图片处理/缩略图/尺寸,后端解码(pixel/SVG bomb) | /thumbnail,/resize,/img,/image | dos |
| 表达式语言引擎(SpEL/OGNL),/eval 端点,响应报错含引擎名 | SpEL,OGNL,expression,/eval,/spel | ssti |
| 通用分页/带参口,无特定类 | pageNo,pageSize,page,offset,count,size | fuzz |
