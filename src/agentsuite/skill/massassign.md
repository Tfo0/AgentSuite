## 一、确认 | 对照差字段 + 增改看后端照写

1. **对照差字段**:普通号建/改资料,对照管理员建用户/改资料的请求,差出来的字段(管理员有、普通号请求里没的)= 提权靶(`role`/`isAdmin`/`permissions`/`verified`/`tenantId`/`balance`/`is\w*`)。
2. **增改后看响应**:增/改权限位 → `me`/回包 `role=admin`/`isAdmin=true`/`verified=true`/余额变 = 照写提权;400 未知字段 / 字段被白名单吞 = 没吃;字段 echo 了但权限没真变 = 展示位非权限位。

## 二、绕过 | 增/改/删权限位 + 嵌套绕白名单 只给思路自由发挥

- **增字段**:body 塞页面控件没有的权限位(`role`/`isAdmin`/`is_admin`/`permissions`/`verified`/`tenantId`/`balance`/`isVerified`/`isActive`),值设 `admin`/`true`/`1`/`0`/超管角色名/别人 `tenantId`。
- **改字段值**:已有权限位改值(`role:editor→admin`/`isAdmin:false→true`/`verified:false→true`/`tenantId:自己→别人`)。
- **删字段**:删 `tenantId`/`ownerCode`/`role` → 后端用 default 高权或跳归属校验(权限位 omission)。
- **嵌套绕顶层白名单**:顶层被白名单挡 → 嵌套 `user.role`/`address.city`/`__proto__`/JSON 重复键;`is\w*` 试大小写/下划线变体(`is_admin`/`isAdmin`/`is.admin`)。
- **状态位**:`hidden`/`publish`/`edit`/`preview` 塞值 → 强制发布/取消隐藏/进草稿编辑态(状态越权,同机制)。

## 三、漏洞证明 | 只对自己号塞一次 过了立刻改回

- 任一轴使 `me`/回包权限位真变(`role=admin`/`isAdmin=true`/`verified=true`/`tenantId` 跨租户/余额变)= 提权成立。证读:低权号过管理口看是否放行;证写:建/改/删用「先加自己的 → 再删自己加的」,只对自己号塞一次,过了立刻改回,不真改他人号不真删。
- 状态位变(`hidden=false`/`publish=true`)= 强制改资源可见态,证资源真被发布/取消隐藏。

## 四、误报场景

- 增字段回 400 未知字段 / 字段被白名单吞(回包无该字段)= 后端 allowlist,没吃。
- 字段 echo 了但 `me` 权限没真变 / 管理口仍 403 = 展示位不是权限位。
- `role` 改了但后端按 session 重算角色 = 改了无效。
- 嵌套/`__proto__` 被 sanitize = 没注入。
- 状态位变但只前端展示态(后端不认)= 没真改。
- 只能改自己号本就能改的字段(展示名/头像)= 不是提权。
