## 一、确认 | 认签名节点与断言绑定、哪段后端验

1. **签名节点(先认)**:哪段 Assertion 被签名(`Response`/`Assertion`/`Subject`),哪段被读;签名验签严否(改 Assertion 即拒=严验)。
2. **断言绑定**:`NameID`/`role`/`email` 属性、`Conditions` 时间窗(NotBefore/NotOnOrAfter)哪个驱动账号绑定。
3. **解析器**:XXE 解析器是否启用实体展开(SAML 请求注入实体看是否展开)。

## 二、绕过 | 验签不严或解析器启用才有攻击面 只给思路自由发挥

- **签名包装(Signature Wrapping)**:插恶意 Assertion(攻击者 NameID),服务端读第一个但验第二个签名;或签名在 `Response` 级但读 `Assertion` 级。
- **断言篡改**:`NameID` 改 admin;`role`/`email` 属性改 admin;`Conditions NotBefore/NotOnOrAfter` 改时间扩窗口;未签名段改了被信任。
- **XXE**:SAML 请求注入 `<!ENTITY xxe SYSTEM "file:///etc/passwd">`,`Issuer`/`NameID` 取实体(解析器启用实体展开时)。
- **注释截断**:`<NameID>victim<!--</NameID><NameID>attacker-->`,注释截断签名验证范围,签名只覆盖注释前段,注释后 attacker NameID 被信任。
- **XSW(签名包装变体)**:`Response` 包多个 `Assertion`,签名外层 `Response` 但内层 `Assertion` 未签名,服务端读内层。

## 三、证明 | 改后断言被接受 = 提权/换身份

- 任一轴使改后/未签名 Assertion 被接受(以 admin/他人身份登录)= 成立。证读:登录后看 `me`/角色页是否变 admin/他人。
- XXE:实体展开读本地文件回显 = 成立。

## 四、误报

- 签名节点正确(验签严,改 Assertion 即拒);签名覆盖的段即读取的段。
- 解析器禁实体展开(XXE 不展开)。
- 注释不截断签名范围(签名覆盖全段)。
