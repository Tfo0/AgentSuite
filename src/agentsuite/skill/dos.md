PoC 用 bash。证到资源耗尽即半条,不批量打挂线上。

## 压缩炸弹(上传口后端解压)
- zip bomb:高压缩比嵌套 zip(42.zip→4.6PB)、递归 zip,后端解压撑爆磁盘/内存;gzip 炸弹单层解压成超大流,body 带 Content-Encoding: gzip 发。docx/xlsx/pptx 本身是 zip,可伪装 zip bomb。
- 认:presigned 直传不经后端=无攻击面;后端收 multipart 再解压=有攻击面。

## 图片炸弹(/thumbnail//resize//avatar)
- pixel bomb:小文件大尺寸(7000×7000 PNG 单色几 KB),后端解码成超大位图(≈196MB/张);SVG 炸弹嵌套 use/image 递归引用。
- 认:直接回显 URL 不处理=无攻击面;后端 ImageMagick/Pillow 解码=有攻击面。

## 解析器 DoS(/convert//preview + docx/pdf)
- XML billion laughs:深层实体展开指数膨胀内存;畸形 PDF 递归对象引用/Pages 自指/超大 xref 表;畸形 OOXML 损坏 zip 结构/超大 sharedStrings;JSON 深嵌套/超大数组(`{"a":{...×1000}}`、`[1,...×1e7]`)解析器栈溢出/OOM。
- 认:presigned 直传不解析=无攻击面;后端 LibreOffice/文档转换服务=有攻击面。

## 算法复杂度 DoS(带正则/搜索/哈希的口,无指纹自由模式)
- regex 灾难回溯:evil regex `(a+)+`/`(a*)*` + 长串 `aaa...b` 指数回溯卡 CPU;哈希冲突 POST 很多同 bucket key(旧 PHP/Java)撑爆哈希表。
- 认:无指纹,verify 在复杂输入口现场探,占满一核即半条不强证。

## 连接/内存耗尽(任意口,无指纹自由模式)
- slowloris:慢速发 header/body 占连接池,后端线程/连接耗尽拒服他人;大 body/大分配 超大 JSON/数组撑爆内存配额;并发昂贵请求 并发打 CPU 密集口(加密/渲染/转换)占满 worker 池。
- 认:无指纹,verify 在昂贵口现场探,证到拒服他人即停不持续。

## 误报
- presigned 直传不经后端=上传/图片炸弹无效;缩略图只回显 URL 不解码=无图片攻击面;文档转换走外部三方服务(后端只投递)=无 parser 攻击面;后端有大小/维度/嵌套深度限制(zip 递归禁、图片尺寸上限、JSON 深度上限、regex 超时包裹)=炸弹被拦;响应慢是网络/CDN 抖动(多发取平均排除 RTT);regex 用 re2 或超时包裹=回溯不卡。
