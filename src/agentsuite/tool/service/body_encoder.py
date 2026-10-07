"""body 序列化器:kind 驱动 → (display_text, raw_bytes, content_type)。

raw 是工具集里唯一"从零造 body"的入口(repeater 编辑已序列化 body、brute 改值,
都不序列化)。序列化逻辑归这里,不散给 agent 手写。kind 决定 value 形状 + 序列化
+ Content-Type 配对——agent 只给意图,工具兜一致性(灭"CT 配错 body → 服务器静默
按错格式解析 → 错响应 → 错判漏洞"这一类静默失败)。

设计原理=生成 vs 填:不让 agent 生成规范 HTTP body 串(escape/boundary/编码处处静默错),
而是有 schema 让 agent 填(kind+value),工具序列化。三级阶梯:kind 驱动(json/form/
multipart,工具兜)→ text(原样,agent 自设 CT,逃生口)→ Bash(绕过 traffic 仪表,断
证据链,最后手段,见 prompt 约束)。

返回三元组:
- display_text:可读 str,存 traffic + traffic_get 显示(multipart 文件 part 占位
  [FILE N bytes],不把二进制灌进 TEXT 列 / 不撑 SDK 1MB ceiling)。
- raw_bytes:真发送 bytes(json/form=utf-8,multipart=文件二进制+utf-8 文本)。
  text kind 留 None(send 走 .text,agent 全控编码,= 方案A 行为)。
- content_type:顶层 CT。text kind 留 None(agent 在 headers 自设)。
"""
from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urlencode
from uuid import uuid4


def encode_body(kind: str, value: Any) -> tuple[str | None, bytes | None, str | None]:
    """kind 驱动序列化。返回 (display_text, raw_bytes, content_type)。

    kind ∈ {json, form, text, multipart}。未知 kind 报 ValueError(traffic_send
    handler 捕获后返 is_error,agent 看到显式错)。
    """
    if kind == "text":
        # 逃生口:agent 原样发,自设 CT。display=原文,raw_bytes=None(send 走 .text)。
        text = "" if value is None else str(value)
        return text, None, None
    if kind == "json":
        s = json.dumps(value, ensure_ascii=False)
        return s, s.encode("utf-8"), "application/json"
    if kind == "form":
        # dict 或 [[k,v]...] → urlencoded。非 ASCII urlencode 成 %XX(ASCII 安全,send 无歧义)。
        s = urlencode(_form_pairs(value))
        return s, s.encode("utf-8"), "application/x-www-form-urlencoded"
    if kind == "multipart":
        return _encode_multipart(value or [])
    raise ValueError(f"未知 body kind:{kind}(须 json|form|text|multipart)")


def _form_pairs(value: Any) -> list[tuple[str, str]]:
    """form value 归一成 [(k, v)]。dict→items;list 项=[k,v] 或 {name,value};其他报错。"""
    if isinstance(value, dict):
        return [(str(k), str(v)) for k, v in value.items()]
    if isinstance(value, list):
        out: list[tuple[str, str]] = []
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                out.append((str(item[0]), str(item[1])))
            elif isinstance(item, dict) and "name" in item and "value" in item:
                out.append((str(item["name"]), str(item["value"])))
            else:
                raise ValueError(f"form 列表元素格式错:{item!r}(须 [k,v] 或 {{name,value}})")
        return out
    raise ValueError(f"form value 须 dict 或 list,得到 {type(value).__name__}")


# 常见扩展名 → content-type(multipart 文件 part 推断用;agent 可 content_type 字段 override)
_EXT_CT = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp",
    ".svg": "image/svg+xml", ".pdf": "application/pdf", ".txt": "text/plain",
    ".csv": "text/csv", ".html": "text/html", ".htm": "text/html",
    ".json": "application/json", ".xml": "application/xml",
    ".zip": "application/zip", ".gz": "application/gzip", ".tar": "application/x-tar",
    ".mp4": "video/mp4", ".mp3": "audio/mpeg", ".wav": "audio/wav",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}


def _infer_content_type(file_path: str) -> str:
    ext = os.path.splitext(file_path)[1].lower()
    return _EXT_CT.get(ext, "application/octet-stream")


def _encode_multipart(parts: list[dict[str, Any]]) -> tuple[str, bytes, str]:
    """multipart/form-data。parts 每项:name + (value 文本 | file_path 文件)。

    文件 part 读 file_path bytes 嵌入 raw_bytes(真发);display 里占位成
    [FILE N bytes](可读、不灌二进制进 DB)。boundary 工具生成,agent 不碰语法。
    raw evidence 是 display-only(_get_base_request reject raw: 前缀,永不重发),
    所以存 display 不存 bytes 没后果。
    """
    boundary = f"----traffic_send_{uuid4().hex}"
    display_parts: list[str] = []
    byte_parts: list[bytes] = []
    for p in parts:
        name = str(p.get("name") or "")
        if not name:
            raise ValueError("multipart part 缺 name")
        ct = p.get("content_type")
        if p.get("file_path"):
            fp = str(p["file_path"])
            try:
                with open(fp, "rb") as f:
                    content = f.read()
            except OSError as exc:
                raise ValueError(f"读 multipart 文件失败 {fp}:{exc}") from exc
            filename = str(p.get("filename") or os.path.basename(fp) or "file")
            ct = ct or _infer_content_type(fp)
            disp = f'form-data; name="{name}"; filename="{filename}"'
            head = (f"--{boundary}\r\nContent-Disposition: {disp}\r\n"
                    f"Content-Type: {ct}\r\n\r\n")
            display_parts.append(f"{head}[FILE {len(content)} bytes]\r\n")
            byte_parts.append(head.encode("utf-8") + content + b"\r\n")
        else:
            val = "" if p.get("value") is None else str(p["value"])
            ct = ct or "text/plain"
            disp = f'form-data; name="{name}"'
            head = (f"--{boundary}\r\nContent-Disposition: {disp}\r\n"
                    f"Content-Type: {ct}\r\n\r\n")
            display_parts.append(f"{head}{val}\r\n")
            byte_parts.append(head.encode("utf-8") + val.encode("utf-8") + b"\r\n")
    closing = f"--{boundary}--\r\n"
    display_text = "".join(display_parts) + closing
    raw_bytes = b"".join(byte_parts) + closing.encode("utf-8")
    return display_text, raw_bytes, f"multipart/form-data; boundary={boundary}"
