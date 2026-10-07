"""dispatch_service:dispatch agent 把可疑流量打包成模块入队(替旧 fan-out)。

dispatch agent 不再按 traffic_id×skill 笛卡尔 fan-out,而是**自己打包**:LLM 判断
把相关流量打成一包(1+ traffic_ids),配上 1+ 攻击面 skills + keys + notes,一次
dispatch_send = 1 模块行写 dispatch_queue 表。module_id = sorted(traffic_ids) 稳定哈希
→ UNIQUE 幂等(同组流量重复打包返回已存行不重写,强制"每组流量只打包一次")。

skills 是漏洞家族 key 列表(idor-test/upload-test/...,= skill 目录 stem);[]=novel
(无 catalog,走 verify 自由);['noise']=噪音丢弃→status=dropped(不进 verify)。
keys≤5 证据指针,notes 一句话分组理由(禁打法,打法归 skill/<stem>.md;只有 novel skills=[] 时才写思路)。1 模块→1 verify agent,逐原生 Read 读完一个个打。

state.dispatched 累计已打包的模块(给 dispatch stop hook 做覆盖率门禁:每 batch_rid
∈ ⋃ module.traffic_ids 才放行)。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..data.store import AuditStore
from ..models import RunState
from .query_service import load_common_params

_MAX_KEYS = 5


def _match_common_in_key(key: str, names: set[str]) -> list[str]:
    """key 串里命中的共过参数名(整标识符 token 匹配,防 'mysubject_aid' 误中 'subject_aid')。

    keys 是证据指针(free-form,如 'subject_aid=305219'、'/?getToken'、'fileId=123')。
    共过参数名(如 'subject_aid')作整 token 匹配:'subject_aid=305219' 命中,
    '/?getToken' 不命中。
    """
    hits: list[str] = []
    for name in names:
        if re.search(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", key):
            hits.append(name)
    return hits


class DispatchService:
    """dispatch agent 打包模块入队:校验 traffic_id 存在 + 共过参数 strip + 写 1 模块行。"""

    def __init__(self, store: AuditStore, *,
                 session_dir: str | Path | None = None) -> None:
        self.store = store
        # session_dir 用于读 pipeline/proxy/noise.jsonl(lib.build_clean 落的共过参数表)做
        # keys strip。None(测试/老路径)→ 不 strip(空集,降级兼容)。prod 由
        # build_traffic_services 传入。lazy 缓存(首次 dispatch 才读;build_clean 在
        # record 尾跑,先于 dispatch)。
        self._session_dir = session_dir
        self._common_names: set[str] | None = None

    def _common_param_names(self) -> set[str]:
        """共过参数名集(lazy 缓存)。session_dir 缺/文件缺 → 空集(不 strip)。"""
        if self._common_names is None:
            params = load_common_params(self._session_dir) if self._session_dir else []
            self._common_names = {str(p.get("key")) for p in params if p.get("key")}
        return self._common_names

    def dispatch(
        self, *, traffic_ids: list[str], skills: list[str],
        keys: list[str] | None = None, notes: str = "",
        state: RunState | None = None,
    ) -> dict[str, Any]:
        """把可疑流量打包成一个模块入队。返模块行 {module_id, traffic_ids, skills,
        keys, notes, status, stripped?}(= 队列数据)。

        - traffic_ids(req,≥1):不存在→ValueError(校验存在,防幻觉锚)。
        - skills(req,可 []):[]=novel;['noise']→status=dropped。
        - keys(opt,≤5):>5→ValueError。公共参数(按子域名,host 内 key 频次>50%,非资源标识符)
          会被**自动剥离**(upsert 前,keys 永不进库/state)+ 反馈进 stripped 字段,
          防 dispatch 把 subject_aid 当越权指针打包致 verify 浪费轮次深测。
        - notes(req):一句话分组理由(禁打法;novel skills=[] 时才写思路草案)。
        - 幂等:同 traffic_ids 组(module_id)重复打包返回已存行不重写。
        """
        if not traffic_ids:
            raise ValueError("traffic_ids 不能为空(模块至少捆 1 条流量)")
        if not str(notes or "").strip():
            raise ValueError("notes 不能为空(打包理由)")
        raw_keys = keys or []
        if len(raw_keys) > _MAX_KEYS:
            raise ValueError(f"keys 最多 {_MAX_KEYS} 个(收到 {len(raw_keys)})")
        # 共过参数 strip(upsert 前):keys 是证据指针(free-form),共过参数名作整 token 匹配。
        names = self._common_param_names()
        kept_keys: list[str] = []
        stripped: list[dict[str, str]] = []
        for k in raw_keys:
            ks = str(k)
            hits = _match_common_in_key(ks, names) if names else []
            if hits:
                stripped.append({"key": ks,
                                 "reason": f"公共参数 {','.join(hits)}(host 内 key 频次>50%,非资源标识符,已自动剥离)"})
            else:
                kept_keys.append(ks)
        # 校验 traffic_id 存在(防幻觉:打包的流量须真实在库)
        missing = [t for t in traffic_ids if not self.store.evidence_exists(t)]
        if missing:
            raise ValueError(f"traffic_id 不在流量库:{missing[:5]}")
        # noise 模块→dropped;其余 unverified
        skills_norm = [str(p or "").strip() for p in skills]
        status = "dropped" if skills_norm == ["noise"] else "unverified"
        module_id, row_status = self.store.upsert_module(
            traffic_ids=[str(t) for t in traffic_ids],
            skills=skills_norm, keys=kept_keys, notes=notes, status=status,
        )
        module: dict[str, Any] = {
            "module_id": module_id,
            "traffic_ids": [str(t) for t in traffic_ids],
            "skills": skills_norm,
            "keys": kept_keys,
            "notes": notes,
            "status": row_status,
        }
        if stripped:
            module["stripped"] = stripped
        # 累计模块给 stop hook(覆盖率)+ runner _resolve(per-unit 覆盖)
        if state is not None:
            state.dispatched.append(module)
        return module
