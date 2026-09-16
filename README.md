## Introduction
You can use HFS (HTTP File Server) to send and receive files.
It's different from classic file sharing because it uses web technology.
It also differs from classic web servers because it's very easy to use and runs "right out-of-the box".

The virtual file system will allow you to easily share even one single file.

---

## Security — CVE-2024-23692

### 漏洞概述

| 项目 | 内容 |
|---|---|
| CVE 编号 | CVE-2024-23692 |
| 影响版本 | HFS 2.3m、HFS 2.4.0 RC07 及以下 |
| 漏洞类型 | 未经身份验证的远程代码执行（Unauthenticated RCE） |
| CVSS 评分 | 9.8 Critical |
| 攻击向量 | 网络可达，无需认证，无需用户交互 |

### 漏洞原理

HFS 的模板引擎在处理 `{.?search.}` 宏（读取 URL 查询参数）时，会对返回值递归调用 `applyMacrosAndSymbols2()`，导致用户可控的字符串被当作模板代码执行。

攻击链分为四步：

```
1. 构造包含 %url% 的 search 参数
         ↓
2. %url% 展开为 macroQuote(完整URL) = {:url_including_payload:}
         ↓
3. %password% 展开为空字符串，导致 {:...:} 引用块提前关闭
         ↓
4. 引用块外的 {.exec|cmd.} 被宏引擎执行 → RCE
```

**POC 示例（仅用于安全研究）：**

```
GET /?n=%0A&cmd=whoami&search=%25xxx%25url%25:%password%}{.exec|{.?cmd.}|timeout=15|out=abc.}{.?n.}{.?n.}RESULT:{.?n.}{.^abc.}===={.?n.} HTTP/1.1
```

### 修复方案

**修复文件：** `scriptLib.pas`

**核心函数：** `noMacrosAllowed()`（第 109–123 行）

```pascal
function noMacrosAllowed(s:string):string;
// prevent hack attempts
begin
  // 步骤 1：将所有宏标记的首字符替换为 HTML 实体
  //   {.  →  &#123;.       .}  →  &#46;}
  //   {:  →  &#123;:       :}  →  &#58;}
  //   |   →  &#124;
  repeat
    i := findMacroMarker(s, i);
    if i = 0 then break;
    replace(s, '&#' + intToStr(charToUnicode(s[i])) + ';', i, i);
  until false;

  // 步骤 2：将 %symbol% 形式的符号引用替换为 HTML 实体
  //   %url%       →  &#37;url&#37;
  //   %password%  →  &#37;password&#37;
  s := reReplace(s, '%([-a-z0-9]+)%', '&#37;$1&#37;', 'mi');
  result := s;
end;
```

**调用位置：** 所有用户可控输入在返回给模板引擎前均经过此函数处理：

| 调用位置 | 防护范围 |
|---|---|
| `urlVar()` 第 548 行 | 所有 URL 查询参数 `{.?name.}` |
| 第 698 行 | 模板变量读取 |
| 第 1549 行 | Cookie 值 |
| 第 2089 行 | URL 解码值 |
| 第 2165 行 | HTTP 请求头 |
| 第 2173 行 | POST 表单参数 |

**修复效果：** POC 中的 `search` 参数经处理后，所有宏标记和符号引用均被 HTML 实体化，无法再触发宏引擎执行。

---

## Security Advisories（后续发现）

本仓库在修复 CVE-2024-23692（`search` 参数入口）之后，继续对 HFS 2.x 的模板引擎做了审计，
发现 **三处相互独立、均可在 2.4.0 RC7 上未认证利用的缺陷**。三者根因、修复点、影响维度各不相同：

| Advisory | 缺陷 | 弱点类型 | 入口 / 位置 | 修其他两条能否关掉它 |
|---|---|---|---|---|
| [WGETNZ-HFS2-2026-001](advisories/hfs2-upload-filename-template-injection/README.md) | 模板注入 → 未授权 RCE | CWE-1336（次 CWE-94） | multipart 上传文件名（`%item-resource%`，`main.pas:3897`） | 否 |
| [WGETNZ-HFS2-2026-002](advisories/hfs2-template-macro-missing-authorization/README.md) | 特权宏鉴权缺失 → 任意文件读/写/删 | CWE-862（次 CWE-22） | 宏分发器无鉴权 + `uri2diskMaybe()` 原样返回绝对路径 | 否 |
| [WGETNZ-HFS2-2026-003](advisories/hfs2-getini-infinite-loop-dos/README.md) | 未授权拒绝服务 → 非终止循环占满服务线程 | CWE-835 | `{.get ini.}` 的配置查找 `getKeyFromString()`（`utillib.pas:2846`） | 否 |

001 与 CVE-2024-23692 的区别：入口点不同、未转义汇点不同，且该 CVE 公布范围是 `<= 2.3m`，**不含 2.4.0 RC7**。
001 与 002 的区别：001 是入口点问题（注入），002 是控制缺失（宏分发器无鉴权模型），002 在任何注入被修复后依然存在。
003 影响的是**可用性**，与 001/002 的机密性/完整性维度不同。

三份 advisory 均附可运行的 PoC（nuclei 模板 / Python 脚本，只读优先、内置 Burp 代理开关），修复建议见各自第 5 节。

> 已于 2026-09-16 向 CNA 提交，编号分配后更新。

---

## Dev notes
Initially developed in 2002 with Delphi 6, now with Delphi 10.3.3 (Community Edition).
Icons are generated at http://fontello.com/ . Use fontello.json for further modifications.

For the default template we are targeting compatibility with Chrome 49 as it's the latest version running on Windows XP.

## Libs used
- [ICS v8.64](http://www.overbyte.be) by François PIETTE
- [TRegExpr v0.952b](https://github.com/andgineer/TRegExpr/releases) by Andrey V. Sorokin
- [JEDI Code Library v2.7](https://github.com/project-jedi/jcl)
- [Kryvich's Delphi Localizer v4.1](http://sites.google.com/site/kryvich)
