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

## Dev notes
Initially developed in 2002 with Delphi 6, now with Delphi 10.3.3 (Community Edition).
Icons are generated at http://fontello.com/ . Use fontello.json for further modifications.

For the default template we are targeting compatibility with Chrome 49 as it's the latest version running on Windows XP.

## Libs used
- [ICS v8.64](http://www.overbyte.be) by François PIETTE
- [TRegExpr v0.952b](https://github.com/andgineer/TRegExpr/releases) by Andrey V. Sorokin
- [JEDI Code Library v2.7](https://github.com/project-jedi/jcl)
- [Kryvich's Delphi Localizer v4.1](http://sites.google.com/site/kryvich)
