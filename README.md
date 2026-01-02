# App 自动化播放 + Frida 监听 + m3u8 下载方案

> 适用于 **自有产品测试 / 自动化实验**  
> 核心目标：**自动触发 App 播放 → 监听响应 → 提取 m3u8 → 自动下载**

---

## 📋 目录

- [总体目标](#总体目标)
- [整体架构](#整体架构)
- [快速开始](#快速开始)
- [模块说明](#模块说明)
  - [App 操作层（Appium）](#1-app-操作层appium)
  - [网络监听层（Frida）](#2-网络监听层frida)
  - [数据解析与调度层（Python）](#3-数据解析与调度层python)
  - [视频下载层（m3u8 下载器）](#4-视频下载层m3u8-下载器)
- [数据流说明](#数据流说明)
- [关键设计原则](#关键设计原则)
- [适用场景](#适用场景)
- [注意事项](#注意事项)

---

## 总体目标

构建一套**全自动流水线**，完成以下闭环：

1. 自动操作 App，触发视频播放
2. 在播放过程中监听网络请求与响应
3. 捕获接口返回的完整 JSON 数据
4. 从响应中解析出 m3u8 播放地址
5. 自动下载视频内容（无需人工介入）

---

## 整体架构

系统拆分为 **4 个独立模块**，职责清晰、互不侵入：

```
┌──────────┐
│ Appium   │  ← 自动触发播放
└────┬─────┘
     │
     ▼
┌──────────┐
│   App    │
└────┬─────┘
     │ 网络请求
     ▼
┌──────────┐
│  Frida   │  ← 监听请求/响应
└────┬─────┘
     │ send(JSON)
     ▼
┌──────────┐
│  Python  │  ← 解析 & 调度
└────┬─────┘
     │ m3u8
     ▼
┌──────────┐
│ 下载器   │
└──────────┘
```

---

## 快速开始

### 前置要求

- Python 3.8+
- Node.js 16+（用于编译 Frida 脚本）
- Frida 17.0+（CLI、Python 包、Server 版本需一致）
- Appium Server
- Android 设备/模拟器

### 安装步骤

1. **安装 Python 依赖：**

```bash
pip install frida appium-python-client
```

2. **编译 Frida Hook 脚本：**

```bash
cd frida-compile
npm install
npx frida-compile -S src/hook_chapter.js -o output/hook_chapter.js
```

3. **运行下载脚本：**

```bash
python app/hook_downloader.py
```

---

## 模块说明

### 1. App 操作层（Appium）

**职责：**

- 启动 App
- 自动点击书籍 / 章节
- 触发视频播放行为

**说明：**

- 只负责 UI 行为
- 不处理网络、不处理下载
- 不与 Frida 直接通信

---

### 2. 网络监听层（Frida）

**职责：**

- 注入目标 App 进程
- 监听网络层接口返回
- 捕获 Response 中的完整 JSON 数据
- 将 JSON 数据原样发送给外部控制端

**说明：**

- Hook 网络层（OkHttp / Retrofit）
- 不修改请求、不破坏签名
- 不解析业务字段，只负责"监听与转发"

#### ⚠️ Frida 17.0.0+ Java Bridge 问题

**问题现象：**

从 Frida 17.0.0 开始，Java/ObjC/Swift 这些 bridge 不再默认打进 GumJS runtime。这导致：

- **CLI 工具（`frida -U ... -l script.js`）**：能正常使用 Java，因为 frida-tools 的 REPL/trace 自带 bridges 做兼容
- **Python `create_script()`**：Java 永远是 `undefined`，因为 Python 直接加载的脚本运行环境里没有注入 Java bridge

**症状：**

```javascript
console.log(typeof Java);  // undefined
Java.perform(...);  // ReferenceError: Java is not defined
```

**解决方案：使用 frida-compile 打包 Java bridge**

1. **初始化项目并安装依赖：**

```bash
cd frida-compile
npm init -y
npm i frida-java-bridge
npm i -D frida-compile
```

2. **在 `src/hook_chapter.js` 开头显式 import：**

```javascript
import Java from "frida-java-bridge";

Java.perform(() => {
  console.log("[READY] Java bridge loaded");
  // 你原来的 hook 代码放这里
});
```

3. **编译成可直接加载的脚本：**

```bash
npx frida-compile -S src/hook_chapter.js -o ../hook/hook_chapter.js
```

4. **Python 里加载编译后的脚本：**

```python
hook_script_path = Path("output/hook_chapter.js")
source = hook_script_path.read_text(encoding="utf-8")
script = session.create_script(source, runtime="v8")
```

**版本对齐提醒：**

确保以下版本主版本号一致（都在 17.x）：

```bash
frida --version                    # CLI 版本
python -c "import frida; print(frida.__version__)"  # Python 版本
adb shell frida-server --version   # Server 版本
```

版本不一致可能导致更诡异的问题。

---

### 3. 数据解析与调度层（Python）

**职责：**

- 启动并管理 Frida 会话
- 接收 Frida 发送的 JSON 数据
- 解析响应结构
- 提取视频播放相关字段（如 m3u8 地址）
- 做去重、过滤、调度

**说明：**

- 所有业务判断集中在此层
- 决定下载哪些视频
- 决定清晰度、CDN 优先级

**主要文件：**

- `app/hook_downloader.py` - Frida hook 脚本加载和消息处理
- `app/goodshort/parse_chapter_list.py` - 章节列表解析

---

### 4. 视频下载层（m3u8 下载器）

**职责：**

- 接收 m3u8 地址
- 下载 ts 分片
- 合并并生成视频文件

**说明：**

- 独立进程或模块
- 不感知 App / Frida / Appium
- 可自由替换实现

**实现：**

使用 `ffmpeg` 进行 m3u8 转 mp4（copy 模式，不重新编码）

---

## 数据流说明

### UI 行为流

```
Appium → App
```

### 网络数据流

```
App → Frida → Python
```

### 下载任务流

```
Python → m3u8 下载器
```

---

## 关键设计原则

- **分层解耦**：每一层只做一件事
- **不侵入业务**：不修改 App 原始逻辑
- **网络层监听**：稳定、通用、可扩展
- **自动化闭环**：无需人工干预

---

## 适用场景

- 自有 App 自动化测试
- 播放链路回归验证
- CDN / 清晰度策略验证
- 自动化内容采集实验

---

## 注意事项

- 仅用于合法、自有产品测试
- 请遵守当地法律法规
- 不用于第三方 App 或未授权场景
