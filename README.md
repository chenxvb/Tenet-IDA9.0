# Tenet for Unicorn (Modified Build)

[中文](#中文说明) | [English](#english)

## 中文说明

### 这是什么

这是一个**针对 Unicorn / Unidbg 动态执行场景**定制的 Tenet 修改版本。目标是让 Unicorn 产生的 trace 能在 IDA 里用 Tenet 做时间旅行调试，并且在 ARM64 + ASLR + dump 场景下更稳定可用。

### Fork 关系（含 IDA 9.0 说明）

- 上游项目：`gaasedelen/tenet`
- IDA 9.0 分支基础：`jiqiu2022/Tenet-IDA9.0`
- 当前仓库：在上述 9.0 fork 基础上继续做 Unicorn 场景增强（trace 格式、ASLR、dump overlay、导航交互等）

### 我们添加/改动了什么

1. AArch64 支持强化
- 增强 AArch64 trace 导入和架构选择。
- 根据 IDA 当前处理器自动选择 `ArchAArch64 / ArchAMD64 / ArchX86`。

2. ASLR 运行时基址联动
- 支持从 trace 注释解析运行时基址：`# SO: <name> @ 0x...`。
- 将运行时基址保存到 `.tt` 头，并在后续加载时恢复。
- 加载时自动计算 slide：`runtime_base - ida_imagebase`，用于地址映射。

3. Dump Overlay 时间线（Unicorn 场景核心）
- 支持在 trace 中标记 dump 切换点：`# DUMP_DIR: <path>`。
- 构建 `idx -> dump_dir` 时间线，随执行位置自动切换 overlay。
- Memory/Stack 视图支持按 `.bin` dump 叠加基线内存（只读显示，不写 IDB）。
- Trace 时间线上增加 dump-load 标记线，便于定位快照切换。

4. 导航动作和快捷键增强
- 增强动作：`Step Into`、`Step Over`、`Step Out`、`Continue`、`Previous Instruction`。
- 默认快捷键：
- `Ctrl+Shift+S`：Step Into
- `Ctrl+Shift+N`：Step Over
- `Ctrl+Shift+F`：Step Out
- `Ctrl+Shift+C`：Continue
- `Ctrl+Shift+B`：Previous Instruction
- `Continue` 会读取 IDA 当前启用断点并映射到 trace 空间后继续。

5. IDA/Qt 兼容性与交互修正
- 适配 IDA 9.x API 路径。
- 兼容 PySide6 / Qt6（IDA 9.2+）。
- 修正部分 action 注册、交互和容错逻辑。

6. Trace 解析容错改进
- 支持 `# SO` / `# DUMP_DIR` 元数据行。
- 对空 token、异常字段、非标准行做更稳健处理。

### 根据本仓库修改后的使用方式

1. 安装插件
- 在 IDA Python 控制台获取插件目录：

```python
import idaapi, os
print(os.path.join(idaapi.get_user_idadir(), "plugins"))
```

- 复制 `tenet/` 与 `tenet_plugin.py` 到 `plugins` 目录。
- 重启 IDA。

2. 准备 Unicorn/Unidbg trace
- 可使用仓库中的 `tracer/unidbg/Tracer.java` 生成 Tenet 可读 trace。
- 建议在 trace 头部包含：
- `# SO: xxx.so @ 0x...`
- `# DUMP_DIR: /path/to/dump_xxx`（可多次出现，表示时间线切换）

3. 加载与分析
- 在 IDA 中打开目标二进制。
- `File -> Load file -> Tenet trace file...` 选择 trace。
- 使用快捷键进行时间旅行调试。
- 若 trace 包含 `# DUMP_DIR`，Memory/Stack 视图会自动切换 overlay。

### 旧版中文 README 摘选（保留）

- Tenet 是一个二进制执行轨迹时间旅行调试工具。
- 核心能力：前后步进、寄存器观察、内存观察、栈分析、断点导航。
- 支持架构：ARM64 / x86 / x86-64。
- 常用动作：Step Into / Step Over / Step Out / Continue / Previous Instruction。
- 适合用于混淆代码路径回放、算法逻辑还原、关键内存变化定位。

### 效果图

#### 对抗虚假控制流、未知混淆

![image-20250413124003343](https://qiude1tuchuang.oss-cn-beijing.aliyuncs.com/blog/202504131554975.png)

#### 算法分析中的内存变化观察

![image-20250413124106913](https://qiude1tuchuang.oss-cn-beijing.aliyuncs.com/blog/202504131554993.png)

#### 时间回溯调试

![CleanShot_2025_04_13_at_12_42_13](https://qiude1tuchuang.oss-cn-beijing.aliyuncs.com/blog/202504131554004.png)

#### 寄存器跟踪

![CleanShot_2025_04_13_at_15_50_56](https://qiude1tuchuang.oss-cn-beijing.aliyuncs.com/blog/202504131554015.png)

#### 时间旅行

![CleanShot_2025_04_13_at_15_52_14](https://qiude1tuchuang.oss-cn-beijing.aliyuncs.com/blog/202504131554026.png)

### 未来方向

1. 初始化内存扫描：trace 开始前保存全局内存状态。
2. 扩展内存扫描：每次内存读写时按窗口持续保存上下文。
3. 后端原生化：考虑 C++ 后端以提高稳定性与性能。

### References

- Tenet (official): https://github.com/gaasedelen/tenet
- Tenet tracers: https://github.com/gaasedelen/tenet/tree/master/tracers
- Tenet blog: https://blog.ret2.io/2021/04/20/tenet-trace-explorer/
- Tenet-IDA9.0 fork: https://github.com/jiqiu2022/Tenet-IDA9.0
- Unidbg tracer in this repo: `tracer/unidbg/README.md`

---

## English

### What This Is

This is a **Unicorn/Unidbg-oriented modified Tenet build**. It is designed to make Unicorn-generated traces practical for IDA time-travel debugging, especially in ARM64 + ASLR + dump-overlay workflows.

### Fork Lineage (including IDA 9.0)

- Upstream: `gaasedelen/tenet`
- IDA 9.0 base fork: `jiqiu2022/Tenet-IDA9.0`
- This repo: additional Unicorn-focused enhancements on top of that fork

### What We Added/Changed

1. Stronger AArch64 support
- Improved AArch64 trace loading and architecture selection.
- Auto-selects `ArchAArch64 / ArchAMD64 / ArchX86` from IDA processor context.

2. ASLR runtime-base aware mapping
- Parses runtime base from trace metadata: `# SO: <name> @ 0x...`.
- Persists runtime base into `.tt` header and restores it on later loads.
- Computes slide (`runtime_base - ida_imagebase`) for remapping.

3. Dump-overlay timeline (core for Unicorn workflows)
- Supports `# DUMP_DIR: <path>` markers in traces.
- Builds an `idx -> dump_dir` timeline and switches overlays automatically.
- Applies dump `.bin` snapshots as baseline bytes in Memory/Stack views (read-only to IDB).
- Adds dump-load markers on the trace timeline.

4. Navigation and hotkey enhancements
- Enhanced actions: `Step Into`, `Step Over`, `Step Out`, `Continue`, `Previous Instruction`.
- Default shortcuts:
- `Ctrl+Shift+S`: Step Into
- `Ctrl+Shift+N`: Step Over
- `Ctrl+Shift+F`: Step Out
- `Ctrl+Shift+C`: Continue
- `Ctrl+Shift+B`: Previous Instruction
- `Continue` maps active IDA breakpoints into trace space before seeking.

5. IDA/Qt compatibility and interaction fixes
- Updated for IDA 9.x API paths.
- Compatible with PySide6 / Qt6 (IDA 9.2+).
- Fixed/improved action registration and interaction robustness.

6. Trace parsing robustness
- Supports metadata lines: `# SO` and `# DUMP_DIR`.
- Better tolerance for malformed items and non-standard lines.

### Usage for This Modified Build

1. Install plugin
- In IDA Python console:

```python
import idaapi, os
print(os.path.join(idaapi.get_user_idadir(), "plugins"))
```

- Copy `tenet/` and `tenet_plugin.py` to your `plugins` directory.
- Restart IDA.

2. Prepare Unicorn/Unidbg trace
- You can use `tracer/unidbg/Tracer.java` from this repo.
- Recommended trace metadata:
- `# SO: xxx.so @ 0x...`
- `# DUMP_DIR: /path/to/dump_xxx` (can appear multiple times as timeline markers)

3. Load and analyze
- Open target binary in IDA.
- Use `File -> Load file -> Tenet trace file...`.
- Navigate with hotkeys.
- If `# DUMP_DIR` exists, Memory/Stack overlays switch automatically.

### Excerpt from Previous Chinese README

- Tenet is a time-travel debugger for binary execution traces.
- Core capabilities include forward/backward stepping, register/memory/stack views, and breakpoint-driven navigation.
- Supported architectures: ARM64 / x86 / x86-64.
- Common actions: Step Into / Step Over / Step Out / Continue / Previous Instruction.

### References

- Tenet (official): https://github.com/gaasedelen/tenet
- Tenet tracers: https://github.com/gaasedelen/tenet/tree/master/tracers
- Tenet blog: https://blog.ret2.io/2021/04/20/tenet-trace-explorer/
- Tenet-IDA9.0 fork: https://github.com/jiqiu2022/Tenet-IDA9.0
- Unidbg tracer in this repo: `tracer/unidbg/README.md`
