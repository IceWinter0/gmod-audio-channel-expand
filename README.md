# GMod 音频通道扩容

适用于 Windows x64 Garry’s Mod 客户端，将音频总槽位扩展到 **512（64 动态 + 448 静态）**。提供中文原生启动器、Steam 游戏路径自动发现和实时诊断，无需执行 Lua 控制台命令。

## 使用方法

1. 在 [Release 页面](https://github.com/IceWinter0/gmod-audio-channel-expand/releases/tag/v0.11.0-rc4) 下载 `gmod-audio-channel-expand-v0.11.0-rc4-win64.zip`。
2. 完整解压到可写目录，先退出正在运行的 GMod。
3. 双击 `channel_expand_launcher.exe`。
4. 等待自动发现游戏；也可手动选择 `GarrysMod` 文件夹。有多个安装时选择正确的一项。
5. 点击“启动 GMod 并启用 512 槽位”，等待显示“512 槽位已激活”。

请下载完整运行包，不要只复制 EXE。无需填写 PID，无需 `lua_run_cl`，无需将 DLL 复制进游戏目录。

## 初始化和退出

界面不再包含确认复选框。点击启动时，原生初始化可能**停止当前客户端声音一次**，以建立空通道表，不会反复停止声音。

关闭启动器只结束监控，扩容保留到游戏进程退出。不支持热卸载；取消等待不会撤销已启用的部分。正在执行的原生请求不会被强行终止，其内存会保留至完成或游戏退出。

引擎版本、模块哈希、进程身份、线程同步和存储检查仍然保留。如果进入无法恢复的同步或补丁状态，保护路径可能终止当前 GMod 进程。请先保存重要游戏进度；部分完成或未知状态下须退出游戏再重试。

## 兼容范围

- Windows x64，GMod x64 客户端；面向 Windows 10/11，跨电脑验证尚不完整。
- 仅支持下列 `engine.dll` SHA-256：
  `7C21E827722FA7AC9BA4539DC652D3B79F58E240DA49D28E75A1A9A1A88C4173`
- 核心 DLL 内部版本：`0.11.0-rc1-native-loader`，SHA-256：
  `D16B94A2EC6CF203AD956D76CA96C9E9AFB0125FB65F2251467EF5FE173B2DA9`

游戏可安装在任意盘符。自动发现读取 Steam 注册表、`libraryfolders.vdf` 和 `appmanifest_4000.acf`，不遍历所有磁盘。找到游戏不代表引擎兼容，哈希不匹配会拒绝启用；游戏更新后可能需要新的适配版本。

启动器不修改磁盘上的引擎、Steam 启动选项或服务器设置，不自动提权。客户端模块的使用权限取决于服务器规则，无法保证所有服务器均接受。

## 诊断

使用“复制诊断”和“打开日志”。日志位于 `logs/`，便携设置位于启动器旁的 `channel_expand_loader.ini`。配置写入失败可仅用于当前会话；日志写入失败会阻止启用。

“扫描范围”不是正在播放的声音数量。单次状态采样不等于安装同步已得到证明；过期或不可用采样会标明。

高级命令行：`channel_expand_loader.exe --discover`；查询已加载模块可用 `--status --pid N`。CLI 保留 `--configure` 参数，不要通过 GUI 和 CLI 同时启动安装。换电脑时请重新解压完整包，避免沿用旧的绝对路径配置。

## 源码与编译

完整源码直接保存在本 Git 仓库中：`source/` 为模块代码，`tools/` 为原生启动器与诊断工具，`build/` 为编译脚本，`third_party/` 为随仓库提供的第三方依赖。克隆仓库后即可浏览、修改和编译。编译好的运行包请从 Release 页面下载。

使用 MSVC x64 和 C++17。若脚本默认路径不适用，将 `TASK_VCVARS` 设置为本机 `vcvars64.bat`，执行 `build/graphical-launcher-build.cmd`。GUI/CLI 编译不会重新编译核心 DLL；重编核心会改变哈希，需要匹配的包与哈希文件及新的游戏验证。

DLL 未数字签名；SHA-256 用于核验完整性，不证明发布者身份。

## 开源许可

本项目自有代码采用 [MIT 许可证](LICENSE)，允许使用、修改、商用和再分发，须保留版权和许可声明。

第三方代码继续适用各自许可证；Zydis 和 garrysmod_common 的完整声明保存在 `THIRD_PARTY_NOTICES.txt` 和源码目录中，不被项目 MIT 许可证替代。
