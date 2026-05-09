# 授权端口巡检工具

这个项目提供一个支持断点续跑的 GitHub Actions 工作流，用于在明确授权的前提下，对指定目标和端口范围做持续巡检。

## 功能说明

- 从仓库文件读取目标列表
- 按批次扫描端口，并在达到时间预算后自动停止
- 默认使用较保守的扫描节奏：单 worker、探测间隔、批次间暂停
- 自动保存进度，下一次运行可以继续
- 按识别出的服务类型分文件输出结果
- 生成滚动汇总文件，方便快速查看进度
- 将 `scan-results/` 和 `scan-state/` 上传为 GitHub Actions 制品
- 可选将结果和进度直接提交回当前分支

## 安全限制

这个工具只应用于你拥有或已获得明确授权的主机、域名和网段。

当前脚本默认拒绝以下目标：

- `*.ngrok.io`
- 常见本地回环地址

如果你需要更严格的限制，可以自行扩展脚本中的拒绝规则。

## 目录结构

- `.github/workflows/authorized-port-monitor.yml`
- `scripts/authorized_port_monitor.py`
- `targets.txt`
- `scan-results/`
- `scan-state/`

## 目标文件

在 `targets.txt` 中每行填写一个目标：

```text
example.internal.company
192.0.2.10
198.51.100.0/30
```

空行和以 `#` 开头的注释行会被忽略。

## 手动运行参数

- `duration_minutes`：本次最多运行多少分钟
- `port_start`：起始端口，包含该端口
- `port_end`：结束端口，包含该端口
- `batch_size`：每批处理多少个端口后保存一次进度
- `connect_timeout_ms`：单端口 TCP 连接超时时间，单位毫秒
- `inter_probe_delay_ms`：每次发起探测之间的间隔，单位毫秒
- `batch_pause_ms`：每批结束后的暂停时间，单位毫秒
- `max_workers`：并发 worker 数，脚本内有限制上限
- `commit_results`：是否把结果和进度直接提交回当前分支

## 输出文件

扫描结果会写入 `scan-results/`：

- `http.txt`
- `https.txt`
- `ssh.txt`
- `smtp.txt`
- `rdp.txt`
- `mysql.txt`
- `postgres.txt`
- `redis.txt`
- `unknown.txt`
- `all-open.jsonl`
- `summary.json`
- `summary.txt`

进度文件写入 `scan-state/progress.json`。

## 默认参数

工作流默认值如下：

- `max_workers=1`
- `inter_probe_delay_ms=100`
- `batch_pause_ms=500`

这套默认值更适合平稳的内部授权巡检，而不是高频探测。

## 断点续跑

如果 `scan-state/progress.json` 已存在，下一次运行会从上次保存的目标和端口继续。

如果你修改了端口范围，脚本会保留当前目标，并把下一个端口自动夹紧到新的范围内。
