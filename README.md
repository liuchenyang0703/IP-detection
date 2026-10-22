# NetScope 网段 IP 检测

NetScope 是一个无需数据库的局域网 IP 检测工具。后端使用 Python 3 + Flask 调用 `nmap -sn`，前端使用原生 HTML、CSS 和 JavaScript。

## 功能

- 支持手动检测单个或多个 IPv4 CIDR 网段
- 多个网段使用中文逗号 `，` 或英文逗号 `,` 分隔
- 输入网段后按 Enter 或点击“检测”开始扫描
- 多网段并行扫描，并按网段分别展示结果
- 展示在线设备的 IP、主机名、MAC 地址、设备厂商和状态
- 自动展示服务器的本机 IP、当前网段、MAC 地址和网卡名称
- 页面加载后自动将当前网段填入空白的检测框，不覆盖手动输入的内容
- 自动补全 Nmap 扫描本机时缺失的本机 MAC 信息
- 支持对扫描结果进行 IP 模糊搜索
- 搜索后只显示匹配的数据，清空搜索框恢复全部结果
- 扫描过程中显示动态加载条
- 支持导出当前展示结果：Excel、Word、PDF、Markdown 和 TXT
- 导出文件顶部会注明本次检测的网段；存在搜索条件时也会注明筛选内容
- Windows 扫描时隐藏 Nmap 子进程窗口，不弹出命令行窗口
- 支持 Windows 和 Linux

## 环境要求

- Python 3.8 或更高版本
- Nmap
- Windows 使用 Nmap 时需要安装 Npcap

## Windows 安装与启动

1. 从 [Nmap 官方网站](https://nmap.org/download.html)下载安装程序。
2. 安装时保留 Npcap，并建议选中将 Nmap 添加到系统 `PATH`。
3. 在 PowerShell 中验证：

```powershell
nmap --version
```

4. 根据本机环境选择一种启动方式。

### 不使用 Conda

确认 Python 已加入 `PATH`，然后执行：

```powershell
cd "D:\vscode\项目\IP-detection"
python -m pip install -r requirements.txt
python ip.py
```

### 使用 Conda

首次使用时创建 Python 3.8 环境；已有合适环境时可以直接激活：

```powershell
cd "D:\vscode\项目\IP-detection"
conda create -n netscope python=3.8 -y
conda activate netscope
python -m pip install -r requirements.txt
python ip.py
```

浏览器打开：

```text
http://127.0.0.1:5000
```

程序会自动查找 `PATH` 中的 Nmap，也会检查以下 Windows 默认安装位置：

```text
C:\Program Files (x86)\Nmap\nmap.exe
C:\Program Files\Nmap\nmap.exe
```

## Linux 安装与启动

Ubuntu / Debian 安装 Python、pip 和 Nmap：

```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap
```

安装依赖并启动：

```bash
cd /path/to/IP-detection
python3 -m pip install -r requirements.txt
python3 ip.py
```

浏览器打开 `http://服务器IP:5000`。如果需要从其他机器访问，请确认 Linux 防火墙允许访问 5000 端口。

服务默认监听 `0.0.0.0`，因此同一网络中的其他设备可以使用服务器实际 IP 访问：

```text
http://服务器IP:5000
```

例如服务器 IP 为 `172.16.11.155`：

```text
http://172.16.11.155:5000
```

Ubuntu 使用 UFW 时可以放行端口：

```bash
sudo ufw allow 5000/tcp
```

### 使用 nohup 后台启动

```bash
cd /path/to/ip-check
nohup python3 -u ip.py > nohup.out 2>&1 &
echo $! > app.pid
```

`-u` 表示不缓存标准输出，访问日志会立即写入 `nohup.out`。实时查看日志：

```bash
tail -f nohup.out
```

日志示例：

```text
2026-10-21 14:30:10 INFO service_start host=0.0.0.0 port=5000 nmap=/usr/bin/nmap
2026-10-21 14:30:15 INFO access ip=172.16.11.20 method=GET path=/ status=200 duration_ms=4
2026-10-21 14:30:28 INFO access ip=172.16.11.20 method=POST path=/api/scan status=200 duration_ms=8231
```

停止后台服务：

```bash
kill "$(cat app.pid)"
```

## 使用方法

单个网段：

```text
172.16.11.0/24
```

多个网段：

```text
172.16.11.0/24，172.16.10.0/24
```

输入完成后按 Enter 或点击“检测”。扫描完成后可以使用 IP 模糊搜索，例如输入：

```text
172.16.11
```

页面将只保留 IP 中包含该内容的在线设备。导出时会导出页面当前展示的结果；如果需要导出全部结果，请先清空搜索框。

## 导出格式

| 格式 | 扩展名 | 说明 |
| --- | --- | --- |
| Excel | `.xlsx` | 按网段分组的电子表格 |
| Word | `.docx` | 包含分组表格的 Word 文档 |
| PDF | `.pdf` | 横向页面，支持中文 |
| Markdown | `.md` | Markdown 表格，UTF-8 编码 |
| 文本 | `.txt` | 制表符分隔，UTF-8 编码 |

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `HOST` | `0.0.0.0` | Flask 监听地址 |
| `PORT` | `5000` | Flask 监听端口 |
| `SCAN_TIMEOUT` | `120` | 每个网段的扫描超时秒数 |
| `MAX_NETWORKS` | `10` | 单次允许扫描的最大网段数量 |
| `MAX_ADDRESSES_PER_NETWORK` | `4096` | 单个网段允许包含的最大地址数量，即最宽 `/20` |
| `NMAP_PATH` | 自动查找 | Nmap 可执行文件的完整路径 |
| `LOG_LEVEL` | `INFO` | 服务日志级别 |
| `TRUST_PROXY` | `false` | 是否信任前方一层反向代理提供的客户端 IP |

Windows 手动指定 Nmap：

```powershell
$env:NMAP_PATH = 'C:\Program Files (x86)\Nmap\nmap.exe'
D:\miniconda3\python.exe ip.py
```

Linux 手动指定 Nmap：

```bash
NMAP_PATH=/usr/bin/nmap python3 ip.py
```

## 生产环境部署

Linux 生产环境建议使用 Gunicorn，并在前面配置 Nginx：

```bash
python3 -m pip install gunicorn
gunicorn -w 2 -b 127.0.0.1:5000 --timeout 180 ip:app
```

Nginx 再将请求反向代理到 `127.0.0.1:5000`。

如果服务位于一层可信 Nginx 反向代理后面，需要让 Nginx 传递客户端 IP：

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Host $host;
```

启动应用时启用代理信任：

```bash
TRUST_PROXY=true gunicorn -w 2 -b 127.0.0.1:5000 --timeout 180 ip:app
```

> 只有应用始终位于可信反向代理后面时才启用 `TRUST_PROXY`，不要在直接暴露 Flask 端口时启用。

## 测试

Windows（普通 Python 或已激活的 Conda 环境）：

```powershell
python -m unittest discover -s tests -v
```

Linux：

```bash
python3 -m unittest discover -s tests -v
```

测试使用 Python 标准库 `unittest`。涉及 Nmap 执行和本机网卡信息的场景使用 `unittest.mock` 模拟，因此运行测试不会真的扫描局域网，也不依赖当前网络中必须存在设备。

当前测试包含：

| 测试内容 | 测试方法 |
| --- | --- |
| Nmap 输出解析 | 使用固定的 Nmap 文本样本，检查 IP、主机名、MAC 和厂商解析结果 |
| 非法网段拦截 | 向扫描接口提交非法 CIDR，检查接口返回 HTTP 400 |
| 访问日志 | 模拟客户端 IP 请求健康接口，检查日志是否记录该 IP |
| 本机网络信息 | 模拟网卡信息，检查接口返回的 IP、网段和 MAC |
| MAC 地址格式化 | 检查横线格式转换以及全零 MAC 的过滤 |
| Windows 无弹窗扫描 | 模拟 Nmap 进程，检查调用参数是否包含隐藏窗口标志 |
| 导出功能 | 在内存中生成五种格式，检查响应状态和文件签名 |
| 多网段扫描顺序 | 模拟多个扫描结果，检查 CIDR 归一化和输入顺序是否保持 |

`tests/` 不是启动服务所必需的，部署时即使不运行测试也不影响应用；但建议在源码仓库中保留，用于修改后快速发现回归问题。

## 项目结构

```text
IP-detection/
├── ip.py                  # Flask 后端、Nmap 调用和导出功能
├── requirements.txt       # Python 依赖
├── templates/
│   └── index.html         # 页面结构
├── static/
│   ├── app.js             # 扫描、搜索和导出交互
│   └── style.css          # 页面样式
└── tests/
    └── test_app.py        # 自动测试
```

## 注意事项

- 只扫描你有权限管理或检测的网络。
- 扫描结果取决于服务器的网络可达范围、防火墙策略和运行权限。
- 某些设备会阻止 ICMP 或其他发现探测，因此“未发现在线”不一定表示地址绝对未使用。
- Nmap 扫描本机时通常不会返回本机 MAC，本项目会从操作系统网卡信息中补全。
- 用户输入会先通过 IPv4 CIDR 校验，再以参数数组调用 Nmap，不会拼接成 shell 命令。

## 许可证

本项目使用 [MIT License](LICENSE)。

版权所有 © 2026-present [Liucy](https://github.com/liuchenyang0703)。
