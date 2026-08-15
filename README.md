# 智能反代系统 v1.0.3

基于 Cloudflare Workers 的边缘媒体库反代系统，专为加速访问家庭媒体服务器（Emby/Jellyfin/Plex）而设计。

## 功能特性

### 核心功能
- **智能路由反代** - 支持多种代理模式（关闭/标准/严格/智能）
- **节点健康检查** - 实时检测节点可用性和延迟
- **DNS 智能调度** - 自动选择最优节点，每6小时更新一次
- **海报缓存加速** - 可选开启图片缓存，提升加载速度

### 安全防护
- **IP 黑名单** - 拦截恶意访问
- **频率限制** - 防止接口滥用
- **请求过滤** - 仅记录真实播放请求，避免统计虚高

### 数据监控
- **数据大屏** - 实时流量统计、播放趋势、客户端分布
- **节点热度榜** - TOP 5 今日播放排行
- **访客日志** - 记录访问来源和播放行为
- **Telegram 播报** - 自动推送节点状态和统计简报

### 管理功能
- **可视化控制台** - 完整的 Web 管理界面
- **节点拖拽排序** - 支持自定义节点优先级
- **批量操作** - 全选、批量修改模式、批量删除
- **在线更新** - 一键从 GitHub 拉取最新代码

## 技术栈

- **Cloudflare Workers** - 边缘计算平台
- **Cloudflare D1** - 边缘 SQLite 数据库
- **Cloudflare GraphQL Analytics** - 流量统计分析
- **SortableJS** - 拖拽排序
- **Chart.js** - 数据可视化

## 部署说明

### 前置要求
1. Cloudflare 账号
2. Wrangler CLI 工具
3. 一个已绑定到 Cloudflare 的域名

### 环境变量配置

在 `wrangler.toml` 中配置以下变量：

```toml
name = "fandai-worker"
main = "worker.js"
compatibility_date = "2026-05-23"
compatibility_flags = ["nodejs_compat"]

[[d1_databases]]
binding = "DB"
database_id = "your-d1-database-id"

[[triggers]]
crons = ["0 */6 * * *"]  # 每6小时执行DNS智能调度

[vars]
ADMIN_TOKEN = "your-admin-password"
CF_ACCOUNT_ID = "your-cf-account-id"
CF_API_TOKEN = "your-cf-api-token"
CF_DOMAIN = "your-domain.com"
CF_WORKER_NAME = "fandai-worker"
CF_ZONE_ID = "your-cf-zone-id"
TG_BOT_TOKEN = "your-telegram-bot-token"
TG_CHAT_ID = "your-telegram-chat-id"
```

### 部署命令

```bash
wrangler deploy
```

## 版本历史

### v1.0.3
- UI/UX 优化：导航栏集成访客入口和 Worker 落地信息
- 修复数据大屏节点热度统计逻辑
- 代码质量优化

### v1.0.2
- 统一错误处理机制
- Toast 通知系统
- 加载动画优化

### v1.0.1
- 内存缓存机制
- CDN 缓存头优化
- 数据库索引优化

### v1.0.0
- 系统重构，更名为"智能反代系统"
- 新增 Telegram 机器人控制台
- 新增数据大屏
- 新增智能DNS自动调度
- 新增节点健康检查
- 新增 IP 黑名单和频率限制

## 项目结构

```
fandai/
├── worker.js          # 主程序（包含前端界面和后端逻辑）
├── wrangler.toml      # Cloudflare 部署配置
├── worker.js.backup   # 稳定版本备份
└── README.md          # 项目说明
```

## 使用说明

1. 访问部署后的 Worker 地址
2. 使用 ADMIN_TOKEN 登录管理后台
3. 添加媒体库节点（支持多目标地址）
4. 开启需要的功能（缓存、健康检查等）
5. 复制直达链接到播放器使用

## 注意事项

- 请妥善保管 ADMIN_TOKEN，不要泄露
- CF_API_TOKEN 需要 Zone:Read 和 Analytics:Read 权限
- D1 数据库需要提前创建并绑定
- 建议定期备份 worker.js.backup

## License

MIT License
