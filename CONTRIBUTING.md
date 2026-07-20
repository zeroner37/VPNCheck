# Contributing

感谢你参与 VPNCheck。

欢迎修改代码、完善文档、提交 Issue 或参与功能讨论。本项目将长期维护，所有有助于提升可靠性和使用体验的贡献都会被认真评估。

项目聚焦 ChatGPT、Claude、Gemini、AI API 与其他 AI 应用的链路质量诊断。提交新功能时，请说明它解决的 AI 服务访问痛点；通用网页测速、带宽测试或代理客户端功能不属于当前核心范围。

1. Fork 仓库并从 `main` 创建功能分支。
2. 不要提交 `%APPDATA%\VPNCheck` 中的配置、日志、API Key 或出口 IP 信息。
3. 运行 `python -m ruff check .`、`python -m ruff format --check .` 和测试。
4. 提交内容应聚焦单一问题，并在 Pull Request 中说明行为变化和验证结果。

运行测试：

```powershell
python -m unittest discover -s tests -v
```

构建 Windows 单文件程序：

```powershell
.\build.ps1
```
