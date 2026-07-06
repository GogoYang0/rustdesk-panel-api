# 项目 Git 工作流

此说明由 workflow.json 生成；JSON 是规则事实源。

工作流：classic-gitflow；修订：1；权威远端：origin

| 角色 | 名称/模式 | 长期必需 | 允许提交 | 来源角色 | 合入角色 |
|---|---|---|---|---|---|
| main | main | True | False |  |  |
| develop | develop | True | False | main |  |
| feature | feature/[a-z0-9][a-z0-9-]* | False | True | develop | develop |
| release | release/[0-9][a-z0-9.-]* | False | True | develop | main, develop |
| hotfix | hotfix/[a-z0-9][a-z0-9.-]* | False | True | main | main, develop |
