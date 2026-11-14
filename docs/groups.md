# 组与部门（Groups / Departments）

Signet 的组与部门是**同一棵树**：每个节点有 `kind`（`group` | `department`），可以有父节点和任意子节点。组成员关系决定 OIDC `groups` claim 的内容；部门本身也是节点，只是用于组织归类。

## 1. 数据模型

组的唯一实体表是 `scim_groups`（迁移 `043_group_tree.sql` 扩展）：

| 列 | 说明 |
|----|------|
| `id` | 组/部门标识；`users.groups` / `users.directory_groups` 存的就是它 |
| `display_name` | 展示名；live 行唯一（部分唯一索引），墓碑可与同名新行共存 |
| `parent_id` | 父节点；`ON DELETE RESTRICT`，由应用层改挂，不做级联删除 |
| `kind` | `group` \| `department` |
| `source` | `local`（Admin/导入）\| `scim`（IdP）\| `directory`（目录同步） |
| `source_id` | `source='directory'` 时记录创建它的目录来源；同步后的清理只针对本来源，避免误删其他来源尚未填充的组 |
| `external_id` | SCIM 上游标识（仅 SCIM 使用） |
| `deleted_at` / `members_at_delete` | 墓碑与删除时的成员快照 |

成员关系仍以数组形式存在用户行上：

- `users.groups UUID[]`：本地/SCIM/手工分配
- `users.directory_groups UUID[]`：目录同步独占，与本地组分开，避免同步覆盖手工分配

读取时统一经 `signet_group_names(UUID[])` 还原成名字，因此 OIDC claim、SCIM 响应、Dashboard 与 CSV 导出的对外形态不变；写入经 `signet_group_ids(TEXT[], src)`，未知名字按 `src` 自动建行。

## 2. 来源与可编辑性

| 操作 | `local` | `scim` | `directory` |
|------|:---:|:---:|:---:|
| 查看 / 移动节点 | ✅ | ✅ | ✅ |
| 修改名称 | ✅ | ❌ 409 | ❌ 409 |
| 修改 kind | ✅ | ✅ | ✅ |
| 增删成员 | ✅ | ❌（SCIM PATCH） | ❌（目录同步） |
| 删除 | ✅（admin） | ❌（SCIM DELETE） | ❌（同步清理） |

SCIM 的 `/scim/v2/Groups` 只看见 `source='scim'` 的组；目录组与本地组不会出现在 IdP 的列表里。

目录组在同步成功且该来源开启 `sync_groups` 时会被清理：`source='directory'`、没有任何成员、没有子节点的 live 节点置墓碑（上游已删除的组不会残留）。有子节点的目录节点会保留。

## 3. OIDC claim 语义

- `groups` scope 下，`id_token` 与 `userinfo` 输出组名列表；
- 列表来自 `users.groups ∪ users.directory_groups`，排序去重；
- **仅直接成员**：加入子组不会自动获得父部门/父组名。客户端若需要祖先，应按树结构自行展开；
- 删除组后成员立即失去该名字（墓碑不参与解析）。

## 4. 权限

| 操作 | 角色 |
|------|------|
| 查看树、创建/改名/移动、增删成员 | admin、manager（staff） |
| 删除组/部门 | **仅 admin** |

所有写操作写入审计：`group.create` / `group.update` / `group.delete` / `group.member_add` / `group.member_remove`。

## 5. HTTP API

挂在 `/api/v1/admin/groups`：

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| `GET` | `/admin/groups` | staff | 扁平节点列表：`id, display_name, parent_id, kind, source, member_count, created_at` |
| `POST` | `/admin/groups` | staff | `{name, kind?, parent_id?}`；重名 409 |
| `PUT` | `/admin/groups/{id}` | staff | `{name?, kind?, parent_id?, clear_parent?}`；移动用递归检查拒环；`parent_id` 省略=保持，`clear_parent=true`=移到根 |
| `DELETE` | `/admin/groups/{id}` | admin | 仅 `local`；子节点上移到被删节点的父级，成员释放，行置墓碑 |
| `GET` | `/admin/groups/{id}/members?q=&limit=&offset=` | staff | 直接成员分页（email/display_name 搜索） |
| `POST` | `/admin/groups/{id}/members` | staff | `{user_ids:[uuid]}` 加入；非 `local` 409 |
| `DELETE` | `/admin/groups/{id}/members/{user_id}` | staff | 移除；非 `local` 409 |

Dashboard 页面：**Directory**（`/directory`，staff 可见）：左侧组织树，右侧是当前节点的完整用户表（可直接移除成员、添加成员）；Users 页的自由文本 Groups 字段仍保留，按名字写入并在不存在时创建 `local` 组。

## 6. 与 SCIM / 目录同步的关系

- SCIM 创建组时写 `source='scim'`、`kind='group'`、`parent_id=NULL`；成员 PATCH 按组 id 操作；删除时子节点上移、成员释放、写墓碑。
- 目录同步把 `directory_groups` 写成 id（`signet_group_ids(names,'directory')`）；指纹仍按名字计算，重命名会触发一次无害的更新。
- 管理员可以把目录组移动到部门下（组织视图），但改不了它的名字/成员/存在性。
