// Package server 本文件：RBAC 授权端口适配层——把 repository 具体仓储
// 适配为 rbac.Stores 端口（T02 装配；rbac 包不依赖 repository，
// 避免横切件反向依赖业务仓储）。适配职责仅两类：错误哨兵映射
// （ErrNotFound → rbac.ErrUserNotFound / rbac.ErrDeviceNotFound）
// 与实体 → Ref 最小视图投影。
package server

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// rbacUserStore rbac.UserReader 适配（公共列查询足够：status/isAdmin）。
type rbacUserStore struct {
	repo *repository.UserRepo
}

// FindAuthUser 按 guid 查用户；未找到返回 rbac.ErrUserNotFound。
func (s rbacUserStore) FindAuthUser(ctx context.Context, guid string) (*rbac.UserRef, error) {
	u, err := s.repo.FindByGuid(ctx, guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, rbac.ErrUserNotFound
		}
		return nil, err
	}
	return &rbac.UserRef{Guid: u.Guid, Status: u.Status, IsAdmin: u.IsAdmin}, nil
}

// FindAuthUsers 批量查用户；未找到的 guid 不出现在结果中。
func (s rbacUserStore) FindAuthUsers(ctx context.Context, guids []string) (map[string]*rbac.UserRef, error) {
	out := make(map[string]*rbac.UserRef, len(guids))
	if len(guids) == 0 {
		return out, nil
	}
	us, err := s.repo.FindByGuids(ctx, guids)
	if err != nil {
		return nil, err
	}
	for i := range us {
		u := &us[i]
		out[u.Guid] = &rbac.UserRef{Guid: u.Guid, Status: u.Status, IsAdmin: u.IsAdmin}
	}
	return out, nil
}

// rbacRoleStore rbac.RoleReader 适配。
type rbacRoleStore struct {
	repo *repository.RoleRepo
}

// FindRolesByGuids 批量查角色；未找到的 guid 不出现在结果中。
func (s rbacRoleStore) FindRolesByGuids(ctx context.Context, guids []string) (map[string]*rbac.RoleRef, error) {
	out := make(map[string]*rbac.RoleRef, len(guids))
	if len(guids) == 0 {
		return out, nil
	}
	rs, err := s.repo.FindByGuids(ctx, guids)
	if err != nil {
		return nil, err
	}
	for i := range rs {
		r := &rs[i]
		out[r.Guid] = &rbac.RoleRef{Guid: r.Guid, ProtectedAccount: r.ProtectedAccount}
	}
	return out, nil
}

// rbacRolePermStore rbac.RolePermissionReader 适配（直转发）。
type rbacRolePermStore struct {
	repo *repository.RolePermissionRepo
}

// CodesByRoles roleGuid → 权限码列表。
func (s rbacRolePermStore) CodesByRoles(ctx context.Context, roleGuids []string) (map[string][]string, error) {
	return s.repo.CodesByRoles(ctx, roleGuids)
}

// rbacAssignmentStore rbac.AssignmentReader 适配。
type rbacAssignmentStore struct {
	repo *repository.AssignmentRepo
}

// ListAssignmentsByUser 用户全部指派。
func (s rbacAssignmentStore) ListAssignmentsByUser(ctx context.Context, userGuid string) ([]rbac.AssignmentRef, error) {
	rows, err := s.repo.ListByUser(ctx, userGuid)
	if err != nil {
		return nil, err
	}
	refs := make([]rbac.AssignmentRef, 0, len(rows))
	for _, a := range rows {
		refs = append(refs, rbac.AssignmentRef{Guid: a.Guid, RoleGuid: a.RoleGuid, ScopeType: a.ScopeType})
	}
	return refs, nil
}

// ListAssignmentsByUsers 批量用户指派（保护账号判定）。
func (s rbacAssignmentStore) ListAssignmentsByUsers(ctx context.Context, userGuids []string) (map[string][]rbac.AssignmentRef, error) {
	rows, err := s.repo.ListByUsers(ctx, userGuids)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]rbac.AssignmentRef, len(rows))
	for ug, list := range rows {
		refs := make([]rbac.AssignmentRef, 0, len(list))
		for _, a := range list {
			refs = append(refs, rbac.AssignmentRef{Guid: a.Guid, RoleGuid: a.RoleGuid, ScopeType: a.ScopeType})
		}
		out[ug] = refs
	}
	return out, nil
}

// rbacAssignmentGroupStore rbac.AssignmentGroupReader 适配（直转发）。
type rbacAssignmentGroupStore struct {
	repo *repository.AssignmentGroupRepo
}

// GroupsByAssignments assignmentGuid → 设备组 guid 列表。
func (s rbacAssignmentGroupStore) GroupsByAssignments(ctx context.Context, assignmentGuids []string) (map[string][]string, error) {
	return s.repo.GroupsByAssignments(ctx, assignmentGuids)
}

// rbacPeerStore rbac.PeerReader 适配。
type rbacPeerStore struct {
	repo *repository.PeerRepo
}

// FindAuthDevice 按 uuid 查设备；未找到返回 rbac.ErrDeviceNotFound。
func (s rbacPeerStore) FindAuthDevice(ctx context.Context, uuid string) (*rbac.DeviceRef, error) {
	p, err := s.repo.FindByUUID(ctx, uuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, rbac.ErrDeviceNotFound
		}
		return nil, err
	}
	return &rbac.DeviceRef{UUID: p.UUID, DeviceGroupGuid: p.DeviceGroupGuid}, nil
}

// FindAuthDevices 批量查设备；未找到的 uuid 不出现在结果中。
func (s rbacPeerStore) FindAuthDevices(ctx context.Context, uuids []string) (map[string]*rbac.DeviceRef, error) {
	out := make(map[string]*rbac.DeviceRef, len(uuids))
	if len(uuids) == 0 {
		return out, nil
	}
	ps, err := s.repo.FindByUUIDs(ctx, uuids)
	if err != nil {
		return nil, err
	}
	for i := range ps {
		p := &ps[i]
		out[p.UUID] = &rbac.DeviceRef{UUID: p.UUID, DeviceGroupGuid: p.DeviceGroupGuid}
	}
	return out, nil
}

// rbacDeviceGroupStore rbac.DeviceGroupReader 适配。
type rbacDeviceGroupStore struct {
	repo *repository.DeviceGroupRepo
}

// FindDeviceGroupsByGuids 批量查设备组；未找到的 guid 不出现在结果中。
func (s rbacDeviceGroupStore) FindDeviceGroupsByGuids(ctx context.Context, guids []string) (map[string]*rbac.DeviceGroupRef, error) {
	out := make(map[string]*rbac.DeviceGroupRef, len(guids))
	if len(guids) == 0 {
		return out, nil
	}
	gs, err := s.repo.FindByGuids(ctx, guids)
	if err != nil {
		return nil, err
	}
	for i := range gs {
		g := &gs[i]
		out[g.Guid] = &rbac.DeviceGroupRef{Guid: g.Guid, Name: g.Name}
	}
	return out, nil
}

// NewRBACStores 构建授权端口集合（装配期一次性调用）。
func NewRBACStores(db *gorm.DB) rbac.Stores {
	return rbac.Stores{
		Users:            rbacUserStore{repo: repository.NewUserRepo(db)},
		Roles:            rbacRoleStore{repo: repository.NewRoleRepo(db)},
		RolePerms:        rbacRolePermStore{repo: repository.NewRolePermissionRepo(db)},
		Assignments:      rbacAssignmentStore{repo: repository.NewAssignmentRepo(db)},
		AssignmentGroups: rbacAssignmentGroupStore{repo: repository.NewAssignmentGroupRepo(db)},
		Peers:            rbacPeerStore{repo: repository.NewPeerRepo(db)},
		DeviceGroups:     rbacDeviceGroupStore{repo: repository.NewDeviceGroupRepo(db)},
	}
}
