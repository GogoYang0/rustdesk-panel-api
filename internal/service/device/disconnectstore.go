// Package device 实现 M2 设备域服务（设计 §3.1 / §4.1 / §4.2）：
// 设备端协议（heartbeat/sysinfo）、/peers 三源可见性查询、/devices
// 管理域（全部动作经 rbac.AuthorizationService 资源级复核）与内存断连队列。
//
// 本文件：DisconnectStore——断连下发内存队列（map+mutex，设计 §1.2
// "内存 DisconnectStore 原样保留"；单二进制部署形态，多副本差异 §10-5）。
//
// 协议语义（共享知识 / §4.1）：
//   - AddPending：管理动作（POST /api/devices/{uuid}/disconnect）入队；
//   - Pending：heartbeat 响应的 disconnect 键来源（客户端据此断开连接）；
//   - RemoveDisconnected：客户端不再上报的连接 = 已断开确认，出队。
package device

import (
	"sort"
	"sync"
)

// DisconnectStore 设备断连队列：uuid → connId 集合（集合语义防重复入队）。
type DisconnectStore struct {
	mu    sync.Mutex
	store map[string]map[int64]struct{}
}

// NewDisconnectStore 构建空队列。
func NewDisconnectStore() *DisconnectStore {
	return &DisconnectStore{store: make(map[string]map[int64]struct{})}
}

// AddPending 入队待断连连接（幂等：重复入队同一 connId 仅计一次）。
func (s *DisconnectStore) AddPending(uuid string, connIDs []int64) {
	if len(connIDs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	set, ok := s.store[uuid]
	if !ok {
		set = make(map[int64]struct{}, len(connIDs))
		s.store[uuid] = set
	}
	for _, id := range connIDs {
		set[id] = struct{}{}
	}
}

// Pending 返回该设备当前待断连 connId（升序，响应可快照断言）；
// 无 pending 返回空切片（nil 安全）。
func (s *DisconnectStore) Pending(uuid string) []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	set, ok := s.store[uuid]
	if !ok || len(set) == 0 {
		return []int64{}
	}
	out := make([]int64, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// RemoveDisconnected 批量出队（客户端不再上报 = 已断开确认）。
// 未入队的 connId 静默忽略。
func (s *DisconnectStore) RemoveDisconnected(uuid string, connIDs []int64) {
	if len(connIDs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	set, ok := s.store[uuid]
	if !ok {
		return
	}
	for _, id := range connIDs {
		delete(set, id)
	}
	if len(set) == 0 {
		delete(s.store, uuid)
	}
}
