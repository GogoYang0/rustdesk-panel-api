package migration

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/golang-migrate/migrate/v4/database"
)

// sqliteDriver 适配 golang-migrate 的 database.Driver 到底层的
// glebarez（纯 Go）*sql.DB。
//
// 为什么不用官方 github.com/golang-migrate/migrate/v4/database/sqlite：
// 它 import modernc.org/sqlite 并在 init 中注册 "sqlite" driver，
// 与 glebarez/go-sqlite（modernc fork）的 init 重复注册同名驱动导致
// panic（sql: Register called twice for driver sqlite）。
// 本适配逻辑与官方实现一致，仅绑定外部注入的 *sql.DB。
type sqliteDriver struct {
	db       *sql.DB
	isLocked atomic.Bool

	migrationsTable string
}

// sqliteDriverErrors 适配层错误。
var (
	errSqliteNilConfig = errors.New("migration: sqlite driver: no config")
	errSqliteLocked    = database.ErrLocked
)

// newSqliteDriver 基于已打开的连接构建驱动并确保版本表存在。
func newSqliteDriver(instance *sql.DB, migrationsTable string) (database.Driver, error) {
	if instance == nil {
		return nil, errSqliteNilConfig
	}
	if err := instance.Ping(); err != nil {
		return nil, fmt.Errorf("migration: sqlite ping: %w", err)
	}
	if migrationsTable == "" {
		migrationsTable = "schema_migrations"
	}
	m := &sqliteDriver{db: instance, migrationsTable: migrationsTable}
	if err := m.ensureVersionTable(); err != nil {
		return nil, err
	}
	return m, nil
}

// ensureVersionTable 确保版本表存在。
func (m *sqliteDriver) ensureVersionTable() (err error) {
	if err = m.Lock(); err != nil {
		return err
	}
	defer func() {
		if e := m.Unlock(); e != nil {
			err = errors.Join(err, e)
		}
	}()
	query := fmt.Sprintf(`
	CREATE TABLE IF NOT EXISTS %s (version uint64,dirty bool);
	CREATE UNIQUE INDEX IF NOT EXISTS version_unique ON %s (version);
	`, m.migrationsTable, m.migrationsTable)
	if _, err := m.db.Exec(query); err != nil {
		return &database.Error{OrigErr: err, Query: []byte(query)}
	}
	return nil
}

// Open 未使用（连接由外部注入）。
func (m *sqliteDriver) Open(string) (database.Driver, error) {
	return nil, errors.New("migration: sqlite driver: Open is not supported; use newSqliteDriver")
}

// Close 关闭底层连接。
func (m *sqliteDriver) Close() error { return m.db.Close() }

// Lock 获取迁移锁（单进程内原子标志；SQLite 本身为文件锁语义）。
func (m *sqliteDriver) Lock() error {
	if m.isLocked.Swap(true) {
		return errSqliteLocked
	}
	return nil
}

// Unlock 释放迁移锁。
func (m *sqliteDriver) Unlock() error { m.isLocked.Store(false); return nil }

// Run 在事务内执行一段迁移 SQL。
func (m *sqliteDriver) Run(migration io.Reader) error {
	mig, err := io.ReadAll(migration)
	if err != nil {
		return &database.Error{OrigErr: err}
	}
	tx, err := m.db.Begin()
	if err != nil {
		return &database.Error{OrigErr: err, Query: mig}
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if _, err := tx.Exec(string(mig)); err != nil {
		_ = tx.Rollback()
		return &database.Error{OrigErr: err, Query: mig}
	}
	if err := tx.Commit(); err != nil {
		return &database.Error{OrigErr: err, Query: mig}
	}
	return nil
}

// SetVersion 保存版本与 dirty 状态。
func (m *sqliteDriver) SetVersion(version int, dirty bool) error {
	tx, err := m.db.Begin()
	if err != nil {
		return &database.Error{OrigErr: err}
	}
	query := fmt.Sprintf(`DELETE FROM %s`, m.migrationsTable)
	if _, err := tx.Exec(query); err != nil {
		_ = tx.Rollback()
		return &database.Error{OrigErr: err, Query: []byte(query)}
	}
	if version >= 0 || dirty {
		query = fmt.Sprintf(`INSERT INTO %s (version, dirty) VALUES (?, ?)`, m.migrationsTable)
		if _, err := tx.Exec(query, version, dirty); err != nil {
			_ = tx.Rollback()
			return &database.Error{OrigErr: err, Query: []byte(query)}
		}
	}
	if err := tx.Commit(); err != nil {
		return &database.Error{OrigErr: err}
	}
	return nil
}

// Version 返回当前版本；无迁移返回 -1。
func (m *sqliteDriver) Version() (version int, dirty bool, err error) {
	query := fmt.Sprintf(`SELECT version, dirty FROM %s LIMIT 1`, m.migrationsTable)
	err = m.db.QueryRow(query).Scan(&version, &dirty)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return -1, false, nil
	case err != nil:
		return -1, false, &database.Error{OrigErr: err, Query: []byte(query)}
	default:
		return version, dirty, nil
	}
}

// Drop 删除全部表（sqlite_master 枚举）。
func (m *sqliteDriver) Drop() (err error) {
	query := `SELECT name FROM sqlite_master WHERE type = 'table';`
	rows, err := m.db.Query(query)
	if err != nil {
		return &database.Error{OrigErr: err, Query: []byte(query)}
	}
	defer func() {
		if e := rows.Close(); e != nil {
			err = errors.Join(err, e)
		}
	}()
	names := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return &database.Error{OrigErr: err}
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return &database.Error{OrigErr: err}
	}
	if len(names) == 0 {
		return nil
	}
	for _, name := range names {
		q := fmt.Sprintf(`DROP TABLE IF EXISTS %s`, name)
		if _, err := m.db.Exec(q); err != nil {
			return &database.Error{OrigErr: err, Query: []byte(q)}
		}
	}
	return nil
}
