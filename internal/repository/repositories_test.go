package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/migration"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
)

// newRepoDB 建内存库并执行迁移（仓储测试跑在真实基线上）。
func newRepoDB(t *testing.T) *repoBundle {
	t.Helper()
	db := testutil.NewMemoryDB(t)
	m, err := migration.New(db, "sqlite")
	if err != nil {
		t.Fatalf("migration.New: %v", err)
	}
	if err := m.Up(); err != nil {
		t.Fatalf("migration.Up: %v", err)
	}
	return &repoBundle{
		users:  NewUserRepo(db),
		tokens: NewUserTokenRepo(db),
		sess:   NewLoginSessionRepo(db),
		pk:     NewPasskeyRepo(db),
		groups: NewUserGroupRepo(db),
		oidc:   NewOidcRepo(db),
	}
}

type repoBundle struct {
	users  *UserRepo
	tokens *UserTokenRepo
	sess   *LoginSessionRepo
	pk     *PasskeyRepo
	groups *UserGroupRepo
	oidc   *OidcRepo
}

// --- 测试数据助手 ---

func seedUser(t *testing.T, r *repoBundle, guid, username, email, password, tfaSecret string) *entity.User {
	t.Helper()
	u := &entity.User{
		Guid: guid, Username: username, Email: email, Password: password,
		Status: 1, TfaSecret: tfaSecret,
	}
	if err := r.users.WithSecrets(context.Background()).Create(u).Error; err != nil {
		t.Fatalf("seedUser %s: %v", username, err)
	}
	return u
}

// --- UserRepo ---

func TestUserRepoFindByUsernameOrEmail(t *testing.T) {
	r := newRepoDB(t)
	ctx := context.Background()
	seedUser(t, r, "u-guid-1", "alice", "alice@x.io", "hashed-pw", "TFASECRET")

	u, err := r.users.FindByUsernameOrEmail(ctx, "alice")
	if err != nil {
		t.Fatalf("by username: %v", err)
	}
	if u.Password != "hashed-pw" || u.TfaSecret != "TFASECRET" {
		t.Errorf("secrets not loaded: %+v", u)
	}
	u2, err := r.users.FindByUsernameOrEmail(ctx, "alice@x.io")
	if err != nil || u2.Guid != "u-guid-1" {
		t.Fatalf("by email: %v %v", u2, err)
	}
	if _, err := r.users.FindByUsernameOrEmail(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing ident err = %v, want ErrNotFound", err)
	}
}

func TestUserRepoSecretsExplicitLoad(t *testing.T) {
	r := newRepoDB(t)
	ctx := context.Background()
	seedUser(t, r, "u-guid-2", "bob", "bob@x.io", "hashed-pw", "TFA")

	// 公共列查询：敏感列必须为空（共享知识 5）。
	pub, err := r.users.FindByGuid(ctx, "u-guid-2")
	if err != nil {
		t.Fatalf("FindByGuid: %v", err)
	}
	if pub.Password != "" || pub.TfaSecret != "" || pub.Verifier != "" || pub.EmailVerificationCode != "" {
		t.Errorf("sensitive columns leaked in public select: %+v", pub)
	}
	if pub.Username != "bob" {
		t.Errorf("username = %q", pub.Username)
	}

	// WithSecrets 全列加载。
	sec, err := r.users.FindByGuidWithSecrets(ctx, "u-guid-2")
	if err != nil {
		t.Fatalf("FindByGuidWithSecrets: %v", err)
	}
	if sec.Password != "hashed-pw" || sec.TfaSecret != "TFA" {
		t.Errorf("secrets not loaded: %+v", sec)
	}
}

func TestUserRepoUpdateProfile(t *testing.T) {
	r := newRepoDB(t)
	ctx := context.Background()
	seedUser(t, r, "u-guid-3", "carol", "carol@x.io", "", "")

	email := "carol-new@x.io"
	note := "hello"
	if err := r.users.UpdateProfile(ctx, "u-guid-3", ProfilePatch{Email: &email, Note: &note}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	u, _ := r.users.FindByGuid(ctx, "u-guid-3")
	if u.Email != "carol-new@x.io" || u.Note != "hello" || u.Username != "carol" {
		t.Errorf("after update = %+v", u)
	}

	// 全 nil 补丁 = no-op。
	if err := r.users.UpdateProfile(ctx, "u-guid-3", ProfilePatch{}); err != nil {
		t.Errorf("no-op patch: %v", err)
	}
}

func TestUserRepoUniqueConstraints(t *testing.T) {
	r := newRepoDB(t)
	ctx := context.Background()
	seedUser(t, r, "u-guid-4", "dave", "dave@x.io", "", "")

	// username 唯一。
	if err := r.users.WithSecrets(ctx).Create(&entity.User{Guid: uuid.New().String(), Username: "dave", Status: 1}).Error; err == nil {
		t.Error("duplicate username should violate UK_users_username")
	}
	// email 唯一。
	if err := r.users.WithSecrets(ctx).Create(&entity.User{Guid: uuid.New().String(), Username: "other", Email: "dave@x.io", Status: 1}).Error; err == nil {
		t.Error("duplicate email should violate UK_users_email")
	}
	// oidcSubject 唯一。
	sub := "oidc:github:42"
	if err := r.users.WithSecrets(ctx).Create(&entity.User{Guid: uuid.New().String(), Username: "oidc1", OidcSubject: &sub, Status: 1}).Error; err != nil {
		t.Fatalf("first oidc user: %v", err)
	}
	if err := r.users.WithSecrets(ctx).Create(&entity.User{Guid: uuid.New().String(), Username: "oidc2", OidcSubject: &sub, Status: 1}).Error; err == nil {
		t.Error("duplicate oidcSubject should violate UK_users_oidcSubject")
	}
	// 按 subject 查找。
	u, err := r.users.FindByOidcSubject(ctx, sub)
	if err != nil || u.Username != "oidc1" {
		t.Errorf("FindByOidcSubject = %v, %v", u, err)
	}
}

// --- UserTokenRepo ---

func TestUserTokenRepoRevokeFlow(t *testing.T) {
	r := newRepoDB(t)
	ctx := context.Background()
	seedUser(t, r, "u-guid-5", "erin", "erin@x.io", "", "")
	now := time.Now()

	tok := &entity.UserToken{
		Guid: "jti-1", UserGuid: "u-guid-5", Jti: "jti-1",
		DeviceId: "dev-1", DeviceUuid: "duid-1", DeviceOs: "linux",
		DeviceType: "desktop", DeviceName: "workstation",
		ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
	}
	if err := r.tokens.Create(ctx, tok); err != nil {
		t.Fatalf("Create token: %v", err)
	}

	got, err := r.tokens.FindActive(ctx, "u-guid-5", "jti-1")
	if err != nil || got.Jti != "jti-1" {
		t.Fatalf("FindActive: %v %v", got, err)
	}

	// 撤销后不可用。
	if err := r.tokens.RevokeByJti(ctx, "u-guid-5", "jti-1"); err != nil {
		t.Fatalf("RevokeByJti: %v", err)
	}
	if _, err := r.tokens.FindActive(ctx, "u-guid-5", "jti-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked token err = %v, want ErrNotFound", err)
	}
}

func TestUserTokenRepoExpiryAndList(t *testing.T) {
	r := newRepoDB(t)
	ctx := context.Background()
	seedUser(t, r, "u-guid-6", "frank", "frank@x.io", "", "")
	now := time.Now()

	mk := func(jti string, ttl time.Duration, revoked bool, createdAt time.Time) {
		err := r.tokens.Create(ctx, &entity.UserToken{
			Guid: jti, UserGuid: "u-guid-6", Jti: jti,
			ExpiresAt: now.Add(ttl), IsRevoked: revoked, CreatedAt: createdAt,
		})
		if err != nil {
			t.Fatalf("mk token %s: %v", jti, err)
		}
	}
	mk("t-live-1", time.Hour, false, now.Add(-2*time.Hour))
	mk("t-live-2", 2*time.Hour, false, now.Add(-1*time.Hour))
	mk("t-expired", -time.Hour, false, now.Add(-3*time.Hour))
	mk("t-revoked", time.Hour, true, now)

	// ListActive：只含未撤销未过期，createdAt 倒序。
	list, err := r.tokens.ListActive(ctx, "u-guid-6")
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	if len(list) != 2 || list[0].Jti != "t-live-2" || list[1].Jti != "t-live-1" {
		t.Errorf("ListActive = %+v", list)
	}

	// 过期清理。
	if _, err := r.tokens.DeleteExpired(ctx, now); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	list2, _ := r.tokens.ListActive(ctx, "u-guid-6")
	if len(list2) != 2 {
		t.Errorf("after cleanup ListActive = %d, want 2", len(list2))
	}
	var total int64
	_ = r.tokens.Scoped(ctx).Count(&total).Error
	if total != 3 {
		t.Errorf("total after cleanup = %d, want 3 (expired removed)", total)
	}
}

func TestUserTokenRepoRevokeByDevice(t *testing.T) {
	r := newRepoDB(t)
	ctx := context.Background()
	seedUser(t, r, "u-guid-7", "grace", "grace@x.io", "", "")
	now := time.Now()

	mk := func(jti, dev string) {
		err := r.tokens.Create(ctx, &entity.UserToken{
			Guid: jti, UserGuid: "u-guid-7", Jti: jti,
			DeviceId: dev, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		if err != nil {
			t.Fatalf("mk %s: %v", jti, err)
		}
	}
	mk("d1", "dev-a")
	mk("d2", "dev-a")
	mk("d3", "dev-b")

	if err := r.tokens.RevokeByDevice(ctx, "u-guid-7", "dev-a", ""); err != nil {
		t.Fatalf("RevokeByDevice: %v", err)
	}
	if _, err := r.tokens.FindActive(ctx, "u-guid-7", "d1"); !errors.Is(err, ErrNotFound) {
		t.Error("d1 should be revoked")
	}
	if _, err := r.tokens.FindActive(ctx, "u-guid-7", "d2"); !errors.Is(err, ErrNotFound) {
		t.Error("d2 should be revoked")
	}
	if _, err := r.tokens.FindActive(ctx, "u-guid-7", "d3"); err != nil {
		t.Error("d3 should stay active")
	}
}

// --- LoginSessionRepo ---

func TestLoginSessionRepoLifecycle(t *testing.T) {
	r := newRepoDB(t)
	ctx := context.Background()
	seedUser(t, r, "u-guid-8", "henry", "henry@x.io", "", "")
	now := time.Now()

	// DeleteExisting 先清旧会话（单活跃）。
	_ = r.sess.Create(ctx, &entity.LoginSession{Guid: "old", UserGuid: "u-guid-8", Method: "tfa", ExpiresAt: now.Add(5 * time.Minute)})
	if err := r.sess.DeleteExisting(ctx, "u-guid-8", "tfa"); err != nil {
		t.Fatalf("DeleteExisting: %v", err)
	}

	s := &entity.LoginSession{Guid: "secret-1", UserGuid: "u-guid-8", Method: "tfa", ExpiresAt: now.Add(5 * time.Minute)}
	if err := r.sess.Create(ctx, s); err != nil {
		t.Fatalf("Create session: %v", err)
	}

	got, err := r.sess.FindUsable(ctx, "secret-1", StringSet{"tfa", "email"})
	if err != nil || got.Guid != "secret-1" {
		t.Fatalf("FindUsable: %v %v", got, err)
	}
	// method 不在白名单。
	if _, err := r.sess.FindUsable(ctx, "secret-1", StringSet{"passkey"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("wrong method err = %v", err)
	}
	// MarkUsed 单次使用。
	if err := r.sess.MarkUsed(ctx, "secret-1"); err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}
	if _, err := r.sess.FindUsable(ctx, "secret-1", StringSet{"tfa"}); !errors.Is(err, ErrNotFound) {
		t.Error("used session should not be usable")
	}
	// 过期会话不可用 + 清理。
	_ = r.sess.Create(ctx, &entity.LoginSession{Guid: "expired-1", UserGuid: "u-guid-8", Method: "tfa", ExpiresAt: now.Add(-time.Minute)})
	if _, err := r.sess.FindUsable(ctx, "expired-1", StringSet{"tfa"}); !errors.Is(err, ErrNotFound) {
		t.Error("expired session should not be usable")
	}
	if _, err := r.sess.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if _, err := r.sess.FindByID(ctx, "expired-1"); !errors.Is(err, ErrNotFound) {
		t.Error("expired session should be deleted")
	}
}

// --- PasskeyRepo ---

func TestPasskeyRepoFlow(t *testing.T) {
	r := newRepoDB(t)
	ctx := context.Background()
	seedUser(t, r, "u-guid-9", "iris", "iris@x.io", "", "")

	c := &entity.PasskeyCredential{
		Guid: "pk-1", UserGuid: "u-guid-9", CredentialId: "cred-abc",
		CredentialPublicKey: "pubkey-b64", Counter: 0, DeviceType: "singleDevice",
	}
	if err := r.pk.Create(ctx, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// credentialId 唯一。
	if err := r.pk.Create(ctx, &entity.PasskeyCredential{Guid: "pk-2", UserGuid: "u-guid-9", CredentialId: "cred-abc"}); err == nil {
		t.Error("duplicate credentialId should violate UK")
	}

	got, err := r.pk.FindByCredentialId(ctx, "cred-abc")
	if err != nil || got.Guid != "pk-1" {
		t.Fatalf("FindByCredentialId: %v %v", got, err)
	}

	if err := r.pk.UpdateCounter(ctx, "pk-1", 5); err != nil {
		t.Fatalf("UpdateCounter: %v", err)
	}
	got, _ = r.pk.FindByCredentialId(ctx, "cred-abc")
	if got.Counter != 5 {
		t.Errorf("counter = %d, want 5", got.Counter)
	}

	list, err := r.pk.ListByUser(ctx, "u-guid-9")
	if err != nil || len(list) != 1 {
		t.Errorf("ListByUser = %v, %v", list, err)
	}
}

// --- UserGroupRepo ---

func TestUserGroupRepoFindDefault(t *testing.T) {
	r := newRepoDB(t)
	ctx := context.Background()

	if err := r.groups.Create(ctx, &entity.UserGroup{Guid: "g-1", Name: "Default", NormalizedName: "default", IsDefault: true}); err != nil {
		t.Fatalf("Create group: %v", err)
	}
	g, err := r.groups.FindDefault(ctx)
	if err != nil || g.Guid != "g-1" || !g.IsDefault {
		t.Fatalf("FindDefault = %v, %v", g, err)
	}
	// normalizedName 唯一。
	if err := r.groups.Create(ctx, &entity.UserGroup{Guid: "g-2", Name: "Default2", NormalizedName: "default"}); err == nil {
		t.Error("duplicate normalizedName should violate UK")
	}
}

// --- OidcRepo ---

func TestOidcRepoProvidersAndStates(t *testing.T) {
	r := newRepoDB(t)
	ctx := context.Background()

	mk := func(name string, enabled bool, priority int) {
		err := r.oidc.SaveState(ctx, &entity.OidcAuthState{}) // 占位以校验 SaveState 可用
		_ = err
		p := &entity.OidcProvider{Guid: uuid.New().String(), Name: name, Enabled: enabled, Priority: priority}
		if err := r.oidc.db.WithContext(ctx).Create(p).Error; err != nil {
			t.Fatalf("create provider %s: %v", name, err)
		}
	}
	mk("beta", true, 2)
	mk("alpha", true, 1)
	mk("gamma", false, 0)

	providers, err := r.oidc.FindEnabledProviders(ctx)
	if err != nil {
		t.Fatalf("FindEnabledProviders: %v", err)
	}
	if len(providers) != 2 || providers[0].Name != "alpha" || providers[1].Name != "beta" {
		t.Errorf("providers = %+v", providers)
	}

	p, err := r.oidc.FindByName(ctx, "alpha")
	if err != nil || p.Priority != 1 {
		t.Fatalf("FindByName = %v, %v", p, err)
	}
	if _, err := r.oidc.FindByName(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing provider err = %v", err)
	}

	// 状态机：Save → Find → Complete。
	st := &entity.OidcAuthState{
		Guid: uuid.New().String(), Code: "poll-code", Status: "pending",
		ExpiresAt: time.Now().Add(10 * time.Minute), CodeVerifier: "verifier-xyz",
	}
	if err := r.oidc.SaveState(ctx, st); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	found, err := r.oidc.FindStateByCode(ctx, "poll-code")
	if err != nil || found.Status != "pending" {
		t.Fatalf("FindStateByCode = %v, %v", found, err)
	}
	status := "success"
	userGuid := "u-guid-9"
	accessToken := "jwt-token"
	if err := r.oidc.CompleteState(ctx, "poll-code", StatePatch{Status: &status, UserGuid: &userGuid, AccessToken: &accessToken}); err != nil {
		t.Fatalf("CompleteState: %v", err)
	}
	found, _ = r.oidc.FindStateByCode(ctx, "poll-code")
	if found.Status != "success" || found.UserGuid != "u-guid-9" || found.AccessToken != "jwt-token" {
		t.Errorf("after complete = %+v", found)
	}
}
