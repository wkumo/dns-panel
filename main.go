package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-webauthn/webauthn/webauthn"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

//go:embed web/dist/*
var web embed.FS

type app struct {
	db       *sql.DB
	webauthn *webauthn.WebAuthn
}
type ctxKey string

const userKey ctxKey = "user"

type user struct {
	ID                                                                                                int64
	Username, Email, Role, NameFilter, ValueFilter, BarkURL, BarkBody, HTTPSQuietStart, HTTPSQuietEnd string
	HTTPSAlertLimit                                                                                   int
	MustChange, MFAVerified                                                                           bool
}
type record struct {
	ID       int64  `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority *int   `json:"priority"`
	Comment  string `json:"comment"`
	Proxied  bool   `json:"proxied"`
	Deleted  bool   `json:"deleted"`
}

func main() {
	dir := env("DATA_DIR", "./data")
	if e := os.MkdirAll(dir, 0750); e != nil {
		log.Fatal(e)
	}
	db, e := sql.Open("sqlite", filepath.Join(dir, "dns-panel.db"))
	if e != nil {
		log.Fatal(e)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	a := &app{db: db}
	if e = a.migrate(); e != nil {
		log.Fatal(e)
	}
	if e = a.bootstrap(); e != nil {
		log.Fatal(e)
	}
	if e = a.configureWebAuthn(); e != nil {
		log.Fatal(e)
	}
	go a.monitorLoop()
	m := http.NewServeMux()
	m.HandleFunc("GET /api/policy", a.policy)
	m.HandleFunc("POST /api/login", a.login)
	m.HandleFunc("POST /api/register", a.register)
	m.HandleFunc("POST /api/register/verify", a.verifyRegistration)
	m.HandleFunc("POST /api/password/forgot", a.forgotPassword)
	m.HandleFunc("POST /api/password/reset", a.resetForgottenPassword)
	m.HandleFunc("POST /api/logout", a.auth(a.logout))
	m.HandleFunc("GET /api/me", a.auth(a.me))
	m.HandleFunc("PUT /api/me/password", a.auth(a.password))
	m.HandleFunc("POST /api/me/profile/request", a.auth(a.profileRequest))
	m.HandleFunc("POST /api/me/profile/confirm", a.auth(a.profileConfirm))
	m.HandleFunc("POST /api/me/bark/test", a.auth(a.testBark))
	m.HandleFunc("GET /api/me/otp", a.auth(a.listOTP))
	m.HandleFunc("POST /api/me/otp", a.auth(a.beginOTP))
	m.HandleFunc("POST /api/me/otp/{id}/confirm", a.auth(a.confirmOTP))
	m.HandleFunc("DELETE /api/me/otp/{id}", a.auth(a.deleteOTP))
	m.HandleFunc("GET /api/me/passkeys", a.auth(a.listPasskeys))
	m.HandleFunc("POST /api/me/passkeys/begin", a.auth(a.beginPasskey))
	m.HandleFunc("POST /api/me/passkeys/finish", a.auth(a.finishPasskey))
	m.HandleFunc("DELETE /api/me/passkeys/{id}", a.auth(a.deletePasskey))
	m.HandleFunc("POST /api/me/mfa/email", a.auth(a.sendMFAEmail))
	m.HandleFunc("POST /api/me/mfa/otp", a.auth(a.verifyMFAOTP))
	m.HandleFunc("POST /api/me/mfa/email/verify", a.auth(a.verifyMFAEmail))
	m.HandleFunc("POST /api/me/mfa/passkey/begin", a.auth(a.beginMFAPasskey))
	m.HandleFunc("POST /api/me/mfa/passkey/finish", a.auth(a.finishMFAPasskey))
	m.HandleFunc("GET /api/domains", a.auth(a.domains))
	m.HandleFunc("POST /api/domains", a.auth(a.addDomain))
	m.HandleFunc("PUT /api/domains/order", a.auth(a.orderDomains))
	m.HandleFunc("DELETE /api/domains/{id}", a.auth(a.deleteDomain))
	m.HandleFunc("GET /api/domains/{id}/records", a.auth(a.records))
	m.HandleFunc("PUT /api/domains/{id}/records", a.auth(a.saveRecords))
	m.HandleFunc("POST /api/domains/{id}/refresh", a.auth(a.refreshDomain))
	m.HandleFunc("POST /api/domains/{id}/sync", a.auth(a.syncDomain))
	m.HandleFunc("POST /api/domains/refresh", a.auth(a.refreshAll))
	m.HandleFunc("GET /api/credentials", a.auth(a.credentials))
	m.HandleFunc("POST /api/credentials", a.auth(a.addCredential))
	m.HandleFunc("PUT /api/credentials/order", a.auth(a.orderCredentials))
	m.HandleFunc("DELETE /api/credentials/{id}", a.auth(a.deleteCredential))
	m.HandleFunc("GET /api/settings", a.auth(a.admin(a.settings)))
	m.HandleFunc("PUT /api/settings", a.auth(a.admin(a.saveSettings)))
	m.HandleFunc("POST /api/settings/test-email", a.auth(a.admin(a.testEmail)))
	m.HandleFunc("POST /api/settings/test-smtp", a.auth(a.admin(a.testSMTP)))
	m.HandleFunc("GET /api/admin/users", a.auth(a.admin(a.listUsers)))
	m.HandleFunc("POST /api/admin/users/{id}/reset-password", a.auth(a.admin(a.adminResetPassword)))
	m.HandleFunc("GET /api/https-monitors", a.auth(a.listHTTPSMonitors))
	m.HandleFunc("GET /api/https-monitors/excluded-domains", a.auth(a.listHTTPSExcludedDomains))
	m.HandleFunc("PUT /api/https-monitors/excluded-domains", a.auth(a.saveHTTPSExcludedDomains))
	m.HandleFunc("PUT /api/https-monitors/{id}", a.auth(a.updateHTTPSMonitor))
	m.HandleFunc("PUT /api/https-monitors/order", a.auth(a.orderHTTPSMonitors))
	m.HandleFunc("POST /api/https-monitors/check", a.auth(a.checkHTTPSMonitors))
	m.HandleFunc("POST /api/https-monitors/{id}/check", a.auth(a.checkHTTPSMonitor))
	dist, _ := fs.Sub(web, "web/dist")
	m.Handle("/", http.FileServer(http.FS(dist)))
	addr := env("LISTEN_ADDR", ":8080")
	log.Printf("DNS Panel listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, headers(m)))
}
func (a *app) migrate() error {
	_, e := a.db.Exec(`PRAGMA foreign_keys=ON;PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,email TEXT NOT NULL DEFAULT '',password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',must_change_password INTEGER NOT NULL DEFAULT 0,email_verified INTEGER NOT NULL DEFAULT 0,otp_secret TEXT,name_filter TEXT NOT NULL DEFAULT '',value_filter TEXT NOT NULL DEFAULT '',bark_url TEXT NOT NULL DEFAULT '',bark_body TEXT NOT NULL DEFAULT '',https_quiet_start TEXT NOT NULL DEFAULT '',https_quiet_end TEXT NOT NULL DEFAULT '',https_alert_limit INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at DATETIME NOT NULL,mfa_verified INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS verification_codes(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,email TEXT NOT NULL,code TEXT NOT NULL,payload TEXT NOT NULL,purpose TEXT NOT NULL DEFAULT 'profile',expires_at DATETIME NOT NULL);
CREATE TABLE IF NOT EXISTS otp_credentials(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,secret TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS passkey_credentials(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,credential_id TEXT NOT NULL UNIQUE,credential_json TEXT NOT NULL,created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS webauthn_sessions(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,purpose TEXT NOT NULL,name TEXT NOT NULL,data TEXT NOT NULL,expires_at DATETIME NOT NULL);
CREATE TABLE IF NOT EXISTS password_reset_tokens(token TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at DATETIME NOT NULL);
CREATE TABLE IF NOT EXISTS https_monitor_preferences(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,record_id INTEGER NOT NULL REFERENCES records(id) ON DELETE CASCADE,port INTEGER NOT NULL DEFAULT 443,note TEXT NOT NULL DEFAULT '',hidden INTEGER NOT NULL DEFAULT 0,sort_order INTEGER NOT NULL DEFAULT 2147483647,last_valid INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',not_before TEXT NOT NULL DEFAULT '',not_after TEXT NOT NULL DEFAULT '',last_checked TEXT NOT NULL DEFAULT '',certificate_domains TEXT NOT NULL DEFAULT '',alert_notified INTEGER NOT NULL DEFAULT 0,alert_notify_count INTEGER NOT NULL DEFAULT 0,UNIQUE(user_id,record_id));
CREATE TABLE IF NOT EXISTS https_domain_exclusions(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,PRIMARY KEY(user_id,domain_id));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS credentials(id INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL,provider TEXT NOT NULL,access_key TEXT NOT NULL,secret TEXT NOT NULL,extra TEXT NOT NULL DEFAULT '{}',sort_order INTEGER NOT NULL DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS domains(id INTEGER PRIMARY KEY,name TEXT NOT NULL,provider TEXT NOT NULL,provider_zone_id TEXT,credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL,sort_order INTEGER NOT NULL DEFAULT 0,UNIQUE(name,provider));
CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY,domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,remote_id TEXT,type TEXT NOT NULL,name TEXT NOT NULL,content TEXT NOT NULL,ttl INTEGER NOT NULL DEFAULT 300,priority INTEGER,comment TEXT NOT NULL DEFAULT '',proxied INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'synced',updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
INSERT OR IGNORE INTO settings VALUES('registration_enabled','true'),('email_verification','false'),('login_notification','false'),('require_mfa','false'),('smtp_verified','false'),('password_min_length','0'),('password_require_number','false'),('password_require_uppercase','false'),('password_require_lowercase','false'),('password_require_symbol','false'),('notification_duration','5'),('default_record_types','["A","CNAME","AAAA"]'),('smtp_host',''),('smtp_port','587'),('smtp_username',''),('smtp_password',''),('smtp_from',''),('site_url',''),('passkey_rp_id',''),('passkey_origins','');`)
	if e != nil {
		return e
	}
	var tenantMigration string
	if e = a.db.QueryRow("SELECT value FROM settings WHERE key='tenant_resources_v1'").Scan(&tenantMigration); e == sql.ErrNoRows {
		_, e = a.db.Exec(`PRAGMA foreign_keys=OFF;
BEGIN;
CREATE TABLE credentials_tenant(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,provider TEXT NOT NULL,access_key TEXT NOT NULL,secret TEXT NOT NULL,extra TEXT NOT NULL DEFAULT '{}',sort_order INTEGER NOT NULL DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,UNIQUE(user_id,name));
INSERT INTO credentials_tenant(id,user_id,name,provider,access_key,secret,extra,sort_order,created_at) SELECT id,(SELECT id FROM users ORDER BY CASE WHEN role='admin' THEN 0 ELSE 1 END,id LIMIT 1),name,provider,access_key,secret,extra,sort_order,created_at FROM credentials;
CREATE TABLE domains_tenant(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,name TEXT NOT NULL,provider TEXT NOT NULL,provider_zone_id TEXT,credential_id INTEGER REFERENCES credentials_tenant(id) ON DELETE SET NULL,sort_order INTEGER NOT NULL DEFAULT 0,UNIQUE(user_id,name,provider));
INSERT INTO domains_tenant(id,user_id,name,provider,provider_zone_id,credential_id,sort_order) SELECT id,(SELECT id FROM users ORDER BY CASE WHEN role='admin' THEN 0 ELSE 1 END,id LIMIT 1),name,provider,provider_zone_id,credential_id,sort_order FROM domains;
DROP TABLE domains;
DROP TABLE credentials;
ALTER TABLE credentials_tenant RENAME TO credentials;
ALTER TABLE domains_tenant RENAME TO domains;
INSERT INTO settings(key,value)VALUES('tenant_resources_v1','done');
COMMIT;
PRAGMA foreign_keys=ON;`)
		if e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	var registrationMigration string
	if e = a.db.QueryRow("SELECT value FROM settings WHERE key='registration_open_migration_v1'").Scan(&registrationMigration); e == sql.ErrNoRows {
		if _, e = a.db.Exec("UPDATE settings SET value='true' WHERE key='registration_enabled'; INSERT INTO settings(key,value)VALUES('registration_open_migration_v1','done')"); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if e = a.ensureColumn("users", "email", "TEXT NOT NULL DEFAULT ''"); e != nil {
		return e
	}
	if e = a.ensureColumn("users", "email_verified", "INTEGER NOT NULL DEFAULT 0"); e != nil {
		return e
	}
	if e = a.ensureColumn("users", "name_filter", "TEXT NOT NULL DEFAULT ''"); e != nil {
		return e
	}
	if e = a.ensureColumn("users", "value_filter", "TEXT NOT NULL DEFAULT ''"); e != nil {
		return e
	}
	if e = a.ensureColumn("users", "bark_url", "TEXT NOT NULL DEFAULT ''"); e != nil {
		return e
	}
	for _, column := range []struct{ table, name, definition string }{
		{"users", "bark_body", "TEXT NOT NULL DEFAULT ''"}, {"users", "https_quiet_start", "TEXT NOT NULL DEFAULT ''"}, {"users", "https_quiet_end", "TEXT NOT NULL DEFAULT ''"},
		{"users", "https_alert_limit", "INTEGER NOT NULL DEFAULT 1"},
		{"https_monitor_preferences", "last_valid", "INTEGER NOT NULL DEFAULT 0"}, {"https_monitor_preferences", "last_error", "TEXT NOT NULL DEFAULT ''"}, {"https_monitor_preferences", "not_before", "TEXT NOT NULL DEFAULT ''"}, {"https_monitor_preferences", "not_after", "TEXT NOT NULL DEFAULT ''"}, {"https_monitor_preferences", "last_checked", "TEXT NOT NULL DEFAULT ''"},
		{"https_monitor_preferences", "certificate_domains", "TEXT NOT NULL DEFAULT ''"},
		{"https_monitor_preferences", "alert_notified", "INTEGER NOT NULL DEFAULT 0"},
		{"https_monitor_preferences", "alert_notify_count", "INTEGER NOT NULL DEFAULT 0"},
	} {
		if e = a.ensureColumn(column.table, column.name, column.definition); e != nil {
			return e
		}
	}
	if _, e = a.db.Exec("UPDATE https_monitor_preferences SET alert_notify_count=1 WHERE alert_notified=1 AND alert_notify_count=0"); e != nil {
		return e
	}
	if e = a.ensureColumn("sessions", "mfa_verified", "INTEGER NOT NULL DEFAULT 1"); e != nil {
		return e
	}
	if e = a.ensureColumn("verification_codes", "purpose", "TEXT NOT NULL DEFAULT 'profile'"); e != nil {
		return e
	}
	if e = a.ensureColumn("domains", "credential_id", "INTEGER REFERENCES credentials(id) ON DELETE SET NULL"); e != nil {
		return e
	}
	if e = a.ensureColumn("domains", "sort_order", "INTEGER NOT NULL DEFAULT 0"); e != nil {
		return e
	}
	if e = a.ensureColumn("credentials", "sort_order", "INTEGER NOT NULL DEFAULT 0"); e != nil {
		return e
	}
	if e = a.ensureColumn("records", "proxied", "INTEGER NOT NULL DEFAULT 0"); e != nil {
		return e
	}
	// Accounts created before registration verification existed are grandfathered in.
	_, e = a.db.Exec("UPDATE users SET email_verified=1 WHERE email_verified=0 AND id NOT IN (SELECT user_id FROM verification_codes WHERE purpose='registration')")
	return e
}
func (a *app) ensureColumn(table, column, definition string) error {
	rows, e := a.db.Query("PRAGMA table_info(" + table + ")")
	if e != nil {
		return e
	}
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var def any
		if e = rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); e != nil {
			rows.Close()
			return e
		}
		if name == column {
			found = true
		}
	}
	rows.Close()
	if found {
		return nil
	}
	_, e = a.db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition)
	return e
}
func (a *app) bootstrap() error {
	var n int
	if e := a.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n); e != nil || n > 0 {
		return e
	}
	h, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	_, e := a.db.Exec("INSERT INTO users(username,password_hash,role,must_change_password)VALUES(?,?,'admin',1)", "admin", h)
	return e
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	var v struct{ Username, Password string }
	if !decode(w, r, &v) {
		return
	}
	var u user
	var h string
	var verified bool
	e := a.db.QueryRow("SELECT id,username,email,COALESCE(name_filter,''),COALESCE(value_filter,''),COALESCE(bark_url,''),COALESCE(bark_body,''),COALESCE(https_quiet_start,''),COALESCE(https_quiet_end,''),COALESCE(https_alert_limit,1),password_hash,role,must_change_password,email_verified FROM users WHERE username=?", v.Username).Scan(&u.ID, &u.Username, &u.Email, &u.NameFilter, &u.ValueFilter, &u.BarkURL, &u.BarkBody, &u.HTTPSQuietStart, &u.HTTPSQuietEnd, &u.HTTPSAlertLimit, &h, &u.Role, &u.MustChange, &verified)
	if e != nil || bcrypt.CompareHashAndPassword([]byte(h), []byte(v.Password)) != nil {
		fail(w, 401, "用户名或密码错误")
		return
	}
	if u.Role != "admin" && !verified {
		fail(w, 403, "邮箱尚未验证，请先完成注册邮箱验证")
		return
	}
	t := token()
	exp := time.Now().Add(7 * 24 * time.Hour)
	mfaVerified := a.setting("require_mfa") != "true" || u.Role == "admin"
	if _, e = a.db.Exec("INSERT INTO sessions(token,user_id,expires_at,mfa_verified)VALUES(?,?,?,?)", t, u.ID, exp, mfaVerified); e != nil {
		fail(w, 500, "无法创建会话")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "dns_session", Value: t, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, Expires: exp})
	u.MFAVerified = mfaVerified
	jsonOut(w, 200, userOut(u))
	if a.setting("login_notification") == "true" && u.Email != "" {
		email, username, remote, agent := u.Email, u.Username, r.RemoteAddr, r.UserAgent()
		go func() {
			body := fmt.Sprintf("账号 %s 刚刚登录 DNS Panel。\n\n时间：%s\nIP：%s\n浏览器：%s\n\n如果这不是你的操作，请立即修改密码。", username, time.Now().Format(time.RFC3339), remote, agent)
			if e := a.sendMail(email, "DNS Panel 登录通知", body); e != nil {
				log.Printf("login notification email failed for user %d: %v", u.ID, e)
			}
		}()
	}
}
func (a *app) register(w http.ResponseWriter, r *http.Request) {
	if a.setting("registration_enabled") != "true" {
		fail(w, 403, "管理员未开放注册")
		return
	}
	if a.setting("smtp_verified") != "true" {
		fail(w, 503, "注册需要先由管理员配置 SMTP 并通过连接测试")
		return
	}
	var v struct{ Username, Email, Password string }
	if !decode(w, r, &v) {
		return
	}
	if v.Username == "" || !strings.Contains(v.Email, "@") {
		fail(w, 400, "用户名不能为空，并填写有效邮箱")
		return
	}
	if e := a.validatePassword(v.Password); e != "" {
		fail(w, 400, e)
		return
	}
	v.Email = strings.TrimSpace(v.Email)
	var emailExists int
	if e := a.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email=? COLLATE NOCASE)", v.Email).Scan(&emailExists); e != nil {
		fail(w, 500, "无法检查邮箱")
		return
	}
	if emailExists != 0 {
		fail(w, 409, "该邮箱已经注册")
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(v.Password), bcrypt.DefaultCost)
	res, e := a.db.Exec("INSERT INTO users(username,email,password_hash,email_verified)VALUES(?,?,?,0)", v.Username, v.Email, h)
	if e != nil {
		fail(w, 409, "用户名已存在")
		return
	}
	userID, _ := res.LastInsertId()
	code := verificationCode()
	if _, e = a.db.Exec("INSERT INTO verification_codes(user_id,email,code,payload,purpose,expires_at)VALUES(?,?,?,'{}','registration',?)", userID, v.Email, code, time.Now().Add(10*time.Minute)); e != nil {
		a.db.Exec("DELETE FROM users WHERE id=?", userID)
		fail(w, 500, "无法创建邮箱验证码")
		return
	}
	if e = a.sendMail(v.Email, "DNS Panel 注册验证码", verificationEmailBody("注册邮箱验证", code)); e != nil {
		a.db.Exec("DELETE FROM users WHERE id=?", userID)
		fail(w, 502, "注册验证码邮件发送失败："+e.Error())
		return
	}
	jsonOut(w, 202, map[string]any{"verificationRequired": true, "email": v.Email})
}
func (a *app) verifyRegistration(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Code string }
	if !decode(w, r, &in) {
		return
	}
	var id, userID int64
	e := a.db.QueryRow("SELECT id,user_id FROM verification_codes WHERE email=? AND code=? AND purpose='registration' AND expires_at>CURRENT_TIMESTAMP ORDER BY id DESC LIMIT 1", in.Email, in.Code).Scan(&id, &userID)
	if e != nil {
		fail(w, 400, "验证码错误或已过期")
		return
	}
	tx, e := a.db.Begin()
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE users SET email_verified=1 WHERE id=?", userID); e == nil {
		_, e = tx.Exec("DELETE FROM verification_codes WHERE id=?", id)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 500, "邮箱验证保存失败")
		return
	}
	w.WriteHeader(204)
}
func (a *app) forgotPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &in) {
		return
	}
	var id int64
	var username, email string
	if e := a.db.QueryRow("SELECT id,username,email FROM users WHERE email=? COLLATE NOCASE ORDER BY id LIMIT 1", strings.TrimSpace(in.Email)).Scan(&id, &username, &email); e == nil {
		if e = a.issuePasswordReset(r, id, username, email); e != nil {
			// Do not reveal whether an email address is registered.
			log.Printf("forgot password email failed for user %d: %v", id, e)
		}
	}
	w.WriteHeader(204)
}

func (a *app) issuePasswordReset(r *http.Request, userID int64, username, email string) error {
	if strings.TrimSpace(email) == "" {
		return fmt.Errorf("用户没有设置邮箱")
	}
	t := token()
	tx, e := a.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("DELETE FROM password_reset_tokens WHERE user_id=?", userID); e == nil {
		_, e = tx.Exec("INSERT INTO password_reset_tokens(token,user_id,expires_at)VALUES(?,?,?)", t, userID, time.Now().Add(time.Hour))
	}
	if e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	link := a.passwordResetBaseURL(r) + "/?reset=" + url.QueryEscape(t)
	body := fmt.Sprintf("用户名：%s\r\n\r\n请在 1 小时内打开以下一次性链接重置密码：\r\n%s\r\n\r\n如果不是你本人操作，请忽略此邮件。", username, link)
	if e = a.sendMail(email, "DNS Panel 密码重置", body); e != nil {
		a.db.Exec("DELETE FROM password_reset_tokens WHERE token=?", t)
		return e
	}
	return nil
}

func (a *app) passwordResetBaseURL(r *http.Request) string {
	if configured := strings.TrimSpace(a.setting("site_url")); configured != "" {
		if normalized, _, _, e := parseSiteURL(configured); e == nil {
			return normalized
		}
	}
	if configured := strings.TrimSpace(os.Getenv("PUBLIC_URL")); configured != "" {
		return strings.TrimSuffix(configured, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); forwarded == "http" || forwarded == "https" {
		scheme = forwarded
	}
	return scheme + "://" + r.Host
}
func (a *app) resetForgottenPassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Token, Password, ConfirmPassword string }
	if !decode(w, r, &in) {
		return
	}
	if in.Password != in.ConfirmPassword {
		fail(w, 400, "两次密码不一致")
		return
	}
	if m := a.validatePassword(in.Password); m != "" {
		fail(w, 400, m)
		return
	}
	var userID int64
	if e := a.db.QueryRow("SELECT user_id FROM password_reset_tokens WHERE token=? AND expires_at>CURRENT_TIMESTAMP", in.Token).Scan(&userID); e != nil {
		fail(w, 400, "重置链接无效或已过期")
		return
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	tx, e := a.db.Begin()
	if e != nil {
		fail(w, 500, "密码重置失败")
		return
	}
	defer tx.Rollback()
	_, e = tx.Exec("UPDATE users SET password_hash=?,must_change_password=0 WHERE id=?", h, userID)
	if e == nil {
		_, e = tx.Exec("DELETE FROM password_reset_tokens WHERE user_id=?", userID)
	}
	if e == nil {
		_, e = tx.Exec("DELETE FROM sessions WHERE user_id=?", userID)
	}
	if e == nil {
		e = tx.Commit()
	}
	if e != nil {
		fail(w, 500, "密码重置失败")
		return
	}
	w.WriteHeader(204)
}
func (a *app) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, e := r.Cookie("dns_session")
		if e != nil {
			fail(w, 401, "请先登录")
			return
		}
		var u user
		e = a.db.QueryRow(`SELECT u.id,u.username,u.email,COALESCE(u.name_filter,''),COALESCE(u.value_filter,''),COALESCE(u.bark_url,''),COALESCE(u.bark_body,''),COALESCE(u.https_quiet_start,''),COALESCE(u.https_quiet_end,''),COALESCE(u.https_alert_limit,1),u.role,u.must_change_password,s.mfa_verified FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>CURRENT_TIMESTAMP`, c.Value).Scan(&u.ID, &u.Username, &u.Email, &u.NameFilter, &u.ValueFilter, &u.BarkURL, &u.BarkBody, &u.HTTPSQuietStart, &u.HTTPSQuietEnd, &u.HTTPSAlertLimit, &u.Role, &u.MustChange, &u.MFAVerified)
		if e != nil {
			fail(w, 401, "登录已过期")
			return
		}
		if u.MustChange && r.URL.Path != "/api/me" && r.URL.Path != "/api/me/password" && r.URL.Path != "/api/logout" {
			fail(w, 403, "首次登录必须修改账号、密码并填写邮箱")
			return
		}
		if !u.MFAVerified && r.URL.Path != "/api/me" && r.URL.Path != "/api/logout" && !strings.HasPrefix(r.URL.Path, "/api/me/mfa/") {
			fail(w, 403, "需要完成二次认证")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	}
}
func (a *app) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if current(r).Role != "admin" {
			fail(w, 403, "需要管理员权限")
			return
		}
		next(w, r)
	}
}
func current(r *http.Request) user { return r.Context().Value(userKey).(user) }
func userOut(u user) map[string]any {
	return map[string]any{"username": u.Username, "email": u.Email, "nameFilter": u.NameFilter, "valueFilter": u.ValueFilter, "barkURL": u.BarkURL, "barkBody": u.BarkBody, "httpsQuietStart": u.HTTPSQuietStart, "httpsQuietEnd": u.HTTPSQuietEnd, "httpsAlertLimit": u.HTTPSAlertLimit, "role": u.Role, "mustChangePassword": u.MustChange, "mfaRequired": !u.MFAVerified}
}
func (a *app) me(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	out := userOut(u)
	_, rpID, _ := a.passkeySiteConfig()
	out["passkeyRPID"] = rpID
	methods := []string{}
	var count int
	a.db.QueryRow("SELECT COUNT(*) FROM otp_credentials WHERE user_id=? AND enabled=1", u.ID).Scan(&count)
	if count > 0 {
		methods = append(methods, "otp")
	}
	a.db.QueryRow("SELECT COUNT(*) FROM passkey_credentials WHERE user_id=?", u.ID).Scan(&count)
	if count > 0 {
		methods = append(methods, "passkey")
	}
	if u.Email != "" {
		methods = append(methods, "email")
	}
	out["mfaMethods"] = methods
	jsonOut(w, 200, out)
}
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("dns_session"); e == nil {
		a.db.Exec("DELETE FROM sessions WHERE token=?", c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "dns_session", Path: "/", MaxAge: -1})
	w.WriteHeader(204)
}
func (a *app) password(w http.ResponseWriter, r *http.Request) {
	var v struct{ Username, Email, NewPassword, ConfirmPassword string }
	if !decode(w, r, &v) {
		return
	}
	if v.Username == "" || !strings.Contains(v.Email, "@") {
		fail(w, 400, "用户名不能为空，并填写有效邮箱")
		return
	}
	if v.NewPassword != v.ConfirmPassword {
		fail(w, 400, "两次输入的密码不一致")
		return
	}
	if e := a.validatePassword(v.NewPassword); e != "" {
		fail(w, 400, e)
		return
	}
	nh, _ := bcrypt.GenerateFromPassword([]byte(v.NewPassword), bcrypt.DefaultCost)
	if _, e := a.db.Exec("UPDATE users SET username=?,email=?,password_hash=?,must_change_password=0,email_verified=0 WHERE id=?", v.Username, v.Email, nh, current(r).ID); e != nil {
		fail(w, 409, "用户名已存在")
		return
	}
	w.WriteHeader(204)
}

type profileChange struct {
	Username        string `json:"username"`
	Email           string `json:"email"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
	NameFilter      string `json:"nameFilter"`
	ValueFilter     string `json:"valueFilter"`
	BarkURL         string `json:"barkURL"`
	BarkBody        string `json:"barkBody"`
	HTTPSQuietStart string `json:"httpsQuietStart"`
	HTTPSQuietEnd   string `json:"httpsQuietEnd"`
	HTTPSAlertLimit string `json:"httpsAlertLimit"`
}

func (a *app) profileRequest(w http.ResponseWriter, r *http.Request) {
	var v profileChange
	if !decode(w, r, &v) {
		return
	}
	if v.Username == "" || !strings.Contains(v.Email, "@") || strings.ContainsAny(v.Email, "\r\n") {
		fail(w, 400, "用户名不能为空，并填写有效邮箱")
		return
	}
	if v.NewPassword != v.ConfirmPassword {
		fail(w, 400, "两次输入的密码不一致")
		return
	}
	for _, value := range []string{v.HTTPSQuietStart, v.HTTPSQuietEnd} {
		if value != "" {
			if _, e := time.Parse("15:04", value); e != nil {
				fail(w, 400, "HTTPS 免检时间格式无效")
				return
			}
		}
	}
	alertLimit, e := strconv.Atoi(v.HTTPSAlertLimit)
	if v.HTTPSAlertLimit == "" {
		alertLimit = 1
		e = nil
	}
	if e != nil || alertLimit < 1 || alertLimit > 100 {
		fail(w, 400, "HTTPS 通知次数必须在 1 到 100 之间")
		return
	}
	v.HTTPSAlertLimit = strconv.Itoa(alertLimit)
	if strings.TrimSpace(v.BarkBody) != "" {
		probe := v.BarkBody
		for _, key := range []string{"{{title}}", "{{body}}", "{{host}}", "{{port}}", "{{error}}"} {
			probe = strings.ReplaceAll(probe, key, "value")
		}
		if !json.Valid([]byte(probe)) {
			fail(w, 400, "Bark POST 内容必须是有效的 JSON")
			return
		}
	}
	if v.NewPassword != "" {
		if m := a.validatePassword(v.NewPassword); m != "" {
			fail(w, 400, m)
			return
		}
	}
	payload, _ := json.Marshal(v)
	if a.setting("email_verification") != "true" {
		if e := a.applyProfile(current(r).ID, v); e != nil {
			fail(w, 409, "用户名已存在")
			return
		}
		w.WriteHeader(204)
		return
	}
	code := verificationCode()
	a.db.Exec("DELETE FROM verification_codes WHERE user_id=? AND purpose='profile'", current(r).ID)
	res, e := a.db.Exec("INSERT INTO verification_codes(user_id,email,code,payload,purpose,expires_at)VALUES(?,?,?,?,'profile',?)", current(r).ID, v.Email, code, string(payload), time.Now().Add(10*time.Minute))
	if e != nil {
		fail(w, 500, "无法创建验证码")
		return
	}
	id, _ := res.LastInsertId()
	if e = a.sendMail(v.Email, "DNS Panel 账户修改验证码", "你的验证码是："+code+"\n验证码 10 分钟内有效。"); e != nil {
		a.db.Exec("DELETE FROM verification_codes WHERE id=?", id)
		fail(w, 502, "验证码邮件发送失败："+e.Error())
		return
	}
	jsonOut(w, 202, map[string]any{"verificationRequired": true})
}
func (a *app) profileConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	var id int64
	var payload string
	e := a.db.QueryRow("SELECT id,payload FROM verification_codes WHERE user_id=? AND code=? AND purpose='profile' AND expires_at>CURRENT_TIMESTAMP ORDER BY id DESC LIMIT 1", current(r).ID, in.Code).Scan(&id, &payload)
	if e != nil {
		fail(w, 400, "验证码错误或已过期")
		return
	}
	var v profileChange
	if json.Unmarshal([]byte(payload), &v) != nil {
		fail(w, 500, "验证数据损坏")
		return
	}
	if e = a.applyProfile(current(r).ID, v); e != nil {
		fail(w, 409, "用户名已存在")
		return
	}
	a.db.Exec("DELETE FROM verification_codes WHERE user_id=? AND purpose='profile'", current(r).ID)
	w.WriteHeader(204)
}
func (a *app) applyProfile(id int64, v profileChange) error {
	if v.NewPassword == "" {
		_, e := a.db.Exec("UPDATE users SET username=?,email=?,name_filter=?,value_filter=?,bark_url=?,bark_body=?,https_quiet_start=?,https_quiet_end=?,https_alert_limit=?,email_verified=1 WHERE id=?", v.Username, v.Email, v.NameFilter, v.ValueFilter, v.BarkURL, v.BarkBody, v.HTTPSQuietStart, v.HTTPSQuietEnd, v.HTTPSAlertLimit, id)
		return e
	}
	h, _ := bcrypt.GenerateFromPassword([]byte(v.NewPassword), bcrypt.DefaultCost)
	_, e := a.db.Exec("UPDATE users SET username=?,email=?,name_filter=?,value_filter=?,bark_url=?,bark_body=?,https_quiet_start=?,https_quiet_end=?,https_alert_limit=?,password_hash=?,email_verified=1 WHERE id=?", v.Username, v.Email, v.NameFilter, v.ValueFilter, v.BarkURL, v.BarkBody, v.HTTPSQuietStart, v.HTTPSQuietEnd, v.HTTPSAlertLimit, h, id)
	return e
}

type webUser struct {
	ID          int64
	Username    string
	Credentials []webauthn.Credential
}

func (u webUser) WebAuthnID() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(u.ID))
	return b
}
func (u webUser) WebAuthnName() string                       { return u.Username }
func (u webUser) WebAuthnDisplayName() string                { return u.Username }
func (u webUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
func (a *app) loadWebUser(id int64) (webUser, error) {
	var u webUser
	u.ID = id
	if e := a.db.QueryRow("SELECT username FROM users WHERE id=?", id).Scan(&u.Username); e != nil {
		return u, e
	}
	rows, e := a.db.Query("SELECT credential_json FROM passkey_credentials WHERE user_id=? ORDER BY id", id)
	if e != nil {
		return u, e
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			return u, e
		}
		var c webauthn.Credential
		if e = json.Unmarshal([]byte(raw), &c); e != nil {
			return u, e
		}
		u.Credentials = append(u.Credentials, c)
	}
	return u, rows.Err()
}
func (a *app) listOTP(w http.ResponseWriter, r *http.Request) {
	rows, e := a.db.Query("SELECT id,name,enabled,created_at FROM otp_credentials WHERE user_id=? ORDER BY id", current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var name, created string
		var enabled bool
		rows.Scan(&id, &name, &enabled, &created)
		out = append(out, map[string]any{"id": id, "name": name, "enabled": enabled, "createdAt": created})
	}
	jsonOut(w, 200, out)
}
func (a *app) beginOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		fail(w, 400, "OTP 名称不能为空")
		return
	}
	raw := make([]byte, 20)
	if _, e := rand.Read(raw); e != nil {
		fail(w, 500, "无法生成 OTP 密钥")
		return
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	res, e := a.db.Exec("INSERT INTO otp_credentials(user_id,name,secret,enabled)VALUES(?,?,?,0)", current(r).ID, in.Name, secret)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	id, _ := res.LastInsertId()
	issuer := url.QueryEscape("DNS Panel")
	account := url.QueryEscape(current(r).Username)
	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", issuer, account, secret, issuer)
	jsonOut(w, 201, map[string]any{"id": id, "secret": secret, "uri": uri})
}
func (a *app) confirmOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	var secret string
	e := a.db.QueryRow("SELECT secret FROM otp_credentials WHERE id=? AND user_id=? AND enabled=0", r.PathValue("id"), current(r).ID).Scan(&secret)
	if e != nil {
		fail(w, 404, "待确认 OTP 不存在")
		return
	}
	if !validTOTP(secret, in.Code, time.Now()) {
		fail(w, 400, "动态验证码错误")
		return
	}
	a.db.Exec("UPDATE otp_credentials SET enabled=1 WHERE id=? AND user_id=?", r.PathValue("id"), current(r).ID)
	w.WriteHeader(204)
}
func (a *app) deleteOTP(w http.ResponseWriter, r *http.Request) {
	res, e := a.db.Exec("DELETE FROM otp_credentials WHERE id=? AND user_id=?", r.PathValue("id"), current(r).ID)
	result(w, res, e)
}
func validTOTP(secret, code string, now time.Time) bool {
	key, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if e != nil {
		return false
	}
	for offset := -1; offset <= 1; offset++ {
		counter := uint64(now.Unix()/30 + int64(offset))
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, counter)
		mac := hmac.New(sha1.New, key)
		mac.Write(b)
		sum := mac.Sum(nil)
		i := sum[len(sum)-1] & 15
		value := (uint32(sum[i])&0x7f)<<24 | (uint32(sum[i+1])&0xff)<<16 | (uint32(sum[i+2])&0xff)<<8 | (uint32(sum[i+3]) & 0xff)
		expected := fmt.Sprintf("%06d", value%1000000)
		if hmac.Equal([]byte(expected), []byte(strings.TrimSpace(code))) {
			return true
		}
	}
	return false
}
func (a *app) listPasskeys(w http.ResponseWriter, r *http.Request) {
	rows, e := a.db.Query("SELECT id,name,created_at FROM passkey_credentials WHERE user_id=? ORDER BY id", current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var name, created string
		rows.Scan(&id, &name, &created)
		out = append(out, map[string]any{"id": id, "name": name, "createdAt": created})
	}
	jsonOut(w, 200, out)
}
func (a *app) beginPasskey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		fail(w, 400, "Passkey 名称不能为空")
		return
	}
	u, e := a.loadWebUser(current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	creation, session, e := a.webauthn.BeginRegistration(u)
	if e != nil {
		fail(w, 500, "无法创建 Passkey 挑战："+e.Error())
		return
	}
	data, _ := json.Marshal(session)
	sessionToken := token()
	if _, e = a.db.Exec("INSERT INTO webauthn_sessions(token,user_id,purpose,name,data,expires_at)VALUES(?,?,'registration',?,?,?)", sessionToken, u.ID, in.Name, string(data), time.Now().Add(5*time.Minute)); e != nil {
		fail(w, 500, e.Error())
		return
	}
	jsonOut(w, 200, map[string]any{"options": creation, "sessionToken": sessionToken})
}
func (a *app) finishPasskey(w http.ResponseWriter, r *http.Request) {
	sessionToken := r.URL.Query().Get("token")
	var name, data string
	e := a.db.QueryRow("SELECT name,data FROM webauthn_sessions WHERE token=? AND user_id=? AND purpose='registration' AND expires_at>CURRENT_TIMESTAMP", sessionToken, current(r).ID).Scan(&name, &data)
	if e != nil {
		fail(w, 400, "Passkey 挑战不存在或已过期")
		return
	}
	var session webauthn.SessionData
	if json.Unmarshal([]byte(data), &session) != nil {
		fail(w, 500, "Passkey 挑战数据损坏")
		return
	}
	u, e := a.loadWebUser(current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	credential, e := a.webauthn.FinishRegistration(u, session, r)
	if e != nil {
		fail(w, 400, "Passkey 验证失败："+e.Error())
		return
	}
	raw, _ := json.Marshal(credential)
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	if _, e = a.db.Exec("INSERT INTO passkey_credentials(user_id,name,credential_id,credential_json)VALUES(?,?,?,?)", u.ID, name, credentialID, string(raw)); e != nil {
		fail(w, 409, "该 Passkey 已经注册")
		return
	}
	a.db.Exec("DELETE FROM webauthn_sessions WHERE token=?", sessionToken)
	w.WriteHeader(204)
}
func (a *app) deletePasskey(w http.ResponseWriter, r *http.Request) {
	res, e := a.db.Exec("DELETE FROM passkey_credentials WHERE id=? AND user_id=?", r.PathValue("id"), current(r).ID)
	result(w, res, e)
}
func (a *app) markMFAVerified(r *http.Request) error {
	c, e := r.Cookie("dns_session")
	if e != nil {
		return e
	}
	_, e = a.db.Exec("UPDATE sessions SET mfa_verified=1 WHERE token=? AND user_id=?", c.Value, current(r).ID)
	return e
}
func (a *app) sendMFAEmail(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	if u.Email == "" {
		fail(w, 400, "账号未设置邮箱")
		return
	}
	code := verificationCode()
	a.db.Exec("DELETE FROM verification_codes WHERE user_id=? AND purpose='mfa'", u.ID)
	if _, e := a.db.Exec("INSERT INTO verification_codes(user_id,email,code,payload,purpose,expires_at)VALUES(?,?,?,'{}','mfa',?)", u.ID, u.Email, code, time.Now().Add(10*time.Minute)); e != nil {
		fail(w, 500, e.Error())
		return
	}
	if e := a.sendMail(u.Email, "DNS Panel 登录验证码", verificationEmailBody("登录二次认证", code)); e != nil {
		fail(w, 502, "验证码发送失败："+e.Error())
		return
	}
	w.WriteHeader(204)
}
func (a *app) verifyMFAEmail(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	var id int64
	if e := a.db.QueryRow("SELECT id FROM verification_codes WHERE user_id=? AND code=? AND purpose='mfa' AND expires_at>CURRENT_TIMESTAMP", current(r).ID, in.Code).Scan(&id); e != nil {
		fail(w, 400, "验证码错误或已过期")
		return
	}
	if e := a.markMFAVerified(r); e != nil {
		fail(w, 500, e.Error())
		return
	}
	a.db.Exec("DELETE FROM verification_codes WHERE id=?", id)
	w.WriteHeader(204)
}
func (a *app) verifyMFAOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	rows, e := a.db.Query("SELECT secret FROM otp_credentials WHERE user_id=? AND enabled=1", current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	valid := false
	for rows.Next() {
		var secret string
		rows.Scan(&secret)
		if validTOTP(secret, in.Code, time.Now()) {
			valid = true
			break
		}
	}
	if !valid {
		fail(w, 400, "OTP 验证码错误")
		return
	}
	if e = a.markMFAVerified(r); e != nil {
		fail(w, 500, e.Error())
		return
	}
	w.WriteHeader(204)
}
func (a *app) beginMFAPasskey(w http.ResponseWriter, r *http.Request) {
	u, e := a.loadWebUser(current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	assertion, session, e := a.webauthn.BeginLogin(u)
	if e != nil {
		fail(w, 400, "无法开始 Passkey 验证："+e.Error())
		return
	}
	data, _ := json.Marshal(session)
	t := token()
	if _, e = a.db.Exec("INSERT INTO webauthn_sessions(token,user_id,purpose,name,data,expires_at)VALUES(?,?,'login','',?,?)", t, u.ID, string(data), time.Now().Add(5*time.Minute)); e != nil {
		fail(w, 500, e.Error())
		return
	}
	jsonOut(w, 200, map[string]any{"options": assertion, "sessionToken": t})
}
func (a *app) finishMFAPasskey(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("token")
	var data string
	if e := a.db.QueryRow("SELECT data FROM webauthn_sessions WHERE token=? AND user_id=? AND purpose='login' AND expires_at>CURRENT_TIMESTAMP", t, current(r).ID).Scan(&data); e != nil {
		fail(w, 400, "Passkey 挑战不存在或已过期")
		return
	}
	var session webauthn.SessionData
	if json.Unmarshal([]byte(data), &session) != nil {
		fail(w, 500, "Passkey 挑战数据损坏")
		return
	}
	u, e := a.loadWebUser(current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	credential, e := a.webauthn.FinishLogin(u, session, r)
	if e != nil {
		fail(w, 400, "Passkey 验证失败："+e.Error())
		return
	}
	raw, _ := json.Marshal(credential)
	cid := base64.RawURLEncoding.EncodeToString(credential.ID)
	a.db.Exec("UPDATE passkey_credentials SET credential_json=? WHERE user_id=? AND credential_id=?", string(raw), u.ID, cid)
	if e = a.markMFAVerified(r); e != nil {
		fail(w, 500, e.Error())
		return
	}
	a.db.Exec("DELETE FROM webauthn_sessions WHERE token=?", t)
	w.WriteHeader(204)
}
func (a *app) policy(w http.ResponseWriter, r *http.Request) {
	minimum, _ := strconv.Atoi(a.setting("password_min_length"))
	var defaultTypes []string
	_ = json.Unmarshal([]byte(a.setting("default_record_types")), &defaultTypes)
	jsonOut(w, 200, map[string]any{"minLength": minimum, "number": a.setting("password_require_number") == "true", "uppercase": a.setting("password_require_uppercase") == "true", "lowercase": a.setting("password_require_lowercase") == "true", "symbol": a.setting("password_require_symbol") == "true", "notificationDuration": a.setting("notification_duration"), "registrationEnabled": a.setting("registration_enabled") == "true", "emailVerification": a.setting("email_verification") == "true", "requireMFA": a.setting("require_mfa") == "true", "defaultRecordTypes": defaultTypes})
}
func (a *app) validatePassword(password string) string {
	if password == "" {
		return "密码不能为空"
	}
	minimum, _ := strconv.Atoi(a.setting("password_min_length"))
	if minimum < 0 {
		minimum = 0
	}
	if len([]rune(password)) < minimum {
		return fmt.Sprintf("密码长度不能少于 %d 位", minimum)
	}
	var number, upper, lower, symbol bool
	for _, c := range password {
		switch {
		case unicode.IsNumber(c):
			number = true
		case unicode.IsUpper(c):
			upper = true
		case unicode.IsLower(c):
			lower = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			symbol = true
		}
	}
	missing := []string{}
	if a.setting("password_require_number") == "true" && !number {
		missing = append(missing, "数字")
	}
	if a.setting("password_require_uppercase") == "true" && !upper {
		missing = append(missing, "大写字母")
	}
	if a.setting("password_require_lowercase") == "true" && !lower {
		missing = append(missing, "小写字母")
	}
	if a.setting("password_require_symbol") == "true" && !symbol {
		missing = append(missing, "符号")
	}
	if len(missing) > 0 {
		return "密码必须包含：" + strings.Join(missing, "、")
	}
	return ""
}
func verificationCode() string {
	b := make([]byte, 4)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	n := (int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])) & 0x7fffffff
	return strconv.Itoa(100000 + n%900000)
}
func verificationEmailBody(purpose, code string) string {
	return "DNS Panel " + purpose + "\r\n\r\n验证码：" + code + "\r\n\r\n验证码在 10 分钟内有效。如果不是你本人操作，请忽略此邮件。"
}
func (a *app) sendMail(to, subject, body string) error {
	host := a.setting("smtp_host")
	port := a.setting("smtp_port")
	from := a.setting("smtp_from")
	username := a.setting("smtp_username")
	password := a.setting("smtp_password")
	if host == "" || port == "" || from == "" {
		return fmt.Errorf("SMTP 配置不完整")
	}
	var auth smtp.Auth
	if username != "" {
		auth = smtp.PlainAuth("", username, password, host)
	}
	message := []byte("To: " + to + "\r\nFrom: " + from + "\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + body)
	if port == "465" {
		conn, e := tls.Dial("tcp", host+":"+port, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if e != nil {
			return e
		}
		client, e := smtp.NewClient(conn, host)
		if e != nil {
			conn.Close()
			return e
		}
		defer client.Close()
		if auth != nil {
			if e = client.Auth(auth); e != nil {
				return e
			}
		}
		if e = client.Mail(from); e != nil {
			return e
		}
		if e = client.Rcpt(to); e != nil {
			return e
		}
		writer, e := client.Data()
		if e != nil {
			return e
		}
		if _, e = writer.Write(message); e != nil {
			writer.Close()
			return e
		}
		if e = writer.Close(); e != nil {
			return e
		}
		return client.Quit()
	}
	return smtp.SendMail(host+":"+port, auth, from, []string{to}, message)
}
func (a *app) testEmail(w http.ResponseWriter, r *http.Request) {
	to := current(r).Email
	if to == "" {
		to = a.setting("smtp_from")
	}
	if to == "" {
		fail(w, 400, "管理员邮箱和 SMTP 发件地址均为空")
		return
	}
	if e := a.sendMail(to, "DNS Panel SMTP 测试", "这是一封 DNS Panel SMTP 测试邮件。\n\n收到此邮件表示当前 SMTP 配置可以正常发信。"); e != nil {
		fail(w, 502, "测试邮件发送失败："+e.Error())
		return
	}
	jsonOut(w, 200, map[string]string{"sentTo": to})
}
func (a *app) testSMTP(w http.ResponseWriter, r *http.Request) {
	if e := a.smtpConnect(); e != nil {
		a.db.Exec("INSERT INTO settings(key,value)VALUES('smtp_verified','false') ON CONFLICT(key)DO UPDATE SET value='false'")
		fail(w, 502, "SMTP 连接失败："+e.Error())
		return
	}
	a.db.Exec("INSERT INTO settings(key,value)VALUES('smtp_verified','true') ON CONFLICT(key)DO UPDATE SET value='true'")
	w.WriteHeader(204)
}
func (a *app) smtpConnect() error {
	host, port, user, password := a.setting("smtp_host"), a.setting("smtp_port"), a.setting("smtp_username"), a.setting("smtp_password")
	if host == "" || port == "" {
		return fmt.Errorf("SMTP 配置不完整")
	}
	address := net.JoinHostPort(host, port)
	var client *smtp.Client
	var e error
	if port == "465" {
		var conn *tls.Conn
		conn, e = tls.Dial("tcp", address, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if e == nil {
			client, e = smtp.NewClient(conn, host)
		}
	} else {
		client, e = smtp.Dial(address)
		if e == nil {
			if ok, _ := client.Extension("STARTTLS"); ok {
				e = client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
			}
		}
	}
	if e != nil {
		return e
	}
	defer client.Close()
	if user != "" {
		if e = client.Auth(smtp.PlainAuth("", user, password, host)); e != nil {
			return e
		}
	}
	return client.Noop()
}
func (a *app) listUsers(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if per < 1 || per > 50 {
		per = 50
	}
	var total int
	a.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&total)
	rows, e := a.db.Query(`SELECT u.id,u.username,u.email,u.role,u.must_change_password,(SELECT COUNT(*) FROM otp_credentials o WHERE o.user_id=u.id AND o.enabled=1),(SELECT COUNT(*) FROM passkey_credentials p WHERE p.user_id=u.id) FROM users u ORDER BY u.id LIMIT ? OFFSET ?`, per, (page-1)*per)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id int64
		var username, email, role string
		var must bool
		var otp, passkey int
		rows.Scan(&id, &username, &email, &role, &must, &otp, &passkey)
		items = append(items, map[string]any{"id": id, "username": username, "email": email, "role": role, "mustChangePassword": must, "otpCount": otp, "passkeyCount": passkey})
	}
	jsonOut(w, 200, map[string]any{"items": items, "page": page, "perPage": per, "total": total})
}
func (a *app) adminResetPassword(w http.ResponseWriter, r *http.Request) {
	var id int64
	var username, email string
	if e := a.db.QueryRow("SELECT id,username,email FROM users WHERE id=?", r.PathValue("id")).Scan(&id, &username, &email); e == sql.ErrNoRows {
		fail(w, 404, "用户不存在")
		return
	} else if e != nil {
		fail(w, 500, e.Error())
		return
	}
	if e := a.issuePasswordReset(r, id, username, email); e != nil {
		fail(w, 502, "重置邮件发送失败："+e.Error())
		return
	}
	w.WriteHeader(204)
}

func (a *app) domains(w http.ResponseWriter, r *http.Request) {
	rows, e := a.db.Query(`SELECT d.id,d.name,d.provider,COALESCE(d.provider_zone_id,''),COALESCE(d.credential_id,0),COALESCE(c.name,'') FROM domains d LEFT JOIN credentials c ON c.id=d.credential_id WHERE d.user_id=? ORDER BY d.sort_order,d.id`, current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, cid int64
		var n, p, z, c string
		rows.Scan(&id, &n, &p, &z, &cid, &c)
		out = append(out, map[string]any{"id": id, "name": n, "provider": p, "zoneId": z, "credentialId": cid, "credential": c})
	}
	jsonOut(w, 200, out)
}
func (a *app) addDomain(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Name, Provider, ZoneID string
		CredentialID           int64
	}
	if !decode(w, r, &v) {
		return
	}
	v.Name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v.Name)), ".")
	v.Provider = strings.ToLower(v.Provider)
	if v.Name == "" || !validProvider(v.Provider) || v.CredentialID < 1 {
		fail(w, 400, "域名、提供商或 API Key 无效")
		return
	}
	var credentialProvider string
	if e := a.db.QueryRow("SELECT provider FROM credentials WHERE id=? AND user_id=?", v.CredentialID, current(r).ID).Scan(&credentialProvider); e != nil || credentialProvider != v.Provider {
		fail(w, 400, "API Key 不属于当前用户或厂商不匹配")
		return
	}
	res, e := a.db.Exec("INSERT INTO domains(user_id,name,provider,provider_zone_id,credential_id,sort_order)VALUES(?,?,?,?,?,COALESCE((SELECT MAX(sort_order)+1 FROM domains WHERE user_id=?),0))", current(r).ID, v.Name, v.Provider, v.ZoneID, v.CredentialID, current(r).ID)
	if e != nil {
		fail(w, 409, "域名已存在或 API Key 无效")
		return
	}
	id, _ := res.LastInsertId()
	jsonOut(w, 201, map[string]any{"id": id})
}
func (a *app) deleteDomain(w http.ResponseWriter, r *http.Request) {
	res, e := a.db.Exec("DELETE FROM domains WHERE id=? AND user_id=?", r.PathValue("id"), current(r).ID)
	result(w, res, e)
}
func (a *app) orderDomains(w http.ResponseWriter, r *http.Request) {
	a.saveOrder(w, r, "domains", current(r).ID)
}
func (a *app) ownsDomain(userID int64, domainID string) bool {
	var found int
	return a.db.QueryRow("SELECT 1 FROM domains WHERE id=? AND user_id=?", domainID, userID).Scan(&found) == nil
}
func (a *app) records(w http.ResponseWriter, r *http.Request) {
	if !a.ownsDomain(current(r).ID, r.PathValue("id")) {
		fail(w, 404, "域名不存在")
		return
	}
	rows, e := a.db.Query("SELECT id,type,name,content,ttl,priority,comment,proxied,status FROM records WHERE domain_id=? AND status<>'deleted' ORDER BY type,name", r.PathValue("id"))
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var ttl int
		var t, n, c, note, s string
		var proxied bool
		var p sql.NullInt64
		rows.Scan(&id, &t, &n, &c, &ttl, &p, &note, &proxied, &s)
		var priority any
		if p.Valid {
			priority = p.Int64
		}
		out = append(out, map[string]any{"id": id, "type": t, "name": n, "content": c, "ttl": ttl, "priority": priority, "comment": note, "proxied": proxied, "status": s})
	}
	jsonOut(w, 200, out)
}
func (a *app) saveRecords(w http.ResponseWriter, r *http.Request) {
	if !a.ownsDomain(current(r).ID, r.PathValue("id")) {
		fail(w, 404, "域名不存在")
		return
	}
	var list []record
	if !decode(w, r, &list) {
		return
	}
	tx, e := a.db.Begin()
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer tx.Rollback()
	for _, v := range list {
		v.Type = strings.ToUpper(v.Type)
		if !v.Deleted && (!validType(v.Type) || v.Name == "" || v.Content == "" || v.TTL < 1) {
			fail(w, 400, "记录类型、名称、值或 TTL 无效")
			return
		}
		if v.ID == 0 && !v.Deleted {
			_, e = tx.Exec("INSERT INTO records(domain_id,type,name,content,ttl,priority,comment,proxied,status)VALUES(?,?,?,?,?,?,?,?,'created')", r.PathValue("id"), v.Type, v.Name, v.Content, v.TTL, v.Priority, v.Comment, v.Proxied)
		} else if v.Deleted {
			_, e = tx.Exec("UPDATE records SET status='deleted' WHERE id=? AND domain_id=?", v.ID, r.PathValue("id"))
		} else {
			_, e = tx.Exec("UPDATE records SET type=?,name=?,content=?,ttl=?,priority=?,comment=?,proxied=?,status=CASE WHEN status='created' THEN 'created' ELSE 'updated' END WHERE id=? AND domain_id=?", v.Type, v.Name, v.Content, v.TTL, v.Priority, v.Comment, v.Proxied, v.ID, r.PathValue("id"))
		}
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
	}
	if e = tx.Commit(); e != nil {
		fail(w, 500, e.Error())
		return
	}
	w.WriteHeader(204)
}

type cfDomain struct {
	ID                  int64
	Name, ZoneID, Token string
}
type cfRecord struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority *int   `json:"priority"`
	Comment  string `json:"comment"`
	Proxied  *bool  `json:"proxied"`
}
type cfInfo struct{ Page, PerPage, TotalPages, Count, TotalCount int }
type cfEnvelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	ResultInfo cfInfo `json:"result_info"`
}

func (a *app) cloudflareDomain(userID int64, id string) (cfDomain, error) {
	var d cfDomain
	var provider, accessKey, secret string
	e := a.db.QueryRow(`SELECT d.id,d.name,COALESCE(d.provider_zone_id,''),d.provider,c.access_key,c.secret FROM domains d JOIN credentials c ON c.id=d.credential_id AND c.user_id=d.user_id WHERE d.id=? AND d.user_id=?`, id, userID).Scan(&d.ID, &d.Name, &d.ZoneID, &provider, &accessKey, &secret)
	if e != nil {
		return d, fmt.Errorf("域名或关联 API Key 不存在")
	}
	if provider != "cloudflare" {
		return d, fmt.Errorf("该域名不是 Cloudflare 域名")
	}
	d.Token = accessKey
	if d.Token == "" {
		d.Token = secret
	}
	if d.Token == "" {
		return d, fmt.Errorf("Cloudflare API Token 为空")
	}
	if d.ZoneID == "" {
		var zones []struct{ ID, Name string }
		if e = a.cfDo(context.Background(), d.Token, "GET", "/zones?name="+url.QueryEscape(d.Name)+"&per_page=50", nil, &zones); e != nil {
			return d, e
		}
		for _, z := range zones {
			if strings.EqualFold(strings.TrimSuffix(z.Name, "."), d.Name) {
				d.ZoneID = z.ID
				break
			}
		}
		if d.ZoneID == "" {
			return d, fmt.Errorf("Cloudflare 中找不到 Zone %s，请确认 Token 具有 Zone Read 权限", d.Name)
		}
		if _, e = a.db.Exec("UPDATE domains SET provider_zone_id=? WHERE id=?", d.ZoneID, d.ID); e != nil {
			return d, e
		}
	}
	return d, nil
}
func (a *app) cfDo(parent context.Context, token, method, path string, body any, out any) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	var reader io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return e
		}
		reader = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4"+path, reader)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		return fmt.Errorf("Cloudflare 请求失败：%w", e)
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if e != nil {
		return e
	}
	var env cfEnvelope
	if e = json.Unmarshal(raw, &env); e != nil {
		return fmt.Errorf("Cloudflare 返回了无效响应（HTTP %d）", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !env.Success {
		messages := []string{}
		for _, x := range env.Errors {
			messages = append(messages, fmt.Sprintf("%d: %s", x.Code, x.Message))
		}
		if len(messages) == 0 {
			messages = append(messages, resp.Status)
		}
		return fmt.Errorf("Cloudflare API：%s", strings.Join(messages, "；"))
	}
	if out != nil && len(env.Result) > 0 && string(env.Result) != "null" {
		if e = json.Unmarshal(env.Result, out); e != nil {
			return fmt.Errorf("解析 Cloudflare 响应失败：%w", e)
		}
	}
	return nil
}
func (a *app) fetchCloudflare(d cfDomain) ([]cfRecord, error) {
	var list []cfRecord
	e := a.cfDo(context.Background(), d.Token, "GET", "/zones/"+url.PathEscape(d.ZoneID)+"/dns_records?per_page=5000000", nil, &list)
	if e != nil {
		return nil, e
	}
	out := make([]cfRecord, 0, len(list))
	for _, r := range list {
		r.Type = strings.ToUpper(r.Type)
		if validType(r.Type) {
			out = append(out, r)
		}
	}
	return out, nil
}
func displayName(name, zone string) string {
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")
	if strings.EqualFold(name, zone) {
		return "@"
	}
	suffix := "." + strings.ToLower(zone)
	if strings.HasSuffix(strings.ToLower(name), suffix) {
		return name[:len(name)-len(suffix)]
	}
	return name
}
func cloudflareName(name, zone string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "@" || name == "" {
		return zone
	}
	if strings.EqualFold(name, zone) || strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zone)) {
		return name
	}
	return name + "." + zone
}
func (a *app) refreshCloudflare(userID int64, id string) error {
	d, e := a.cloudflareDomain(userID, id)
	if e != nil {
		return e
	}
	list, e := a.fetchCloudflare(d)
	if e != nil {
		return e
	}
	tx, e := a.db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	existingRows, e := tx.Query("SELECT id,COALESCE(remote_id,'') FROM records WHERE domain_id=?", d.ID)
	if e != nil {
		return e
	}
	existing := map[string]int64{}
	stale := map[int64]bool{}
	for existingRows.Next() {
		var localID int64
		var remoteID string
		if e = existingRows.Scan(&localID, &remoteID); e != nil {
			existingRows.Close()
			return e
		}
		stale[localID] = true
		if remoteID != "" {
			existing[remoteID] = localID
		}
	}
	if e = existingRows.Err(); e != nil {
		existingRows.Close()
		return e
	}
	existingRows.Close()
	for _, r := range list {
		ttl := r.TTL
		if ttl < 1 {
			ttl = 1
		}
		proxied := false
		if r.Proxied != nil {
			proxied = *r.Proxied
		}
		if localID, found := existing[r.ID]; found {
			_, e = tx.Exec("UPDATE records SET remote_id=?,type=?,name=?,content=?,ttl=?,priority=?,comment=?,proxied=?,status='synced',updated_at=CURRENT_TIMESTAMP WHERE id=?", r.ID, r.Type, displayName(r.Name, d.Name), r.Content, ttl, r.Priority, r.Comment, proxied, localID)
			delete(stale, localID)
		} else {
			_, e = tx.Exec("INSERT INTO records(domain_id,remote_id,type,name,content,ttl,priority,comment,proxied,status)VALUES(?,?,?,?,?,?,?,?,?,'synced')", d.ID, r.ID, r.Type, displayName(r.Name, d.Name), r.Content, ttl, r.Priority, r.Comment, proxied)
		}
		if e != nil {
			return e
		}
	}
	for localID := range stale {
		if _, e = tx.Exec("DELETE FROM records WHERE id=?", localID); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (a *app) refreshDomain(w http.ResponseWriter, r *http.Request) {
	if e := a.refreshCloudflare(current(r).ID, r.PathValue("id")); e != nil {
		status := 502
		if strings.Contains(e.Error(), "不是 Cloudflare") {
			status = 501
		}
		fail(w, status, e.Error())
		return
	}
	w.WriteHeader(204)
}
func (a *app) refreshAll(w http.ResponseWriter, r *http.Request) {
	rows, e := a.db.Query("SELECT id FROM domains WHERE provider='cloudflare' AND user_id=? ORDER BY id", current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	ids := []string{}
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		ids = append(ids, strconv.FormatInt(id, 10))
	}
	rows.Close()
	for _, id := range ids {
		if e = a.refreshCloudflare(current(r).ID, id); e != nil {
			fail(w, 502, "域名 ID "+id+" 最新化失败："+e.Error())
			return
		}
	}
	jsonOut(w, 200, map[string]any{"refreshed": len(ids)})
}
func (a *app) syncDomain(w http.ResponseWriter, r *http.Request) {
	d, e := a.cloudflareDomain(current(r).ID, r.PathValue("id"))
	if e != nil {
		status := 502
		if strings.Contains(e.Error(), "不是 Cloudflare") {
			status = 501
		}
		fail(w, status, e.Error())
		return
	}
	rows, e := a.db.Query("SELECT id,COALESCE(remote_id,''),type,name,content,ttl,priority,comment,proxied,status FROM records WHERE domain_id=? AND status<>'synced' ORDER BY id", d.ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	type pending struct {
		ID                            int64
		RemoteID, Type, Name, Content string
		TTL                           int
		Priority                      *int
		Proxied                       bool
		Comment, Status               string
	}
	changes := []pending{}
	for rows.Next() {
		var x pending
		var priority sql.NullInt64
		if e = rows.Scan(&x.ID, &x.RemoteID, &x.Type, &x.Name, &x.Content, &x.TTL, &priority, &x.Comment, &x.Proxied, &x.Status); e != nil {
			rows.Close()
			fail(w, 500, e.Error())
			return
		}
		if priority.Valid {
			p := int(priority.Int64)
			x.Priority = &p
		}
		changes = append(changes, x)
	}
	rows.Close()
	applied := 0
	for _, x := range changes {
		path := "/zones/" + url.PathEscape(d.ZoneID) + "/dns_records"
		if x.Status == "deleted" {
			if x.RemoteID != "" {
				if e = a.cfDo(r.Context(), d.Token, "DELETE", path+"/"+url.PathEscape(x.RemoteID), nil, nil); e != nil {
					fail(w, 502, fmt.Sprintf("已完成 %d 项，第 %d 项删除失败：%v", applied, x.ID, e))
					return
				}
			}
			_, e = a.db.Exec("DELETE FROM records WHERE id=?", x.ID)
		} else {
			payload := map[string]any{"type": x.Type, "name": cloudflareName(x.Name, d.Name), "content": x.Content, "ttl": x.TTL, "comment": x.Comment}
			if x.Priority != nil {
				payload["priority"] = *x.Priority
			}
			if x.Type == "A" || x.Type == "AAAA" || x.Type == "CNAME" {
				payload["proxied"] = x.Proxied
			}
			if x.Status == "created" || x.RemoteID == "" {
				var created cfRecord
				e = a.cfDo(r.Context(), d.Token, "POST", path, payload, &created)
				if e == nil {
					_, e = a.db.Exec("UPDATE records SET remote_id=?,status='synced',updated_at=CURRENT_TIMESTAMP WHERE id=?", created.ID, x.ID)
				}
			} else {
				var updated cfRecord
				e = a.cfDo(r.Context(), d.Token, "PATCH", path+"/"+url.PathEscape(x.RemoteID), payload, &updated)
				if e == nil {
					_, e = a.db.Exec("UPDATE records SET status='synced',updated_at=CURRENT_TIMESTAMP WHERE id=?", x.ID)
				}
			}
		}
		if e != nil {
			fail(w, 502, fmt.Sprintf("已完成 %d 项，第 %d 项同步失败：%v", applied, x.ID, e))
			return
		}
		applied++
	}
	jsonOut(w, 200, map[string]any{"synced": applied})
}

func (a *app) credentials(w http.ResponseWriter, r *http.Request) {
	rows, e := a.db.Query("SELECT id,name,provider,access_key,created_at FROM credentials WHERE user_id=? ORDER BY sort_order,id", current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var n, p, k, t string
		rows.Scan(&id, &n, &p, &k, &t)
		if len(k) > 4 {
			k = "****" + k[len(k)-4:]
		} else {
			k = "****"
		}
		out = append(out, map[string]any{"id": id, "name": n, "provider": p, "accessKey": k, "createdAt": t})
	}
	jsonOut(w, 200, out)
}
func (a *app) addCredential(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Name, Provider, AccessKey, Secret string
		Extra                             map[string]string
	}
	if !decode(w, r, &v) {
		return
	}
	v.Provider = strings.ToLower(v.Provider)
	if v.Provider == "cloudflare" && v.Secret == "" {
		v.Secret = v.AccessKey
	}
	if v.Name == "" || v.AccessKey == "" || v.Secret == "" || !validProvider(v.Provider) {
		fail(w, 400, "API Key 配置无效")
		return
	}
	x, _ := json.Marshal(v.Extra)
	res, e := a.db.Exec("INSERT INTO credentials(user_id,name,provider,access_key,secret,extra,sort_order)VALUES(?,?,?,?,?,?,COALESCE((SELECT MAX(sort_order)+1 FROM credentials WHERE user_id=?),0))", current(r).ID, v.Name, v.Provider, v.AccessKey, v.Secret, string(x), current(r).ID)
	if e != nil {
		fail(w, 409, "名称已存在")
		return
	}
	id, _ := res.LastInsertId()
	jsonOut(w, 201, map[string]any{"id": id})
}
func (a *app) deleteCredential(w http.ResponseWriter, r *http.Request) {
	res, e := a.db.Exec("DELETE FROM credentials WHERE id=? AND user_id=?", r.PathValue("id"), current(r).ID)
	result(w, res, e)
}
func (a *app) orderCredentials(w http.ResponseWriter, r *http.Request) {
	a.saveOrder(w, r, "credentials", current(r).ID)
}
func (a *app) saveOrder(w http.ResponseWriter, r *http.Request, table string, userID int64) {
	var in struct {
		IDs []int64 `json:"ids"`
	}
	if !decode(w, r, &in) {
		return
	}
	tx, e := a.db.Begin()
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer tx.Rollback()
	seen := map[int64]bool{}
	for order, id := range in.IDs {
		if id < 1 || seen[id] {
			fail(w, 400, "排序数据无效")
			return
		}
		seen[id] = true
		result, updateErr := tx.Exec("UPDATE "+table+" SET sort_order=? WHERE id=? AND user_id=?", order, id, userID)
		if updateErr != nil {
			e = updateErr
			fail(w, 500, e.Error())
			return
		}
		if affected, _ := result.RowsAffected(); affected != 1 {
			fail(w, 400, "排序包含不属于当前用户的数据")
			return
		}
	}
	if e = tx.Commit(); e != nil {
		fail(w, 500, e.Error())
		return
	}
	w.WriteHeader(204)
}

type httpsMonitor struct {
	ID                 int64  `json:"id"`
	Host               string `json:"host"`
	Type               string `json:"type"`
	Value              string `json:"value"`
	Domain             string `json:"domain"`
	DomainID           int64  `json:"domainId"`
	Note               string `json:"note"`
	Port               int    `json:"port"`
	Hidden             bool   `json:"hidden"`
	ExplicitHidden     bool   `json:"explicitHidden"`
	Filtered           bool   `json:"filtered"`
	DomainExcluded     bool   `json:"domainExcluded"`
	SortOrder          int    `json:"sortOrder"`
	Valid              bool   `json:"valid"`
	Skipped            bool   `json:"skipped"`
	Error              string `json:"error"`
	NotBefore          string `json:"notBefore"`
	NotAfter           string `json:"notAfter"`
	LastChecked        string `json:"lastChecked"`
	DaysRemaining      int    `json:"daysRemaining"`
	CertificateDomains string `json:"certificateDomains"`
	AlertNotified      bool   `json:"alertNotified"`
	AlertNotifyCount   int    `json:"alertNotifyCount"`
}

func (a *app) listMonitorData(userID int64) ([]httpsMonitor, error) {
	var nameFilter, valueFilter string
	if e := a.db.QueryRow("SELECT COALESCE(name_filter,''),COALESCE(value_filter,'') FROM users WHERE id=?", userID).Scan(&nameFilter, &valueFilter); e != nil {
		return nil, e
	}
	rows, e := a.db.Query(`SELECT r.id,r.type,r.name,r.content,d.name,d.id,COALESCE(p.port,443),COALESCE(p.note,''),COALESCE(p.hidden,0),COALESCE(p.sort_order,2147483647),COALESCE(p.last_valid,0),COALESCE(p.last_error,''),COALESCE(p.not_before,''),COALESCE(p.not_after,''),COALESCE(p.last_checked,''),COALESCE(p.certificate_domains,''),COALESCE(p.alert_notified,0),COALESCE(p.alert_notify_count,0),EXISTS(SELECT 1 FROM https_domain_exclusions e WHERE e.user_id=? AND e.domain_id=d.id) FROM records r JOIN domains d ON d.id=r.domain_id LEFT JOIN https_monitor_preferences p ON p.record_id=r.id AND p.user_id=? WHERE d.user_id=? AND r.status<>'deleted' AND r.type IN('A','AAAA','CNAME') ORDER BY COALESCE(p.sort_order,2147483647),r.id`, userID, userID, userID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []httpsMonitor{}
	for rows.Next() {
		var m httpsMonitor
		if e = rows.Scan(&m.ID, &m.Type, &m.Host, &m.Value, &m.Domain, &m.DomainID, &m.Port, &m.Note, &m.ExplicitHidden, &m.SortOrder, &m.Valid, &m.Error, &m.NotBefore, &m.NotAfter, &m.LastChecked, &m.CertificateDomains, &m.AlertNotified, &m.AlertNotifyCount, &m.DomainExcluded); e != nil {
			return nil, e
		}
		recordName := m.Host
		m.Host = cloudflareName(m.Host, m.Domain)
		m.Filtered = matchesPersonalFilter(recordName, nameFilter) || matchesPersonalFilter(m.Host, nameFilter) || matchesPersonalFilter(m.Value, valueFilter)
		m.Hidden = m.ExplicitHidden || m.Filtered || m.DomainExcluded
		if m.NotAfter != "" {
			if expires, parseErr := time.Parse(time.RFC3339, m.NotAfter); parseErr == nil {
				m.DaysRemaining = certificateDaysRemaining(expires)
			}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func matchesPersonalFilter(value, filters string) bool {
	value = strings.ToLower(value)
	for _, term := range strings.FieldsFunc(filters, func(r rune) bool { return r == '\n' || r == '\r' }) {
		term = strings.TrimSpace(strings.ToLower(term))
		if term != "" && strings.Contains(value, term) {
			return true
		}
	}
	return false
}

func (a *app) listHTTPSExcludedDomains(w http.ResponseWriter, r *http.Request) {
	rows, e := a.db.Query("SELECT domain_id FROM https_domain_exclusions WHERE user_id=? ORDER BY domain_id", current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var id int64
		if e = rows.Scan(&id); e != nil {
			fail(w, 500, e.Error())
			return
		}
		ids = append(ids, id)
	}
	jsonOut(w, 200, ids)
}

func (a *app) saveHTTPSExcludedDomains(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs []int64 `json:"ids"`
	}
	if !decode(w, r, &in) {
		return
	}
	tx, e := a.db.Begin()
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer tx.Rollback()
	if _, e = tx.Exec("DELETE FROM https_domain_exclusions WHERE user_id=?", current(r).ID); e != nil {
		fail(w, 500, e.Error())
		return
	}
	seen := map[int64]bool{}
	for _, id := range in.IDs {
		if id < 1 || seen[id] {
			continue
		}
		seen[id] = true
		if _, e = tx.Exec("INSERT INTO https_domain_exclusions(user_id,domain_id) SELECT ?,id FROM domains WHERE id=? AND user_id=?", current(r).ID, id, current(r).ID); e != nil {
			fail(w, 500, e.Error())
			return
		}
	}
	if e = tx.Commit(); e != nil {
		fail(w, 500, e.Error())
		return
	}
	w.WriteHeader(204)
}

func (a *app) listHTTPSMonitors(w http.ResponseWriter, r *http.Request) {
	items, e := a.listMonitorData(current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	jsonOut(w, 200, items)
}
func (a *app) updateHTTPSMonitor(w http.ResponseWriter, r *http.Request) {
	if !a.ownsMonitorRecord(current(r).ID, r.PathValue("id")) {
		fail(w, 404, "监控记录不存在")
		return
	}
	var in struct {
		Port   int    `json:"port"`
		Note   string `json:"note"`
		Hidden bool   `json:"hidden"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Port < 1 || in.Port > 65535 {
		fail(w, 400, "端口必须在 1 到 65535 之间")
		return
	}
	_, e := a.db.Exec(`INSERT INTO https_monitor_preferences(user_id,record_id,port,note,hidden)VALUES(?,?,?,?,?) ON CONFLICT(user_id,record_id)DO UPDATE SET port=excluded.port,note=excluded.note,hidden=excluded.hidden`, current(r).ID, r.PathValue("id"), in.Port, in.Note, in.Hidden)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	w.WriteHeader(204)
}
func (a *app) orderHTTPSMonitors(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs []int64 `json:"ids"`
	}
	if !decode(w, r, &in) {
		return
	}
	tx, e := a.db.Begin()
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer tx.Rollback()
	for order, id := range in.IDs {
		var owned int
		if tx.QueryRow("SELECT 1 FROM records r JOIN domains d ON d.id=r.domain_id WHERE r.id=? AND d.user_id=?", id, current(r).ID).Scan(&owned) != nil {
			fail(w, 400, "排序包含不属于当前用户的记录")
			return
		}
		_, e = tx.Exec(`INSERT INTO https_monitor_preferences(user_id,record_id,sort_order)VALUES(?,?,?) ON CONFLICT(user_id,record_id)DO UPDATE SET sort_order=excluded.sort_order`, current(r).ID, id, order)
		if e != nil {
			fail(w, 500, e.Error())
			return
		}
	}
	if e = tx.Commit(); e != nil {
		fail(w, 500, e.Error())
		return
	}
	w.WriteHeader(204)
}

func (a *app) ownsMonitorRecord(userID int64, recordID string) bool {
	var found int
	return a.db.QueryRow("SELECT 1 FROM records r JOIN domains d ON d.id=r.domain_id WHERE r.id=? AND d.user_id=?", recordID, userID).Scan(&found) == nil
}

func checkTLS(m httpsMonitor) httpsMonitor {
	m.Valid = false
	m.Error = ""
	m.NotBefore = ""
	m.NotAfter = ""
	m.LastChecked = time.Now().Format(time.RFC3339)
	address := net.JoinHostPort(m.Host, strconv.Itoa(m.Port))
	conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}, "tcp", address, &tls.Config{ServerName: m.Host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if e != nil {
		m.Error = e.Error()
		return m
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		m.Error = "服务未返回证书"
		return m
	}
	cert := certs[0]
	certificateDomains := cert.DNSNames
	if len(certificateDomains) == 0 && cert.Subject.CommonName != "" {
		certificateDomains = []string{cert.Subject.CommonName}
	}
	m.CertificateDomains = strings.Join(certificateDomains, ", ")
	if m.CertificateDomains == "" {
		m.CertificateDomains = "（证书未声明 DNS 域名）"
	}
	m.NotBefore = cert.NotBefore.Format(time.RFC3339)
	m.NotAfter = cert.NotAfter.Format(time.RFC3339)
	m.DaysRemaining = certificateDaysRemaining(cert.NotAfter)
	if time.Now().Before(cert.NotBefore) {
		m.Error = "证书尚未生效"
	} else if time.Now().After(cert.NotAfter) {
		expiredDays := int(math.Ceil(time.Since(cert.NotAfter).Hours() / 24))
		if expiredDays < 1 {
			expiredDays = 1
		}
		m.Error = fmt.Sprintf("证书域名 %s 已过期 %d 天", m.CertificateDomains, expiredDays)
	} else {
		intermediates := x509.NewCertPool()
		for _, intermediate := range certs[1:] {
			intermediates.AddCert(intermediate)
		}
		if _, e = cert.Verify(x509.VerifyOptions{DNSName: m.Host, Intermediates: intermediates}); e != nil {
			m.Error = "证书链验证失败：" + e.Error()
		} else {
			m.Valid = true
		}
	}
	return m
}

func certificateDaysRemaining(expires time.Time) int {
	return int(math.Ceil(time.Until(expires).Hours() / 24))
}

func (a *app) saveMonitorResult(userID int64, m httpsMonitor) {
	_, e := a.db.Exec(`INSERT INTO https_monitor_preferences(user_id,record_id,last_valid,last_error,not_before,not_after,last_checked,certificate_domains) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(user_id,record_id) DO UPDATE SET last_valid=excluded.last_valid,last_error=excluded.last_error,not_before=excluded.not_before,not_after=excluded.not_after,last_checked=excluded.last_checked,certificate_domains=excluded.certificate_domains`, userID, m.ID, m.Valid, m.Error, m.NotBefore, m.NotAfter, m.LastChecked, m.CertificateDomains)
	if e != nil {
		log.Printf("save HTTPS monitor result failed: %v", e)
	}
}

func (a *app) setMonitorAlertCount(userID, recordID int64, count int) {
	if _, e := a.db.Exec("UPDATE https_monitor_preferences SET alert_notify_count=?,alert_notified=? WHERE user_id=? AND record_id=?", count, count > 0, userID, recordID); e != nil {
		log.Printf("save HTTPS alert state failed: %v", e)
	}
}

type monitorRecipient struct {
	ID                                          int64
	Email, Bark, BarkBody, QuietStart, QuietEnd string
	AlertLimit                                  int
}

func (a *app) monitorRecipient(userID int64) (monitorRecipient, error) {
	var recipient monitorRecipient
	e := a.db.QueryRow("SELECT id,email,COALESCE(bark_url,''),COALESCE(bark_body,''),COALESCE(https_quiet_start,''),COALESCE(https_quiet_end,''),COALESCE(https_alert_limit,1) FROM users WHERE id=?", userID).Scan(&recipient.ID, &recipient.Email, &recipient.Bark, &recipient.BarkBody, &recipient.QuietStart, &recipient.QuietEnd, &recipient.AlertLimit)
	return recipient, e
}

func (a *app) notifyMonitorResult(recipient monitorRecipient, result *httpsMonitor) {
	if result.Valid && result.DaysRemaining > 15 {
		if result.AlertNotifyCount > 0 {
			a.setMonitorAlertCount(recipient.ID, result.ID, 0)
			result.AlertNotified = false
			result.AlertNotifyCount = 0
		}
		return
	}
	shouldAlert := !result.Valid || (result.Valid && result.DaysRemaining <= 5)
	if !shouldAlert || result.AlertNotifyCount >= recipient.AlertLimit {
		return
	}
	body := fmt.Sprintf("%s:%d HTTPS 检测失败：%s", result.Host, result.Port, result.Error)
	if result.Valid {
		result.Error = fmt.Sprintf("证书域名 %s 即将到期，仅剩 %d 天（有效至 %s）", result.CertificateDomains, result.DaysRemaining, result.NotAfter)
		body = fmt.Sprintf("%s:%d %s", result.Host, result.Port, result.Error)
	}
	configured := false
	delivered := true
	if a.setting("smtp_verified") == "true" && recipient.Email != "" {
		configured = true
		if e := a.sendMail(recipient.Email, "DNS Panel HTTPS 告警", body); e != nil {
			log.Printf("monitor email failed: %v", e)
			delivered = false
		}
	}
	if recipient.Bark != "" {
		configured = true
		if e := sendBark(recipient.Bark, recipient.BarkBody, *result, body); e != nil {
			log.Printf("bark notification failed: %v", e)
			delivered = false
		}
	}
	if configured && delivered {
		result.AlertNotifyCount++
		a.setMonitorAlertCount(recipient.ID, result.ID, result.AlertNotifyCount)
		result.AlertNotified = true
	}
}

func (a *app) checkHTTPSMonitors(w http.ResponseWriter, r *http.Request) {
	items, e := a.listMonitorData(current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	recipient, recipientErr := a.monitorRecipient(current(r).ID)
	for i := range items {
		if items[i].Hidden {
			items[i].Skipped = true
			continue
		}
		items[i] = checkTLS(items[i])
		a.saveMonitorResult(current(r).ID, items[i])
		if recipientErr == nil {
			a.notifyMonitorResult(recipient, &items[i])
		}
	}
	jsonOut(w, 200, items)
}

func (a *app) checkHTTPSMonitor(w http.ResponseWriter, r *http.Request) {
	items, e := a.listMonitorData(current(r).ID)
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	wantedID, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if e != nil {
		fail(w, 400, "监控记录 ID 无效")
		return
	}
	for _, item := range items {
		if item.ID != wantedID {
			continue
		}
		if item.Hidden {
			fail(w, 409, "该记录已屏蔽，请取消屏蔽后再检测")
			return
		}
		result := checkTLS(item)
		a.saveMonitorResult(current(r).ID, result)
		if recipient, recipientErr := a.monitorRecipient(current(r).ID); recipientErr == nil {
			a.notifyMonitorResult(recipient, &result)
		}
		jsonOut(w, 200, result)
		return
	}
	fail(w, 404, "监控记录不存在")
}

func (a *app) monitorLoop() {
	a.runMonitorAlerts()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		<-ticker.C
		a.runMonitorAlerts()
	}
}
func (a *app) runMonitorAlerts() {
	rows, e := a.db.Query("SELECT id,email,COALESCE(bark_url,''),COALESCE(bark_body,''),COALESCE(https_quiet_start,''),COALESCE(https_quiet_end,''),COALESCE(https_alert_limit,1) FROM users")
	if e != nil {
		return
	}
	users := []monitorRecipient{}
	for rows.Next() {
		var u monitorRecipient
		rows.Scan(&u.ID, &u.Email, &u.Bark, &u.BarkBody, &u.QuietStart, &u.QuietEnd, &u.AlertLimit)
		users = append(users, u)
	}
	rows.Close()
	for _, u := range users {
		if inQuietHours(time.Now(), u.QuietStart, u.QuietEnd) {
			continue
		}
		items, e := a.listMonitorData(u.ID)
		if e != nil {
			continue
		}
		for _, m := range items {
			if m.Hidden {
				continue
			}
			result := checkTLS(m)
			a.saveMonitorResult(u.ID, result)
			a.notifyMonitorResult(u, &result)
		}
	}
}
func inQuietHours(now time.Time, start, end string) bool {
	if start == "" || end == "" {
		return false
	}
	parse := func(value string) (int, bool) {
		parsed, e := time.Parse("15:04", value)
		return parsed.Hour()*60 + parsed.Minute(), e == nil
	}
	startMinute, startOK := parse(start)
	endMinute, endOK := parse(end)
	if !startOK || !endOK || startMinute == endMinute {
		return false
	}
	nowMinute := now.Hour()*60 + now.Minute()
	if startMinute < endMinute {
		return nowMinute >= startMinute && nowMinute < endMinute
	}
	return nowMinute >= startMinute || nowMinute < endMinute
}

func sendBark(endpoint, template string, monitor httpsMonitor, body string) error {
	parsed, e := url.Parse(endpoint)
	if e != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("Bark URL 无效")
	}
	payload := []byte(template)
	if strings.TrimSpace(template) == "" {
		payload, _ = json.Marshal(map[string]any{"title": "DNS Panel HTTPS 告警", "body": body, "group": "DNS Panel"})
	} else {
		replacements := map[string]string{"{{title}}": "DNS Panel HTTPS 告警", "{{body}}": body, "{{host}}": monitor.Host, "{{port}}": strconv.Itoa(monitor.Port), "{{error}}": monitor.Error}
		for key, value := range replacements {
			encoded, _ := json.Marshal(value)
			escaped := strings.Trim(string(encoded), "\"")
			payload = []byte(strings.ReplaceAll(string(payload), key, escaped))
		}
		if !json.Valid(payload) {
			return fmt.Errorf("Bark POST 内容不是有效 JSON")
		}
	}
	req, e := http.NewRequest("POST", endpoint, bytes.NewReader(payload))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, e := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Bark HTTP %d", resp.StatusCode)
	}
	return nil
}

func (a *app) testBark(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL  string `json:"url"`
		Body string `json:"body"`
	}
	if !decode(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.URL) == "" {
		fail(w, 400, "请先填写 Bark Webhook URL")
		return
	}
	monitor := httpsMonitor{Host: "test.example.com", Type: "A", Value: "192.0.2.1", Port: 443, Error: "这是一条测试通知"}
	if e := sendBark(in.URL, in.Body, monitor, "DNS Panel Bark 连通测试成功"); e != nil {
		fail(w, 502, "Bark 测试失败："+e.Error())
		return
	}
	jsonOut(w, 200, map[string]any{"message": "Bark 测试通知已发送"})
}

func (a *app) settings(w http.ResponseWriter, r *http.Request) {
	rows, e := a.db.Query("SELECT key,value FROM settings")
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		if k == "smtp_password" && v != "" {
			v = "********"
		}
		out[k] = v
	}
	jsonOut(w, 200, out)
}
func (a *app) saveSettings(w http.ResponseWriter, r *http.Request) {
	var v map[string]string
	if !decode(w, r, &v) {
		return
	}
	if raw, ok := v["password_min_length"]; ok {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 0 || n > 128 {
			fail(w, 400, "密码长度必须是 0 到 128 之间的整数")
			return
		}
	}
	if raw, ok := v["notification_duration"]; ok && raw != "3" && raw != "5" && raw != "manual" {
		fail(w, 400, "通知显示时间无效")
		return
	}
	if v["require_mfa"] == "true" && a.setting("require_mfa") != "true" && a.setting("smtp_verified") != "true" {
		fail(w, 400, "启用强制二次认证前必须保存 SMTP 设置并通过连接测试")
		return
	}
	if v["email_verification"] == "true" && a.setting("email_verification") != "true" && a.setting("smtp_verified") != "true" {
		fail(w, 400, "启用邮箱修改验证前必须保存 SMTP 设置并通过连接测试")
		return
	}
	if v["registration_enabled"] == "true" && a.setting("registration_enabled") != "true" && a.setting("smtp_verified") != "true" {
		fail(w, 400, "开放注册前必须保存 SMTP 设置并通过连接测试")
		return
	}
	allowed := map[string]bool{"registration_enabled": true, "email_verification": true, "require_mfa": true, "login_notification": true, "password_min_length": true, "password_require_number": true, "password_require_uppercase": true, "password_require_lowercase": true, "password_require_symbol": true, "notification_duration": true, "default_record_types": true, "smtp_host": true, "smtp_port": true, "smtp_username": true, "smtp_password": true, "smtp_from": true, "site_url": true, "passkey_rp_id": true, "passkey_origins": true}
	var pendingWebAuthn *webauthn.WebAuthn
	if raw, changed := v["site_url"]; changed && strings.TrimSpace(raw) != "" {
		_, rpID, origin, configErr := parseSiteURL(raw)
		if configErr != nil {
			fail(w, 400, configErr.Error())
			return
		}
		pendingWebAuthn, configErr = buildWebAuthn(rpID, origin)
		if configErr != nil {
			fail(w, 400, "站点 URL 无法用于 Passkey："+configErr.Error())
			return
		}
	} else if _, rpChanged := v["passkey_rp_id"]; rpChanged || v["passkey_origins"] != "" {
		rpID := strings.TrimSpace(v["passkey_rp_id"])
		if rpID == "" {
			rpID = env("PASSKEY_RP_ID", "localhost")
		}
		origins := strings.TrimSpace(v["passkey_origins"])
		if origins == "" {
			origins = env("PASSKEY_ORIGINS", "http://localhost:8080")
		}
		var configErr error
		pendingWebAuthn, configErr = buildWebAuthn(rpID, origins)
		if configErr != nil {
			fail(w, 400, "Passkey 域名配置无效："+configErr.Error())
			return
		}
	}
	smtpChanged := false
	for _, k := range []string{"smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_from"} {
		if x, ok := v[k]; ok && !(k == "smtp_password" && x == "********") && x != a.setting(k) {
			smtpChanged = true
		}
	}
	tx, e := a.db.Begin()
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	defer tx.Rollback()
	for k, x := range v {
		if !allowed[k] || (k == "smtp_password" && x == "********") {
			continue
		}
		if _, e = tx.Exec("INSERT INTO settings VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", k, x); e != nil {
			fail(w, 500, e.Error())
			return
		}
	}
	if smtpChanged {
		_, e = tx.Exec("INSERT INTO settings(key,value)VALUES('smtp_verified','false') ON CONFLICT(key)DO UPDATE SET value='false'")
		if e == nil {
			_, e = tx.Exec("INSERT INTO settings(key,value)VALUES('require_mfa','false') ON CONFLICT(key)DO UPDATE SET value='false'")
		}
	}
	if e = tx.Commit(); e != nil {
		fail(w, 500, e.Error())
		return
	}
	if pendingWebAuthn != nil {
		a.webauthn = pendingWebAuthn
	}
	w.WriteHeader(204)
}
func (a *app) setting(k string) string {
	var v string
	a.db.QueryRow("SELECT value FROM settings WHERE key=?", k).Scan(&v)
	return v
}

func (a *app) configureWebAuthn() error {
	originsValue, rpID, e := a.passkeySiteConfig()
	if e != nil {
		return e
	}
	configured, e := buildWebAuthn(rpID, originsValue)
	if e == nil {
		a.webauthn = configured
	}
	return e
}

func (a *app) passkeySiteConfig() (origin, rpID string, err error) {
	if siteURL := strings.TrimSpace(a.setting("site_url")); siteURL != "" {
		_, rpID, origin, err = parseSiteURL(siteURL)
		return
	}
	rpID = strings.TrimSpace(a.setting("passkey_rp_id"))
	if rpID == "" {
		rpID = env("PASSKEY_RP_ID", "localhost")
	}
	origin = strings.TrimSpace(a.setting("passkey_origins"))
	if origin == "" {
		origin = env("PASSKEY_ORIGINS", "http://localhost:8080")
	}
	return
}

func parseSiteURL(raw string) (normalized, rpID, origin string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", "", "", fmt.Errorf("站点 URL 必须是完整的 http(s) 地址，且不能包含路径、参数或片段")
	}
	if u.Hostname() == "" {
		return "", "", "", fmt.Errorf("站点 URL 缺少有效域名")
	}
	origin = u.Scheme + "://" + u.Host
	return origin, u.Hostname(), origin, nil
}

func buildWebAuthn(rpID, originsValue string) (*webauthn.WebAuthn, error) {
	origins := []string{}
	for _, origin := range strings.Split(originsValue, ",") {
		if origin = strings.TrimSpace(origin); origin != "" {
			origins = append(origins, origin)
		}
	}
	if len(origins) == 0 {
		return nil, fmt.Errorf("Passkey Origin 不能为空")
	}
	return webauthn.New(&webauthn.Config{RPID: rpID, RPDisplayName: "DNS Panel", RPOrigins: origins})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	if d.Decode(v) != nil {
		fail(w, 400, "JSON 请求无效")
		return false
	}
	return true
}
func jsonOut(w http.ResponseWriter, s int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(s)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, s int, m string) { jsonOut(w, s, map[string]string{"error": m}) }
func result(w http.ResponseWriter, res sql.Result, e error) {
	if e != nil {
		fail(w, 500, e.Error())
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		fail(w, 404, "对象不存在")
		return
	}
	w.WriteHeader(204)
}
func token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func validProvider(v string) bool { return v == "cloudflare" || v == "aliyun" || v == "tencent" }
func validType(v string) bool {
	for _, x := range []string{"A", "AAAA", "CNAME", "TXT", "MX", "CAA", "SRV"} {
		if v == x {
			return true
		}
	}
	return false
}
func headers(n http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		n.ServeHTTP(w, r)
	})
}
