package quiltro

import (
	"fmt"
	"time"

	"github.com/casbin/casbin/v2"
	"gorm.io/gorm"
)

// Config holds all configuration required to initialize a Quiltro instance.
type Config struct {
	DB         *gorm.DB
	CasbinConf string        // path to a Casbin model .conf file
	JWTSecret  []byte        // HMAC secret for signing tokens
	JWTExpiry  time.Duration // defaults to 24h if zero
	SubjectKey string        // Gin context key for the subject ID; defaults to "subjectID"
}

// Quiltro provides JWT-based authentication and Casbin authorization for Gin applications.
type Quiltro struct {
	db         *gorm.DB
	enforcer   *casbin.Enforcer
	jwtKey     []byte
	jwtExpiry  time.Duration
	subjectKey string
}

// New creates a Quiltro instance, initializing the Casbin enforcer backed by the given DB.
func New(cfg Config) (*Quiltro, error) {
	fmt.Println("Initializing Quiltro with config:", cfg)
	if cfg.DB == nil {
		return nil, fmt.Errorf("quiltro: DB is required")
	}
	if len(cfg.JWTSecret) == 0 {
		return nil, fmt.Errorf("quiltro: JWTSecret is required")
	}
	if cfg.CasbinConf == "" {
		return nil, fmt.Errorf("quiltro: CasbinConf path is required")
	}

	expiry := cfg.JWTExpiry
	if expiry == 0 {
		expiry = 24 * time.Hour
	}
	subKey := cfg.SubjectKey
	if subKey == "" {
		subKey = "subjectID"
	}

	q := &Quiltro{
		db:         cfg.DB,
		jwtKey:     cfg.JWTSecret,
		jwtExpiry:  expiry,
		subjectKey: subKey,
	}

	if err := q.initCasbin(cfg.CasbinConf); err != nil {
		return nil, fmt.Errorf("quiltro: %w", err)
	}

	return q, nil
}
