package database

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/meili-NG/meiliNG/v2/internal/models"
	"github.com/meili-NG/meiliNG/v2/internal/types"
	"github.com/meili-NG/meiliNG/v2/internal/utils"
	"gorm.io/gorm"
)

type SignInLog struct {
	models.SignInLogFields `gorm:"embedded"`

	// Relations
	User *User `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

func (s *SignInLog) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}

	if s.SignedInAt.IsZero() {
		s.SignedInAt = time.Now()
	}

	return nil
}

func NewSignInLog(tid, userID uuid.UUID, c *fiber.Ctx) *SignInLog {
	return &SignInLog{
		SignInLogFields: models.SignInLogFields{
			UserID:     userID,
			IP:         c.IP(),
			UserAgent:  c.Get("User-Agent"),
			SessionID:  tid,
			SignedInAt: time.Now(),
		},
	}
}

func (s *SignInLog) Serialize() types.SignInLogSerialized {
	return utils.TransferJSONData[*SignInLog, types.SignInLogSerialized](s)
}
