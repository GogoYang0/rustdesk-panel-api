// Package settings 本文件：frontend 公开三键（设计事实④，M3 T07）。
//
// GET /api/settings/frontend 为 Public，仅回 {watermarkEnabled,
// defaultLanguage, webauthnEnabled}——不得泄露任何敏感键。
package settings

import (
	"context"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
)

// FrontendService 前端公开设置读取。
type FrontendService struct {
	general *GeneralService
}

// NewFrontendService 构建服务（复用 general 的类型化读取与缺省回退）。
func NewFrontendService(general *GeneralService) *FrontendService {
	return &FrontendService{general: general}
}

// Get 读取公开三键。
func (s *FrontendService) Get(ctx context.Context) (dto.FrontendSettingsView, error) {
	watermark, err := s.general.store.GetBool(ctx, KeyGeneralWatermarkEnabled, defaultWatermarkEnabled)
	if err != nil {
		return dto.FrontendSettingsView{}, err
	}
	language, err := s.general.store.GetString(ctx, KeyGeneralDefaultLanguage, defaultLanguage)
	if err != nil {
		return dto.FrontendSettingsView{}, err
	}
	webauthnEnabled, err := s.general.store.GetBool(ctx, KeyGeneralWebauthnEnabled, defaultWebauthnEnabled)
	if err != nil {
		return dto.FrontendSettingsView{}, err
	}
	return dto.FrontendSettingsView{
		WatermarkEnabled: watermark,
		DefaultLanguage:  language,
		WebauthnEnabled:  webauthnEnabled,
	}, nil
}
