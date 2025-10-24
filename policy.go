package quiltro

type Policy struct {
	ID    uint   `gorm:"primaryKey" json:"id"`
	Ptype string `gorm:"size:100;not null" json:"ptype"`
	V0    string `gorm:"size:100;not null" json:"v0"`
	V1    string `gorm:"size:100;not null" json:"v1"`
	V2    string `gorm:"size:100;not null" json:"v2"`
	V3    string `gorm:"size:100;not null" json:"v3"`
	V4    string `gorm:"size:100;not null" json:"v4"`
	V5    string `gorm:"size:100;not null" json:"v5"`
}

func (Policy) TableName() string {
	return "casbin_rule"
}
