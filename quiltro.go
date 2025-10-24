package quiltro

import (
	"gorm.io/gorm"
	"reflect"
	"strings"
)

var (
	db *gorm.DB
	subjectId string
)

func Init(gormDb *gorm.DB, s interface{}) {
	db = gormDb
	initCasbin()
	dataType := reflect.TypeOf(s)

	if dataType.Kind() == reflect.Struct {
		structName := dataType.Name()
		subjectId = strings.ToLower(structName) + "ID"
	}
}
