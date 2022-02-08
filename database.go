package main

import (
	"sync"

	sql "github.com/FloatTech/sqlite"
)

var (
	db   = &sql.Sqlite{DBPath: "md5.db"}
	dbmu sync.RWMutex
)

type filemd5 struct {
	Name string `db:"name"`
	Md5  string `db:"md5"`
}

func init() {
	err := db.Open()
	if err != nil {
		panic(err)
	}
}
