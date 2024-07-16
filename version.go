package main

import (
    "time"
)


var Version string

func init() {
    // 在程序初始化时设置版本号为编译时的日期，东八区时间
    now := time.Now().UTC().Add(time.Hour * 8)
    Version = now.Format("2006-01-02")
}
