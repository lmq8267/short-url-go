//go:build windows
// +build windows
package main

import (  
    "log"
    "os"
    "os/exec"
) 

func runAsDaemon() {
    cmd := exec.Command(os.Args[0], os.Args[1:]...)
    cmd.Env = os.Environ()
    err := cmd.Start()
    if err != nil {
        log.Fatalf("后台运行失败: %v", err)
    }
    os.Exit(0)
}
