//go:build !windows
// +build !windows
package main

import (
    "log"
    "os"
    "os/exec"
    "syscall"  
)

func runAsDaemon() {
    if os.Getppid() != 1 {
        cmd := exec.Command(os.Args[0], os.Args[1:]...)
        cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
        cmd.Stdout, cmd.Stderr, cmd.Stdin = nil, nil, nil
        
        cmd.Env = os.Environ()
        err := cmd.Start()
        if err != nil {
            log.Fatalf("后台运行失败: %v", err)
        }
        os.Exit(0)
    }
}
