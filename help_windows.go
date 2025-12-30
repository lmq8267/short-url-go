//go:build windows  
// +build windows  
  
package main

import (  
    "fmt"  
)
  
func printHelp() {  
    // Windows 不使用彩色输出  
    fmt.Printf("  %-20s %-15s %s\n", "-p", "[端口号]", "监听指定端口号")  
    fmt.Printf("  %-20s %-15s %s\n", "-d", "[文件路径]", "指定本地数据存放的目录路径，默认当前程序路径的./short_data文件夹")  
    fmt.Printf("  %-20s %-15s %s\n", "-db", "[文件路径]", "指定IP地址库离线数据存放的目录路径，默认当前程序路径的./ip_data文件夹")  
    fmt.Printf("  %-20s %-15s %s\n", "-log", "[文件路径]", "启用日志，并指定日志存放的目录路径")  
    fmt.Printf("  %-20s %-15s %s\n", "-admin", "", "启用管理页面管理短链数据，网页路径/admin")  
    fmt.Printf("  %-20s %-15s %s\n", "-e", "[邮箱地址]", "指定邮箱地址，修改页面的联系邮箱地址")  
    fmt.Printf("  %-20s %-15s %s\n", "-u", "[账户名]", "指定管理页面的登陆账户名")  
    fmt.Printf("  %-20s %-15s %s\n", "-w", "[密码]", "指定管理页面的登陆密码")  
    fmt.Printf("  %-20s %-15s %s\n", "-daemon", "", "以后台模式运行")  
    fmt.Printf("  %-20s %-15s %s\n", "-redis-addr", "[地址:端口]", "Redis服务器地址 (例如: localhost:6379)")  
    fmt.Printf("  %-20s %-15s %s\n", "-redis-user", "[用户名]", "Redis用户名 (可选)")  
    fmt.Printf("  %-20s %-15s %s\n", "-redis-pass", "[密码]", "Redis密码 (可选)")  
    fmt.Printf("  %-20s %-15s %s\n", "-redis-pre", "[前缀]", "Redis数据前缀，默认为short，连接相同的redis数据库时用于区分不同应用")  
    fmt.Printf("  %-20s %-15s %s\n", "-v", "", "版本号")  
    fmt.Printf("  %-20s %-15s %s\n", "-h", "", "帮助信息")  
}
