//go:build !windows  
// +build !windows  
  
package main

import (  
    "fmt"  
)
  
func printHelp() {  
    colorText := func(color int, message string) string {  
        return fmt.Sprintf("\x1b[1;%dm%s\x1b[0m", color, message)  
    }  
      
    // Unix 系统使用彩色输出  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-p"), colorText(34, "[端口号]"), "监听指定端口号")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-d"), colorText(34, "[文件路径]"), "指定本地数据存放的目录路径，默认当前程序路径的./short_data文件夹")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-db"), colorText(34, "[文件路径]"), "指定IP地址库离线数据存放的目录路径，默认/tmp文件夹")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-log"), colorText(34, "[文件路径]"), "启用日志，并指定日志存放的目录路径")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-admin"), "", "启用管理页面管理短链数据，网页路径/admin")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-e"), colorText(34, "[邮箱地址]"), "指定邮箱地址，修改页面的联系邮箱地址")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-u"), colorText(34, "[账户名]"), "指定管理页面的登陆账户名")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-w"), colorText(34, "[密码]"), "指定管理页面的登陆密码")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-daemon"), "", "以后台模式运行")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-redis-addr"), colorText(34, "[地址:端口]"), "Redis服务器地址 (例如: localhost:6379)")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-redis-user"), colorText(34, "[用户名]"), "Redis用户名 (可选)")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-redis-pass"), colorText(34, "[密码]"), "Redis密码 (可选)")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-redis-pre"), colorText(34, "[前缀]"), "Redis数据前缀，默认为short，连接相同的redis数据库时用于区分不同应用")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-v"), "", "版本号")  
    fmt.Printf("  %-20s %-15s %s\n", colorText(36, "-h"), "", "帮助信息")  
}
