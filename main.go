package main

import (
    "embed"
    "encoding/json"
    "flag"
    "io/fs"
    "io/ioutil"
    "log"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "strconv"
    "syscall"
    "runtime"
    "fmt"
    "time"
    "strings"
    "net/url"
    "math/rand"
)

//go:embed static/*
var content embed.FS
var dataDir string
// 定义API请求的数据结构
type ApiRequest struct {
    LongUrl          string `json:"longUrl"`
    ShortCode        string `json:"shortCode"`
    Password         string `json:"password"`
    ClientIP           string `json:"client_ip"`
    Expiration       string `json:"expiration"`
    BurnAfterReading string `json:"burn_after_reading"`
    Type             string `json:"type"`
    LastUpdate         string `json:"last_update"`
}
// 定义根目录请求的数据结构
type Data struct {
    TotalRules        int    `json:"total_rules"`
    TodayNewRules     int    `json:"today_new_rules"`
    LastRuleUpdate    string `json:"last_rule_update"`
    TotalVisits       int    `json:"total_visits"`
    TodayVisits       int    `json:"today_visits"`
    LastVisitsUpdate  string `json:"last_visits_update"`
    Email             string `json:"email"`
    Img               string `json:"img"`
}

// ApiResponse 是响应体的结构
type ApiResponse struct {
    Type      string `json:"type"`
    ShortURL  string `json:"short_url"`
    URLName   string `json:"URL_NAME"`
}
//配置文件读取修改，数据中获取指定键的字符串
func getStringValue(data map[string]interface{}, key string, defaultValue string) string {
    if value, ok := data[key]; ok {
        if strValue, ok := value.(string); ok {
            return strValue
        }
    }
    return defaultValue
}
//配置文件读取，数据中获取指定键的数值
func getIntValue(data map[string]interface{}, key string, defaultValue int) int {
    if value, ok := data[key]; ok {
        if floatValue, ok := value.(float64); ok {
            return int(floatValue)
        }
    }
    return defaultValue
}
//初始统计数据文件
func initializeData(dataFilePath string) {
    timeFormat := "2006-01-02"
    
    // 设置东八区（北京时间），偏移量为 +8 小时
    cst := time.FixedZone("CST", 8*60*60)
    
    // 获取当前时间并转换为东八区时间
    now := time.Now().In(cst)
    
    // 格式化日期
    today := now.Format(timeFormat)

    initialData := Data{
        TotalRules:       0,
        TodayNewRules:    0,
        LastRuleUpdate:   today,
        TotalVisits:      0,
        TodayVisits:      0,
        LastVisitsUpdate: today,
        Email:            os.Getenv("Email"),
        Img:              "https://pic.rmb.bdstatic.com/bjh/gallery/373e5f5d10577706a529f69cc4997ecd608.jpeg",
    }
    // 如果short_data.json文件不存在则创建
    if _, err := os.Stat(dataFilePath); os.IsNotExist(err) {
        file, err := os.Create(dataFilePath)
        if err != nil {
            log.Fatalf("无法创建统计数据文件: %v", err)
        }
        defer file.Close()

        encoder := json.NewEncoder(file)
        if err := encoder.Encode(initialData); err != nil {
            log.Fatalf("无法写入初始统计数据: %v", err)
        }
    } else {
        // 如果文件存在，检查缺失字段并补充
        file, err := os.OpenFile(dataFilePath, os.O_RDWR, 0644)
        if err != nil {
            log.Fatalf("无法打开统计数据文件: %v", err)
        }
        defer file.Close()

        var rawData map[string]interface{}
        decoder := json.NewDecoder(file)
        if err := decoder.Decode(&rawData); err != nil {
            log.Fatalf("无法解析统计数据文件: %v", err)
        }

        existingData := Data{
            TotalRules:       getIntValue(rawData, "total_rules", initialData.TotalRules),
            TodayNewRules:    getIntValue(rawData, "today_new_rules", initialData.TodayNewRules),
            LastRuleUpdate:   getStringValue(rawData, "last_rule_update", initialData.LastRuleUpdate),
            TotalVisits:      getIntValue(rawData, "total_visits", initialData.TotalVisits),
            TodayVisits:      getIntValue(rawData, "today_visits", initialData.TodayVisits),
            LastVisitsUpdate: getStringValue(rawData, "last_visits_update", initialData.LastVisitsUpdate),
            Img:              getStringValue(rawData, "img", initialData.Img),
            Email:            getStringValue(rawData, "email", initialData.Email),
        }

        if existingData.LastRuleUpdate != today {
            existingData.LastRuleUpdate = today
            existingData.TodayNewRules = 0
        }
        if existingData.LastVisitsUpdate != today {
            existingData.LastVisitsUpdate = today
            existingData.TodayVisits = 0
        }
        if os.Getenv("Email") != "" && existingData.Email != os.Getenv("Email") {
            existingData.Email = os.Getenv("Email")
        }
        dataFilePath := filepath.Join(dataDir, "short_data.json")
        // 统计dataDir目录下的.json文件数量
        totalRules := 0
        err = filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
            if err != nil {
                return err
            }
            if !info.IsDir() && filepath.Ext(info.Name()) == ".json" && info.Name() != filepath.Base(dataFilePath) {
                totalRules++
            }
            return nil
        })
        if err != nil {
            log.Fatalf("无法统计.json文件数量: %v", err)
        }
        existingData.TotalRules = totalRules
        
        // 将文件内容截断为0并将更新后的数据写入
        file.Seek(0, 0)
        file.Truncate(0)
        // 创建 JSON 编码器并设置缩进将数据写入文件
        encoder := json.NewEncoder(file)
        encoder.SetIndent("", "  ")
        if err := encoder.Encode(existingData); err != nil {
            log.Fatalf("无法更新统计数据文件: %v", err)
        }
    }
}
//随机生成8位字符的后缀
func generateRandomString(n int) string {
    const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    rand.Seed(time.Now().UnixNano())
    b := make([]byte, n)
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }
    return string(b)
}

// getClientIP 从HTTP请求中获取客户端IP地址
func getClientIP(r *http.Request) string {
    // 从X-Forwarded-For头部获取IP地址（用于代理服务器后的客户端）
    ip := r.Header.Get("X-Forwarded-For")

    // 如果X-Forwarded-For为空或未知，则使用RemoteAddr
    if ip == "" || strings.ToLower(ip) == "unknown" {
        ip = r.RemoteAddr
    } else {
        // X-Forwarded-For可能返回以逗号分隔的多个IP地址
        ips := strings.Split(ip, ",")
        ip = strings.TrimSpace(ips[0]) // 使用列表中的第一个IP地址
    }

    // 如果IP地址包含端口号（IPv4或IPv6），则分割主机和端口
    if strings.Contains(ip, ":") {
        ip, _, _ = net.SplitHostPort(ip)
    }

    return ip
}
// 处理API请求
func apiHandler(w http.ResponseWriter, r *http.Request, dataDir string) {
    var req ApiRequest

    // 解析请求体
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // 如果没有后缀就随机生成8位字符的后缀
    if req.ShortCode == "" {
        req.ShortCode = generateRandomString(8)
    }
    // 不能使用后缀api
    if req.ShortCode == "api" {
        errMsg := map[string]string{"error": "错误！该后缀是api调用，请使用其他后缀。"}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(errMsg)
        return
    }
    // 判断请求里的type的值
    if req.Type == "link" {
        if !strings.HasPrefix(req.LongUrl, "http://") && !strings.HasPrefix(req.LongUrl, "https://") {
            req.LongUrl = "http://" + req.LongUrl
        }
    }
    // 生成文件路径
    filePath := filepath.Join(dataDir, req.ShortCode+".json")

    // 检查文件是否存在
    isNewRule := true
    _, err := os.Stat(filePath)
    if err == nil {
        isNewRule = false

        // 文件存在，检查密码
        existingReq := ApiRequest{}
        fileData, err := ioutil.ReadFile(filePath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        if err := json.Unmarshal(fileData, &existingReq); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // 检查密码是否匹配
        if existingReq.Password != "" && existingReq.Password != req.Password {
            errMsg := map[string]string{"error": "密码错误！该后缀已经被使用，请使用正确的密码修改或使用其他后缀。"}
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusBadRequest)
            json.NewEncoder(w).Encode(errMsg)
            return
        }
    }

    // 更新过期时间
    expirationMinutesStr := req.Expiration
    if expirationMinutesStr != "" {
        expirationMinutes, err := strconv.Atoi(expirationMinutesStr)
        if err != nil {
            http.Error(w, "expiration must be a valid number", http.StatusBadRequest)
            return
        }

        // 手动设置为东八区（上海时区）
loc := time.FixedZone("CST", 8*60*60) // CST: China Standard Time
currentTime := time.Now().In(loc)

        // 添加指定分钟数到当前时间
        expirationTime := currentTime.Add(time.Duration(expirationMinutes) * time.Minute)

        // 更新请求中的expiration字段为格式化后的时间字符串
        req.Expiration = expirationTime.Format("2006-01-02 15:04:05")
    }
    
    // 新增 last_update 参数到请求中
    // 手动设置为东八区（上海时区）
loc := time.FixedZone("CST", 8*60*60) // CST: China Standard Time
lastUpdate := time.Now().In(loc).Format("2006-01-02 15:04:05")
    req.LastUpdate = lastUpdate
    
    // 获取客户端 IP 地址
    clientIP := getClientIP(r) // Assuming getClientIP function retrieves client IP from request 'r'
    req.ClientIP = clientIP 

    // 将更新后的data作为新的请求
    data, err := json.MarshalIndent(req, "", "  ")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // 创建或更新JSON文件
    dir := filepath.Dir(filePath)
    if _, err := os.Stat(dir); os.IsNotExist(err) {
        if err := os.MkdirAll(dir, 0755); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    }

    // 将更新后的data写入文件
    if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    // 如果是新的规则，更新 short_data.json 中的数据
    if isNewRule {
        // 读取 short_data.json 文件
        shortDataPath := filepath.Join(dataDir, "short_data.json")
        shortData, err := ioutil.ReadFile(shortDataPath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // 解析 JSON 数据
        var shortDataMap map[string]interface{}
        if err := json.Unmarshal(shortData, &shortDataMap); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // 获取当前上海时区日期
        loc := time.FixedZone("CST", 8*60*60)
        currentDate := time.Now().In(loc).Format("2006-01-02")

        // 更新 total_rules 和 today_new_rules
        totalRules := getIntValue(shortDataMap, "total_rules", 0)
        todayNewRules := getIntValue(shortDataMap, "today_new_rules", 0)
        lastRuleUpdate := getStringValue(shortDataMap, "last_rule_update", "")

        if lastRuleUpdate != currentDate {
            todayNewRules = 0
        }

        totalRules++
        todayNewRules++

        // 更新 short_data.json 的数据
        shortDataMap["total_rules"] = totalRules
        shortDataMap["today_new_rules"] = todayNewRules
        shortDataMap["last_rule_update"] = currentDate

        // 将更新后的数据写回 short_data.json 文件
        updatedShortData, err := json.MarshalIndent(shortDataMap, "", "  ")
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        if err := ioutil.WriteFile(shortDataPath, updatedShortData, 0644); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
    }
    // 构造返回的URL
    host := r.Host
    shortURL := fmt.Sprintf("http://%s/%s", host, req.ShortCode)

    response := ApiResponse{
        Type:     req.Type,
        ShortURL: shortURL,
        URLName:  req.ShortCode,
    }
    //发送响应
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(response)
}

// 默认首页HTML文件
func indexHandler(w http.ResponseWriter, r *http.Request) {
    // 读取short_data.json统计数据文件
    dataFilePath := filepath.Join(dataDir, "short_data.json")
    initializeData(dataFilePath)
    file, err := os.Open(dataFilePath)
    if err != nil {
        http.Error(w, fmt.Sprintf("无法打开统计数据文件: %v", err), http.StatusInternalServerError)
        return
    }
    defer file.Close()

    // 解析数据
    var data Data
    decoder := json.NewDecoder(file)
    if err := decoder.Decode(&data); err != nil {
        http.Error(w, fmt.Sprintf("无法解析统计数据文件: %v", err), http.StatusInternalServerError)
        return
    }

    // 读取网页文件
    htmlContent, err := fs.ReadFile(content, "static/index.html")
    if err != nil {
        http.Error(w, fmt.Sprintf("无法读取HTML文件: %v", err), http.StatusInternalServerError)
        return
    }

    // 将统计数据的值替换到网页里
    htmlString := string(htmlContent)
    htmlString = strings.ReplaceAll(htmlString, "{{totalRules}}", strconv.Itoa(data.TotalRules))
    htmlString = strings.ReplaceAll(htmlString, "{{todayNewRules}}", strconv.Itoa(data.TodayNewRules))
    htmlString = strings.ReplaceAll(htmlString, "{{totalvisits}}", strconv.Itoa(data.TotalVisits))
    htmlString = strings.ReplaceAll(htmlString, "{{todayvisits}}", strconv.Itoa(data.TodayVisits))
    htmlString = strings.ReplaceAll(htmlString, "修改为你的邮箱", data.Email)
    htmlString = strings.ReplaceAll(htmlString, "my-img.jpeg", data.Img)

    // 将网页数据响应给客户端
    w.Header().Set("Content-Type", "text/html")
    w.Write([]byte(htmlString))
}

// 处理其他请求
func shortHandler(w http.ResponseWriter, r *http.Request, dataDir string) {
    // 获取请求路径并处理
    path := r.URL.Path[1:] // 去掉开头的斜杠

    // 将百分号编码转换为中文字符
    path, err := url.QueryUnescape(path)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // 如果路径为空或者在 dataDir 目录中没有对应的 .json 文件，则重定向到根目录
    filePath := filepath.Join(dataDir, path+".json")
    _, err = os.Stat(filePath)
    if path != "" && err != nil {
        // 文件不存在，重定向到根目录
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }
    // 如果路径为空，则返回
    if path == "" {
        errMsg := map[string]string{"error": "空页面！"}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(errMsg)
        return
    }
    // 读取JSON文件内容
    jsonData, err := ioutil.ReadFile(filePath)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // 解析JSON数据
    var data map[string]interface{}
    if err := json.Unmarshal(jsonData, &data); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // 检查expiration字段
    expirationStr, ok := data["expiration"].(string)
    if ok && expirationStr != "" {
    // 解析expiration时间
    expirationTime, err := time.Parse("2006-01-02 15:04:05", expirationStr)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    // 获取当前上海时区时间
    loc := time.FixedZone("CST", 8*60*60) 
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    now := time.Now().In(loc)

    // 格式化时间为字符串，以便比较
    expirationTimeFormatted := expirationTime.Format("2006-01-02 15:04:05")
    nowFormatted := now.Format("2006-01-02 15:04:05")

    // 比较时间
    if expirationTimeFormatted <= nowFormatted {
        // 如果过期，返回"链接已过期"并删除文件
        err := os.Remove(filePath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        fmt.Fprintf(w, "链接已过期")
        return
    }
    }
    // 解析JSON内容
    var apiRequest ApiRequest
    err = json.Unmarshal(jsonData, &apiRequest)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // 检查 burn_after_reading 的值，如果为 "true" 则删除文件
    if apiRequest.BurnAfterReading == "true" {
        err = os.Remove(filePath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
     }
     // 读取 short_data.json 文件
        shortDataPath := filepath.Join(dataDir, "short_data.json")
        shortData, err := ioutil.ReadFile(shortDataPath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // 解析 JSON 数据
        var shortDataMap map[string]interface{}
        if err := json.Unmarshal(shortData, &shortDataMap); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // 获取当前上海时区日期
        loc := time.FixedZone("CST", 8*60*60)
        currentDate := time.Now().In(loc).Format("2006-01-02")

        // 更新 total_rules 和 today_new_rules
        totalVisits := getIntValue(shortDataMap, "total_visits", 0)
        todayVisits := getIntValue(shortDataMap, "today_visits", 0)
        lastVisitsUpdate := getStringValue(shortDataMap, "last_visits_update", "")

        if lastVisitsUpdate != currentDate {
            todayVisits = 0
        }

        totalVisits++
        todayVisits++

        // 更新 short_data.json 的数据
        shortDataMap["total_visits"] = totalVisits
        shortDataMap["today_visits"] = todayVisits
        shortDataMap["last_visits_update"] = currentDate

        // 将更新后的数据写回 short_data.json 文件
        updatedShortData, err := json.MarshalIndent(shortDataMap, "", "  ")
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        if err := ioutil.WriteFile(shortDataPath, updatedShortData, 0644); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
       // 解析JSON内容
    var apiReq ApiRequest
    err = json.Unmarshal(jsonData, &apiReq)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // 根据type值做相应处理
    switch apiReq.Type {
    case "link":
        http.Redirect(w, r, apiReq.LongUrl, http.StatusFound)
    case "html":
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(apiReq.LongUrl))
    case "text":
        htmlContent, err := content.ReadFile("static/text.html")
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        responseHtml := strings.Replace(string(htmlContent), "{长内容}", apiReq.LongUrl, -1)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(responseHtml))
    default:
        http.Error(w, "Forbidden", http.StatusForbidden)
    }
}

func main() {
    
    var (
        port    int
        daemon  bool
        showHelp bool
        showVersion bool
        email   string
    )

    // 使用flag包解析命令行参数
    flag.IntVar(&port, "p", 8080, "监听端口")
    flag.StringVar(&dataDir, "d", "", "指定数据存放目录路径")
    flag.BoolVar(&daemon, "f", false, "后台运行")
    flag.StringVar(&email, "e", "请修改为你的邮箱", "指定邮箱")
    flag.BoolVar(&showHelp, "h", false, "帮助信息")
    flag.BoolVar(&showHelp, "help", false, "帮助信息")
    flag.BoolVar(&showVersion, "v", false, "版本号")
    flag.BoolVar(&showVersion, "version", false, "版本号")
    flag.Parse()
    
    //打印帮助信息
    if showHelp {
       // 添加颜色的打印函数
	colorPrint := func(color int, message string) {
		fmt.Printf("\x1b[1;%dm%s\x1b[0m", color, message)
	}

	fmt.Printf("\nUsage: \n\n")
	fmt.Printf("  %s ", os.Args[0])
	colorPrint(36, fmt.Sprintf("-p "))
	colorPrint(34, fmt.Sprintf("[端口号]"))
	fmt.Println(" 监听指定端口号")
	
	fmt.Printf("  %s ", os.Args[0])
	colorPrint(36, fmt.Sprintf("-d "))
	colorPrint(34, fmt.Sprintf("[文件路径]"))
	fmt.Println(" 指定数据存放的目录路径，默认当前程序路径的./short_data文件夹")
	
	fmt.Printf("  %s ", os.Args[0])
	colorPrint(36, fmt.Sprintf("-e "))
	colorPrint(34, fmt.Sprintf("[邮箱地址]"))
	fmt.Println(" 指定邮箱地址，修改页面的邮箱地址")

	fmt.Printf("  %s ", os.Args[0])
	colorPrint(36, fmt.Sprintf("-f "))
	fmt.Println(" 后台运行,此模式下请加-d 参数指定数据路径文件夹")

	fmt.Printf("  %s ", os.Args[0])
	colorPrint(36, fmt.Sprintf("-v "))
	fmt.Println(" 版本号")
	
	
	fmt.Printf("  %s ", os.Args[0])
	colorPrint(36, fmt.Sprintf("-h "))
	fmt.Println(" 帮助信息")
	
       return
   }
    
    //打印版本信息
    if showVersion {
       fmt.Println("Version:", Version)
       fmt.Println("Go Version:", runtime.Version())
       return
    }

    if email != "" {
		os.Setenv("Email", email)
    }
    // 获取当前二进制文件的目录并设为数据存放目录的/short_data子目录
    if dataDir == "" {
        exePath, err := filepath.Abs(os.Args[0])
        if err != nil {
            log.Fatalf("无法获取当前二进制文件的路径: %v", err)
        }
        dataDir = filepath.Join(filepath.Dir(exePath), "short_data")
    }

    // 创建数据存放目录（如果不存在）
    if _, err := os.Stat(dataDir); os.IsNotExist(err) {
        if err := os.MkdirAll(dataDir, 0755); err != nil {
            log.Fatalf("无法创建数据目录: %v", err)
        }
    }
    
    //初始统计数据文件
    dataFilePath := filepath.Join(dataDir, "short_data.json")
    initializeData(dataFilePath)
    
    // 后台运行
    if daemon {
    // 复制命令行参数
    args := append([]string(nil), os.Args[1:]...)

    // 设置 umask
    syscall.Umask(0)

    // 创建新进程
    attr := &syscall.ProcAttr{
        Dir:   "",
        Env:   os.Environ(),
        Files: []uintptr{uintptr(syscall.Stdin), uintptr(syscall.Stdout), uintptr(syscall.Stderr)},
        Sys: &syscall.SysProcAttr{
            Setsid: true,
        },
    }
    pid, err := syscall.ForkExec(os.Args[0], args, attr)
    if err != nil {
        log.Fatalf("无法启动后台进程: %v", err)
    }
    log.Printf("后台进程启动成功，PID: %d", pid)
    os.Exit(0)
}
    
    // 设置http请求处理程序
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path == "/api" {
        // 处理/api
        apiHandler(w, r, dataDir)
    } else if r.URL.Path == "/" {
        // 处理主页
        indexHandler(w, r)
    } else {
        // 处理其他后缀
        shortHandler(w, r, dataDir)
    }
    })
    
    // 组合地址和端口
    addr := net.JoinHostPort("", strconv.Itoa(port))

    // 创建监听器，支持端口重用和双栈
    ln, err := net.Listen("tcp", addr)
    if err != nil {
        log.Fatalf("无法监听端口 %d: %v", port, err)
    }
    defer ln.Close()
    
    // 记录监听信息
    log.Printf("服务器正在监听端口 %d", port)
    // 启动HTTP服务
    if err := http.Serve(ln, nil); err != nil {
        log.Fatalf("服务器错误: %v", err)
    }
}
