package main

import (
    "embed"
    "encoding/json"
    "flag"
    "io/fs"
    "io/ioutil"
    "log"
    "errors"
    "net"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "runtime"
    "fmt"
    "time"
    "strings"
    "net/url"
    "math/rand"
    "html/template"
    "sync"
    "syscall"
    "io"
    "regexp"
    "github.com/natefinch/lumberjack"
    "github.com/zu1k/nali/pkg/geoip"
    "github.com/zu1k/nali/pkg/ip2region"
    "github.com/zu1k/nali/pkg/ipip"
    "github.com/zu1k/nali/pkg/qqwry"
    "github.com/zu1k/nali/pkg/cdn"
    "github.com/zu1k/nali/pkg/zxipv6wry"
    "github.com/zu1k/nali/pkg/ip2location"
)

//go:embed static/*
var content embed.FS

var (
        dataDir string
        dbDir string
        admin bool
        logDir string
	// 错误尝试限制和锁定时间
	maxAttempts       = 5
	lockoutDuration   = 10 * time.Minute
	authenticationURL = "/admin-auth"
	authCredentials   = map[string]string{}
	lockoutData       = struct {
		sync.RWMutex
		attempts      int
		lockout       time.Time
	}{}
	// 认证 cookie 的设置
	authCookieName     = "authenticated"
	authCookieValue    = "true"
	authCookieAge      = 10 * time.Minute // 认证 cookie 的有效期
	ipCookieName       = "auth-ip"
	ipCookieValue      = "" // 动态设置
)

// 定义查询实例
var (
	QQWryPath        string
	ZXIPv6WryPath    string
	GeoLite2CityPath string
	IPIPFreePath     string
	Ip2RegionPath    string
	CdnPath          string
	Ip2locationPath  string
	
	geoip2Instance    *geoip.GeoIP
	qqwryInstance     *qqwry.QQwry
	ipipInstance      *ipip.IPIPFree
	ip2regionInstance *ip2region.Ip2Region
	zxipv6wryInstance    *zxipv6wry.ZXwry
	ip2locationInstance    *ip2location.IP2Location
	cdnInstance    *cdn.CDN
)

func init() {
    // 设置时区为上海
    loc := time.FixedZone("CST", 8*60*60)
    time.Local = loc
}

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
        Img:              "https://img-baofun.zhhainiao.com/pcwallpaper_ugc/static/a613b671bce87bdafae01938c7cad011.jpg",
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

    // 检查IP地址是否包含端口号
    if strings.Contains(ip, ":") {
        if strings.Count(ip, ":") == 1 {
            // 处理端口号
            ip, _, _ = net.SplitHostPort(ip)
            
        }
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
    // 判断后缀是否包含 "/"
    if strings.Contains(req.ShortCode, "/") {
        errMsg := map[string]string{"error": "错误！后缀里不能包含 / 符号。"}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(errMsg)
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
    // 不能使用后缀admin
    if req.ShortCode == "admin" {
        errMsg := map[string]string{"error": "错误！该后缀已经被使用，请使用正确的密码修改或使用其他后缀。"}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(errMsg)
        return
    }
    // 不能使用后缀admin-auth
    if req.ShortCode == "admin-auth" {
        errMsg := map[string]string{"error": "错误！该后缀已经被使用，请使用正确的密码修改或使用其他后缀。"}
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        json.NewEncoder(w).Encode(errMsg)
        return
    }
    // 判断请求里的type的值
    if req.Type == "link" || req.Type == "iframe" {
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
    
     // 判断路径中是否包含 "/"
    var extra string // 定义用于存储 "/" 后内容的新变量
    if idx := strings.Index(path, "/"); idx != -1 {
        // 如果包含 "/", 截取 "/" 前后的内容
        extra = path[idx+1:] // "/" 后面的内容
        path = path[:idx]    // "/" 前面的内容
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
    	// 判断 extra 是否为空
    	if extra != "" {
        // 检查 apiReq.LongUrl 是否以 '/' 结尾，或 extra 是否以 '/' 开头
        if strings.HasSuffix(apiReq.LongUrl, "/") && strings.HasPrefix(extra, "/") {
            // 如果两者都有 '/'，移除 extra 的前导 '/'
            extra = strings.TrimPrefix(extra, "/")
        } else if !strings.HasSuffix(apiReq.LongUrl, "/") && !strings.HasPrefix(extra, "/") {
            // 如果两者都没有 '/'，在两者之间添加一个 '/'
            extra = "/" + extra
        }

        // 拼接 extra 到 apiReq.LongUrl
           apiReq.LongUrl += extra
    	}
        // 如果是 WebSocket 请求，返回特定的头字段或响应体
        if r.Header.Get("Upgrade") == "websocket" {
	   if strings.HasPrefix(apiReq.LongUrl, "http://") {
                apiReq.LongUrl = "ws://" + strings.TrimPrefix(apiReq.LongUrl, "http://")
            } else if strings.HasPrefix(apiReq.LongUrl, "https://") {
                apiReq.LongUrl = "wss://" + strings.TrimPrefix(apiReq.LongUrl, "https://")
            } else if !strings.HasPrefix(apiReq.LongUrl, "ws://") && !strings.HasPrefix(apiReq.LongUrl, "wss://") {
                // 如果没有前缀，则添加 ws://
                apiReq.LongUrl = "ws://" + apiReq.LongUrl
            }
	}
        http.Redirect(w, r, apiReq.LongUrl, http.StatusFound)
    case "html":
        // 如果是 WebSocket 请求，返回特定的头字段或响应体
        if r.Header.Get("Upgrade") == "websocket" {
           if strings.HasPrefix(apiReq.LongUrl, "http://") {
                apiReq.LongUrl = "ws://" + strings.TrimPrefix(apiReq.LongUrl, "http://")
            } else if strings.HasPrefix(apiReq.LongUrl, "https://") {
                apiReq.LongUrl = "wss://" + strings.TrimPrefix(apiReq.LongUrl, "https://")
            } else if !strings.HasPrefix(apiReq.LongUrl, "ws://") && !strings.HasPrefix(apiReq.LongUrl, "wss://") {
                // 如果没有前缀，则添加 ws://
                apiReq.LongUrl = "ws://" + apiReq.LongUrl
            }
            
            http.Redirect(w, r, apiReq.LongUrl, http.StatusFound)
        } else {
          w.Header().Set("Content-Type", "text/html; charset=utf-8")
          w.WriteHeader(http.StatusOK)
          w.Write([]byte(apiReq.LongUrl))
        }
    case "page":
        htmlContent, err := content.ReadFile("static/page.html")
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        responseHtml := strings.Replace(string(htmlContent), "{长内容}", apiReq.LongUrl, -1)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(responseHtml))
    case "iframe":
        htmlContent, err := content.ReadFile("static/iframe.html")
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        if extra != "" {
        	if strings.HasSuffix(apiReq.LongUrl, "/") && strings.HasPrefix(extra, "/") {
            		extra = strings.TrimPrefix(extra, "/")
        	} else if !strings.HasSuffix(apiReq.LongUrl, "/") && !strings.HasPrefix(extra, "/") {
            		extra = "/" + extra
        	}
           	apiReq.LongUrl += extra
    	}
	
    	// 判断是否为 curl 或 wget 请求
    	userAgent := r.Header.Get("User-Agent")
    	if strings.Contains(userAgent, "curl") || strings.Contains(userAgent, "wget") {
        	// 如果是 curl 或 wget 请求，则直接重定向
        	http.Redirect(w, r, apiReq.LongUrl, http.StatusFound)
        	return
    	}
        responseHtml := strings.Replace(string(htmlContent), "{套娃地址}", apiReq.LongUrl, -1)
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(responseHtml))
    case "text":
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte(apiReq.LongUrl))
    default:
        http.Error(w, "Forbidden", http.StatusForbidden)
    }
}

// 认证处理函数
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		// 获取当前 IP 地址
		ip := getClientIP(r)
		

		if validPassword(username, password) {
                       log.Printf("用户 IP: %s 登录成功！", ip)
			// 认证成功，设置认证 cookie 和 IP 地址 cookie
			http.SetCookie(w, &http.Cookie{
				Name:    authCookieName,
				Value:   authCookieValue,
				Path:    "/",
				Expires: time.Now().Add(authCookieAge),
				HttpOnly: true,
			})

			http.SetCookie(w, &http.Cookie{
				Name:    ipCookieName,
				Value:   ip,
				Path:    "/",
				Expires: time.Now().Add(authCookieAge),
				HttpOnly: true,
			})

			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}

		// 认证失败，记录错误尝试
		log.Printf("用户 IP: %s 使用帐号：%s 密码：%s 尝试登录！", ip, username, password)
		lockoutData.Lock()
		defer lockoutData.Unlock()
		lockoutData.attempts++
		if lockoutData.attempts >= maxAttempts {
			lockoutData.lockout = time.Now().Add(lockoutDuration)
			http.Error(w, "连续输错次数过多，请十分钟后重试", http.StatusForbidden)
			return
		}

		// 显示认证表单并添加错误提示
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `
			<!DOCTYPE html>
			<html lang="zh-CN">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>登录</title>
				<style>
					body {
						margin: 0;
						padding: 0;
						background-color: #f0f2f5;
						font-family: Arial, sans-serif;
					}
					.container {
						display: flex;
						justify-content: center;
						align-items: center;
						height: 100vh;
					}
					.form-container {
						background: white;
						padding: 20px;
						border-radius: 8px;
						box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
						text-align: center;
						width: 360px;
						position: relative;
					}
					.form-container h1 {
						margin-bottom: 20px;
						color: #333;
					}
					.form-container label {
						display: block;
						margin: 10px 0;
						color: #555;
					}
					.form-container input[type="text"],
					.form-container input[type="password"] {
						width: calc(100% - 20px);
						padding: 10px;
						margin: 5px 0;
						border: 1px solid #ccc;
						border-radius: 4px;
					}
					.form-container input[type="submit"] {
						background-color: #007bff;
						color: white;
						border: none;
						padding: 10px 15px;
						border-radius: 4px;
						cursor: pointer;
					}
					.form-container input[type="submit"]:hover {
						background-color: #0056b3;
					}
					.error-message {
						color: red;
						margin-bottom: 15px;
						display: none;
					}
					.error-message.show {
						display: block;
					}
					.shake {
						animation: shake 0.5s;
					}
					@keyframes shake {
						0% { transform: translateX(0); }
						25% { transform: translateX(-5px); }
						50% { transform: translateX(5px); }
						75% { transform: translateX(-5px); }
						100% { transform: translateX(0); }
					}
				</style>
			</head>
			<body>
				<div class="container">
					<div class="form-container">
						<h1>登录</h1>
						<div id="error-message" class="error-message">账户或密码错误</div>
						<form method="post" id="login-form">
							<label>用户名: <input type="text" name="username" /></label>
							<label>密码: <input type="password" name="password" /></label>
							<input type="submit" value="登录" />
						</form>
					</div>
				</div>
				<script>
					document.addEventListener('DOMContentLoaded', function() {
						const form = document.getElementById('login-form');
						const errorMessage = document.getElementById('error-message');
						if (errorMessage.textContent.trim() !== '') {
							errorMessage.classList.add('show');
							form.classList.add('shake');
							setTimeout(() => form.classList.remove('shake'), 500);
						}
					});
				</script>
			</body>
			</html>
		`)
		return
	}

	// 显示认证表单
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `
		<!DOCTYPE html>
		<html lang="zh-CN">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>登录</title>
			<style>
				body {
					margin: 0;
					padding: 0;
					background-color: #f0f2f5;
					font-family: Arial, sans-serif;
				}
				.container {
					display: flex;
					justify-content: center;
					align-items: center;
					height: 100vh;
				}
				.form-container {
					background: white;
					padding: 20px;
					border-radius: 8px;
					box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
					text-align: center;
					width: 360px;
				}
				.form-container h1 {
					margin-bottom: 20px;
					color: #333;
				}
				.form-container label {
					display: block;
					margin: 10px 0;
					color: #555;
				}
				.form-container input[type="text"],
				.form-container input[type="password"] {
					width: calc(100% - 20px);
					padding: 10px;
					margin: 5px 0;
					border: 1px solid #ccc;
					border-radius: 4px;
				}
				.form-container input[type="submit"] {
					background-color: #007bff;
					color: white;
					border: none;
					padding: 10px 15px;
					border-radius: 4px;
					cursor: pointer;
				}
				.form-container input[type="submit"]:hover {
					background-color: #0056b3;
				}
			</style>
		</head>
		<body>
			<div class="container">
				<div class="form-container">
					<h1>登录</h1>
					<form method="post">
						<label>用户名: <input type="text" name="username" /></label>
						<label>密码: <input type="password" name="password" /></label>
						<input type="submit" value="登录" />
					</form>
				</div>
			</div>
		</body>
		</html>
	`)
}


// 校验账户和密码
func validPassword(username, password string) bool {
	if pwd, ok := authCredentials[username]; ok && pwd == password {
		return true
	}
	return false
}

// 检查是否已认证
func isAuthenticated(r *http.Request) bool {
	authCookie, err := r.Cookie(authCookieName)
	if err != nil || authCookie.Value != authCookieValue {
		return false
	}

	ipCookie, err := r.Cookie(ipCookieName)
	if err != nil {
		return false
	}

	ip := getClientIP(r)
	return ip == ipCookie.Value
}

// 处理/admin请求
func adminHandler(w http.ResponseWriter, r *http.Request, dataDir string) {

	// 检查锁定状态
	lockoutData.RLock()
	defer lockoutData.RUnlock()
	if time.Now().Before(lockoutData.lockout) {
		http.Error(w, "错误：连续输错次数太多啦，请休息一会儿后再试吧！", http.StatusForbidden)
		return
	}
	//处理清理日志请求
	      if r.Method == http.MethodPost && r.FormValue("mode") == "del-log" {
	         if logDir != "" {
			logFile := fmt.Sprintf("%s/shortener.log", logDir)
			err := os.Truncate(logFile, 0)
			if err != nil {
				http.Error(w, "错误：无法清空日志", http.StatusInternalServerError)
				return
			}
			fmt.Fprintln(w, "清空日志成功")
		} else {
			http.Error(w, "错误：日志目录未指定", http.StatusInternalServerError)
		}
	}
	
	// 处理删除请求
	if r.Method == http.MethodPost && r.FormValue("mode") == "delete" {
		shortCode := r.FormValue("shortcode")
		if shortCode == "" {
			http.Error(w, "错误：缺少必要的参数", http.StatusBadRequest)
			return
		}

		// 构建要删除的文件路径
		filePath := filepath.Join(dataDir, shortCode+".json")

		// 删除文件
		err := os.Remove(filePath)
		if err != nil {
			log.Printf("删除%s失败 : %v", filePath, err)
			http.Error(w, "删除失败", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("删除成功"))
		return
	}
	
		// 处理编辑请求
	        if r.Method == http.MethodPost && r.FormValue("mode") == "edit" {
		var data ApiRequest
		decoder := json.NewDecoder(r.Body)
		err := decoder.Decode(&data)
		if err != nil {
			http.Error(w, "错误：无效的请求数据", http.StatusBadRequest)
			return
		}

		// 使用 ShortCode 作为文件名
		shortCode := data.ShortCode
		if shortCode == "" {
			http.Error(w, "错误：缺少 ShortCode", http.StatusBadRequest)
			return
		}
		// 判断 ShortCode 是否为单个 "/" 或包含 "/"
    		if shortCode == "/" || strings.Contains(shortCode, "/") {
        		http.Error(w, "错误：后缀里不能包含 / 符号", http.StatusBadRequest)
        		return
    		}
		// 构建要更新的文件路径
		filePath := filepath.Join(dataDir, shortCode+".json")

		// 读取文件内容
		_, err = os.Stat(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "错误：文件不存在", http.StatusNotFound)
				return
			}
			http.Error(w, "错误：无法读取文件", http.StatusInternalServerError)
			return
		}

		// 写入新数据到文件
		fileContent, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			http.Error(w, "错误：无法序列化数据", http.StatusInternalServerError)
			return
		}

		err = os.WriteFile(filePath, fileContent, 0644)
		if err != nil {
			http.Error(w, "错误：无法写入文件", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("修改成功"))
		return
	}
	// 读取dataDir目录中的所有.json文件（不包括short_data.json）
	files, err := filepath.Glob(filepath.Join(dataDir, "*.json"))
	if err != nil {
		http.Error(w, fmt.Sprintf("无法读取数据目录：%v", err), http.StatusInternalServerError)
		return
	}

	// 定义结构用于保存所有文件的数据
	var allData []ApiRequest

	// 读取每个JSON文件的内容
	for _, file := range files {
		if filepath.Base(file) == "short_data.json" {
			continue
		}

		// 读取JSON文件内容
		content, err := os.ReadFile(file)
		if err != nil {
			log.Printf("无法读取文件 %s: %v", file, err)
			continue
		}

		var data ApiRequest
		if err := json.Unmarshal(content, &data); err != nil {
			log.Printf("无法解析文件 %s: %v", file, err)
			continue
		}

		allData = append(allData, data)
	}

	// 生成HTML响应
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	renderAdminPage(w, allData)
}

// 生成/admin页面的HTML响应
func renderAdminPage(w http.ResponseWriter, data []ApiRequest) {
        // 读取日志文件内容
	var logContent string
	if logDir != "" {
		logFile := fmt.Sprintf("%s/shortener.log", logDir)
		content, err := ioutil.ReadFile(logFile)
		if err == nil {
			logContent = string(content)
		}
	}
	// 定义模板
	const adminTemplate = `
	<!DOCTYPE html>
	<html lang="zh-CN">
	<head>
		<meta charset="UTF-8">
		<title>管理页面</title>
		<style>
			body {
				font-family: Arial, sans-serif;
				background-color: #f4f4f4;
				margin: 0;
				padding: 0;
			}
			h2 {
				text-align: center;
				color: #333;
				padding: 20px;
			}
			.container {
				width: 90%;
				margin: 0 auto;
				padding: 20px;
				background-color: #fff;
				box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
				border-radius: 8px;
			}
			input[type="text"], textarea {
				padding: 10px;
				margin: 10px 0;
				border: 1px solid #ddd;
				border-radius: 4px;
				width: 100%;
				box-sizing: border-box;
			}
			textarea {
				resize: vertical;
				min-height: 40px;
			}
			button {
				background-color: #007bff;
				color: #fff;
				border: none;
				padding: 10px 20px;
				margin: 10px;
				border-radius: 4px;
				cursor: pointer;
				font-size: 16px;
			}
			button:hover {
				background-color: #0056b3;
			}
			table {
				width: 100%;
				border-collapse: collapse;
				margin: 20px 0;
			}
			table, th, td {
				border: 1px solid #ddd;
			}
			th {
				background-color: #007bff;
				color: #fff;
				padding: 12px;
			}
			td {
				padding: 10px;
				text-align: center;
				overflow: hidden;
				text-overflow: ellipsis;
			}
			td:nth-child(1) {
				width: 300px;
				white-space: normal;
			}
			.highlight {
				background-color: yellow;
			}
			.pagination {
				display: flex;
				justify-content: center;
				align-items: center;
				margin: 20px 0;
			}
			.pagination span {
				margin: 0 10px;
			}
			@media (max-width: 768px) {
				.container {
					width: 100%;
					padding: 10px;
				}
				button {
					width: 100%;
					margin: 5px 0;
				}
				input[type="text"], textarea {
					width: 100%;
				}
			}
			.editable {
				background-color: #f0f8ff;
			}
			/* 新增日志悬浮按钮和展示区域的样式 */
		        /* 日志弹出框样式 */
        .log-popup {
            display: none;
            position: fixed;
            top: 10%;
            right: 10%;
            width: 80%;
            height: 70%;
            background-color: #fff;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
            border-radius: 8px;
            overflow: hidden;
            z-index: 1000;
            padding: 10px;
        }
        .log-popup .log-content {
            height: calc(100% - 50px); /* 减去顶部和底部的高度 */
            overflow-y: auto;
            padding: 10px;
            border: 1px solid #ddd;
            box-sizing: border-box;
            white-space: pre-wrap; /* 保持原有的换行 */
        }
        .log-popup .log-footer {
            position: absolute;
            bottom: 10px;
            right: 10px;
        }
        .log-popup .close-btn {
    position: absolute;
    top: 10px;
    right: 10px;
    width: 40px;  /* 控制按钮的宽度 */
    height: 40px;  /* 控制按钮的高度 */
    background-color: #007bff;  /* 按钮背景色为蓝色 */
    color: #ffffff;  /* 文字颜色为白色 */
    border: none;
    border-radius: 50%;  /* 使用50%的圆角使其呈现圆形效果 */
    font-size: 16px;
    cursor: pointer;
    display: flex;  /* 使用flex布局使得按钮内文字垂直水平居中 */
    justify-content: center;
    align-items: center;
}

.log-popup .close-btn:hover {
    background-color: #0056b3;  /* 鼠标悬停时按钮背景色稍微变深 */
}

        /* 悬浮按钮样式 */
        .floating-btn {
    position: fixed;
    top: 10px;
    right: 10px;
    background-color: #007bff;
    color: #fff;
    border: none;
    padding: 10px 20px;
    border-radius: 5px; /* 使用圆角半径使其呈现矩形效果 */
    cursor: pointer;
    font-size: 16px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
}
        .floating-btn:hover {
            background-color: #0056b3;
        }
		</style>
		<script>
			function searchTable() {
				var input, filter, table, tr, td, i, j, txtValue;
				input = document.getElementById("searchInput");
				filter = input.value.toLowerCase();
				table = document.getElementById("dataTable");
				tr = table.getElementsByTagName("tr");
				for (i = 1; i < tr.length; i++) {
					td = tr[i].getElementsByTagName("td");
					for (j = 0; j < td.length; j++) {
						td[j].classList.remove("highlight");
					}
					tr[i].style.display = "";
				}
				if (filter === "") {
					return;
				}
				for (i = 1; i < tr.length; i++) {
					tr[i].style.display = "none";
					td = tr[i].getElementsByTagName("td");
					for (j = 0; j < td.length; j++) {
						if (td[j]) {
							txtValue = td[j].textContent || td[j].innerText;
							if (txtValue.toLowerCase().indexOf(filter) > -1) {
								tr[i].style.display = "";
								td[j].classList.add("highlight");
							}
						}
					}
				}
			}

			var pageSize = 5;
			var currentPage = 1;

			function previousPage() {
				if (currentPage > 1) {
					currentPage--;
					updateTablePagination();
				}
			}

			function nextPage() {
				var totalItems = document.getElementById("dataTable").getElementsByTagName("tr").length - 1;
				var totalPages = Math.ceil(totalItems / pageSize);
				if (currentPage < totalPages) {
					currentPage++;
					updateTablePagination();
				}
			}

			function updateTablePagination() {
				var rows = document.getElementById("dataTable").getElementsByTagName("tr");
				var start = (currentPage - 1) * pageSize + 1;
				var end = start + pageSize - 1;

				for (var i = 1; i < rows.length; i++) {
					rows[i].style.display = "none";
				}

				for (var i = start; i <= end && i < rows.length; i++) {
					rows[i].style.display = "";
				}

				document.getElementById("currentPage").innerText = " 当前页: " + currentPage + " / ";
				document.getElementById("totalPages").innerText = " 总页数: " + Math.ceil(rows.length / pageSize);
			}

			window.onload = function() {
				var savedPageSize = localStorage.getItem("pageSize");
				if (savedPageSize) {
					pageSize = parseInt(savedPageSize);
				}
				updatePageSizeSelect();
				updateTablePagination();
			};

			function changePageSize() {
				var select = document.getElementById("pageSizeSelect");
				pageSize = parseInt(select.value);
				localStorage.setItem("pageSize", pageSize);
				currentPage = 1;
				updateTablePagination();
			}

			function updatePageSizeSelect() {
				var select = document.getElementById("pageSizeSelect");
				for (var i = 0; i < select.options.length; i++) {
					if (parseInt(select.options[i].value) === pageSize) {
						select.selectedIndex = i;
						break;
					}
				}
			}

			function deleteRow(shortcode) {
				if (confirm("确定要删除此项吗？")) {
					var xhr = new XMLHttpRequest();
					xhr.open("POST", "/admin?mode=delete", true);
					xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
					xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
					xhr.send("shortcode=" + encodeURIComponent(shortcode));
					xhr.onload = function() {
						if (xhr.status === 200) {
						   if (xhr.responseText.includes('删除成功')) {
						      alert('删除成功');
						   } else {
						      alert('删除失败');
						   }
							location.reload();
						}
					};
				}
			}

			function editRow(row) {
    var cells = row.getElementsByTagName("td");
    for (var i = 0; i < cells.length; i++) {
        if (i < cells.length - 1) { // 跳过最后一列（操作按钮）
            var dataField = cells[i].getAttribute("data-field");
            if (dataField) {
                var input;
                if (dataField === "expiration" || dataField === "last_update") {
                    input = document.createElement("input");
                    input.type = "text";
                    var value = cells[i].innerText;
                    if (value) {
                        // 格式化时间为 YYYY-MM-DD HH:MM:SS
                        var date = new Date(value);
                        input.value = date.toISOString().replace('T', ' ').slice(0, 19);
                    } else {
                        input.value = "";
                    }
                } else if (dataField === "burn_after_reading") {
                    input = document.createElement("select");
                    input.innerHTML = '<option value="true" ' + (cells[i].innerText === "true" ? "selected" : "") + '>是</option>' +
                                        '<option value="false" ' + (cells[i].innerText === "false" ? "selected" : "") + '>否</option>';
                } else if (dataField === "Type") {
                    input = document.createElement("select");
                    input.innerHTML = '<option value="link" ' + (cells[i].innerText === "link" ? "selected" : "") + '>缩短链接</option>' +
                                        '<option value="html" ' + (cells[i].innerText === "html" ? "selected" : "") + '>html网页</option>' +
                                        '<option value="page" ' + (cells[i].innerText === "page" ? "selected" : "") + '>网页文本</option>' +
                                        '<option value="iframe" ' + (cells[i].innerText === "iframe" ? "selected" : "") + '>iframe网页</option>' +
                                        '<option value="text" ' + (cells[i].innerText === "text" ? "selected" : "") + '>txt文本</option>';
                } else {
                    input = document.createElement("textarea");
                    input.value = cells[i].innerText;
                }
                input.className = "editable";
                input.oninput = function() { adjustTextAreaHeight(this); };
                cells[i].innerHTML = "";
                cells[i].appendChild(input);
                adjustTextAreaHeight(input);
            }
        }
    }
    row.querySelector("button.edit").style.display = "none";
    row.querySelector("button.submit").style.display = "inline-block";
    row.classList.add("editing");

    // 检测点击外部以取消编辑
    document.addEventListener("click", function(e) {
        if (!row.contains(e.target) && row.classList.contains("editing")) {
            cancelEdit(row);
        }
    });
}

		function submitEdit(row) {
			var cells = row.getElementsByTagName("td");
			var data = {};
			for (var i = 0; i < cells.length; i++) {
				if (i < cells.length - 1) { // 跳过最后一列（操作按钮）
					var field = cells[i].getAttribute("data-field");
					if (field) {
						var input = cells[i].querySelector("input, textarea, select");
						data[field] = input.value;
					}
				}
			}
			var shortcode = row.querySelector("td:nth-child(2)").innerText;
			data.shortcode = shortcode;

			// 验证日期格式
			var dateFormat = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;
			if (data.last_update && !dateFormat.test(data.last_update)) {
				alert("最后更新时间字段的格式必须为 年-月-日 时:分:秒 如 2000-01-01 01:01:01");
				return;
			}
			if (data.Expiration && !dateFormat.test(data.Expiration)) {
				alert("到期时间字段的格式必须为 年-月-日 时:分:秒 如 2000-01-01 01:01:01");
				return;
			}

			// 如果最后更新为空，设置为当前时间
			if (!data.last_update) {
				data.last_update = new Date().toISOString().replace('T', ' ').slice(0, -5);
			}

			var xhr = new XMLHttpRequest();
			xhr.open("POST", "/admin?mode=edit", true);
			xhr.setRequestHeader("Content-Type", "application/json");
			xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
			xhr.send(JSON.stringify(data));
			xhr.onload = function() {
				if (xhr.status === 200) {
				   if (xhr.responseText.includes('修改成功')) {
				      alert('修改成功');
				   } else {
				      alert('修改失败');
				   }
					location.reload();
				}
			};
		}

		function cancelEdit(row) {
			var cells = row.getElementsByTagName("td");
			for (var i = 0; i < cells.length; i++) {
				if (i < cells.length - 1) { // 跳过最后一列（操作按钮）
					var field = cells[i].getAttribute("data-field");
					if (field) {
						cells[i].innerHTML = cells[i].querySelector("input, textarea, select").value;
					}
				}
			}
			row.querySelector("button.edit").style.display = "inline-block";
			row.querySelector("button.submit").style.display = "none";
			row.classList.remove("editing");
		}

			// 调整文本区域高度
			function adjustTextAreaHeight(textarea) {
				textarea.style.height = 'auto';
				textarea.style.height = (textarea.scrollHeight) + 'px';
			}
			function showLogPopup() {
            var popup = document.getElementById("logPopup");
            popup.style.display = "block";
            var logContent = document.getElementById("logContent");
            logContent.scrollTop = logContent.scrollHeight; // 自动滚动到日志底部
        }

        function closeLogPopup() {
            var popup = document.getElementById("logPopup");
            popup.style.display = "none";
        }

		function clearLog() {
			if (confirm("确定要清空日志吗？")) {
				var xhr = new XMLHttpRequest();
				xhr.open("POST", "/admin?mode=del-log", true);
				xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
				xhr.send();
				xhr.onload = function() {
					if (xhr.status === 200) {
						if (xhr.responseText.includes('清空日志成功')) {
							document.getElementById("logContent").innerHTML = "";
							alert('日志已清空');
						} else {
							alert('清空日志失败');
						}
					}
				};
			}
		}
		</script>
	</head>
	<body>
		<h2>管理页面</h2>
		<div class="container">
			<input type="text" id="searchInput" onkeyup="searchTable()" placeholder="搜索关键词...">
			<table id="dataTable">
				<thead>
					<tr>
						<th>长链接内容</th>
						<th>后缀</th>
						<th>密码</th>
						<th>客户端IP</th>
						<th>到期时间</th>
						<th>阅后即焚</th>
						<th>类型</th>
						<th>最后更新时间</th>
						<th>操作</th>
					</tr>
				</thead>
				<tbody>
					{{range .}}
					<tr>
						<td data-field="LongUrl">{{.LongUrl}}</td>
						<td>{{.ShortCode}}</td>
						<td data-field="Password">{{.Password}}</td>
						<td data-field="client_ip">{{.ClientIP}}</td>
						<td data-field="Expiration">{{.Expiration}}</td>
						<td data-field="burn_after_reading">{{.BurnAfterReading}}</td>
						<td data-field="Type">{{.Type}}</td>
						<td data-field="last_update">{{.LastUpdate}}</td>
						<td>
							<button class="edit" onclick="editRow(this.closest('tr'))">编辑</button>
							<button class="submit" style="display:none;" onclick="submitEdit(this.closest('tr'))">提交</button>
							<button onclick="deleteRow('{{.ShortCode}}')">删除</button>
						</td>
					</tr>
					{{end}}
				</tbody>
			</table>
			<div class="pagination">
				<button onclick="previousPage()">上一页</button>
				<span id="currentPage"> 当前页: 1 / </span><span id="totalPages"> 总页数: 1</span>
				<button onclick="nextPage()">下一页</button>
			</div>
			<select id="pageSizeSelect" onchange="changePageSize()">
				<option value="5">每页 5 项</option>
				<option value="10">每页 10 项</option>
				<option value="15">每页 15 项</option>
				<option value="20">每页 20 项</option>
				<option value="50">每页 50 项</option>
				<option value="100">每页 100 项</option>
			</select>
			<!-- 悬浮按钮 -->
    <button class="floating-btn" onclick="showLogPopup()">查看日志</button>
    <!-- 日志弹出框 -->
    <div id="logPopup" class="log-popup">
        <button class="close-btn" onclick="closeLogPopup()">X</button>
        <div class="log-content" id="logContent">
            {{LOG_CONTENT}}
        </div>
        <div class="log-footer">
            <button onclick="clearLog()">清空日志</button>
        </div>
    </div>     
		<br><br><br>
	</body>
	</html>
	`
       pageContent := strings.ReplaceAll(adminTemplate, "{{LOG_CONTENT}}", logContent)
	// 渲染页面
	tmpl, err := template.New("admin").Parse(pageContent)
	if err != nil {
		http.Error(w, "无法解析模板", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "无法渲染模板", http.StatusInternalServerError)
		return
	}
}

func setupLogging(logDir string) {
    var logOutput io.Writer
    if logDir != "" {
        logFilePath := filepath.Join(logDir, "shortener.log")

        // 创建 lumberjack.Logger 实例
        logOutput = io.MultiWriter(&lumberjack.Logger{
            Filename:   logFilePath,
            MaxSize:    10, // MB
            MaxBackups: 1,  // 保留3个旧日志文件
            MaxAge:     28, // 保留日志文件的最大天数
            Compress:   true, // 是否压缩旧日志
        }, os.Stdout)
    } else {
        logOutput = os.Stdout
    }

    // 设置日志的输出目标
    log.SetOutput(logOutput)
}

// 获取客户端IP地址
func getIP(r *http.Request) string {
    // 获取客户端的真实IP（你可以根据实际需求调整获取方式）
    clientIP := r.Header.Get("X-Forwarded-For")
    if clientIP == "" {
        clientIP = r.RemoteAddr
        // RemoteAddr包含端口，需要分割出IP部分
	if strings.Contains(clientIP, ":") {
		clientIP, _, _ = net.SplitHostPort(clientIP)
	}
    }
    return clientIP
}

// 查询cdn
func querycdn(ip string) (string, error) {
	if cdnInstance == nil {
		return "", errors.New("CDN服务不可用")
	}
	res, err := cdnInstance.Find(ip)
	if err != nil {
		return "", err
	}
	return res.String(), nil
}

// 查询ip2location
func queryip2location(ip string) (string, error) {
	if ip2locationInstance == nil {
		return "", errors.New("ip2location服务不可用")
	}
	res, err := ip2locationInstance.Find(ip)
	if err != nil {
		return "", err
	}
	return res.String(), nil
}

// 查询zxipv6wry
func queryzxipv6wry(ip string) (string, error) {
	if zxipv6wryInstance == nil {
		return "", errors.New("zxipv6wry服务不可用")
	}
	res, err := zxipv6wryInstance.Find(ip)
	if err != nil {
		return "", err
	}
	return res.String(), nil
}

// 查询Geoip2
func queryGeoip2(ip string) (string, error) {
	if geoip2Instance == nil {
		return "", errors.New("GeoIP服务不可用")
	}
	res, err := geoip2Instance.Find(ip)
	if err != nil {
		return "", err
	}
	return res.String(), nil
}

// 查询QQwry
func queryQQwry(ip string) (string, error) {
	if qqwryInstance == nil {
		return "", errors.New("QQWry服务不可用")
	}
	// 使用查询方法，假设有 Find 方法
	res, err := qqwryInstance.Find(ip)
	if err != nil {
		return "", err
	}
	return res.String(), nil
}

// 查询IPIP
func queryIPIP(ip string) (string, error) {
	if ipipInstance == nil {
		return "", errors.New("IPIP服务不可用")
	}
	// 使用查询方法，假设有 Find 方法
	res, err := ipipInstance.Find(ip)
	if err != nil {
		return "", err
	}
	return res.String(), nil
}

// 查询Ip2Region
func queryIp2Region(ip string) (string, error) {
	if ip2regionInstance == nil {
		return "", errors.New("Ip2Region服务不可用")
	}
	// 使用查询方法，假设有 Find 方法
	res, err := ip2regionInstance.Find(ip)
	if err != nil {
		return "", err
	}
	return res.String(), nil
}

// 查询IP地址信息
func queryIP(ip string) string {
	var result string
	var err error

	// 依次调用各个查询方法
	result, err = queryQQwry(ip)
	if err == nil && result != "" {
		fmt.Println("QQWry查询结果：", ip, result)
		return ip + " " + result
	}

	result, err = queryGeoip2(ip)
	if err == nil && result != "" {
		fmt.Println("GeoIP查询结果：", ip, result)
		return ip + " " + result
	}

	result, err = queryIp2Region(ip)
	if err == nil && result != "" {
		fmt.Println("Ip2Region查询结果：", ip, result)
		return ip + " " + result
	}

	result, err = queryIPIP(ip)
	if err == nil && result != "" {
		fmt.Println("IPIP查询结果：", ip, result)
		return ip + " " + result
	}
	
	result, err = querycdn(ip)
	if err == nil && result != "" {
		fmt.Println("CDN查询结果：", ip, result)
		return ip + " " + result
	}
	result, err = queryip2location(ip)
	if err == nil && result != "" {
		fmt.Println("IP2location查询结果：", ip, result)
		return ip + " " + result
	}
	result, err = queryzxipv6wry(ip)
	if err == nil && result != "" {
		fmt.Println("Zxipv6wry查询结果：", ip, result)
		return ip + " " + result
	}

	// 如果所有查询都没有结果，使用原IP
	fmt.Println("未查询到IP区域信息，返回原始IP：", ip)
	return ip
}

// 生成SVG内容
func generateSVG(clientIP string) string {
    // 使用估算值，每个字符宽度为 5px（你可以根据实际需求调整）
    const charWidth = 5
    
    // 计算文本宽度，不能在常量表达式中使用len(clientIP)
    textWidth := len(clientIP) * charWidth  // 计算文本宽度

    // 右边矩形宽度比文本宽度多一些，保证有适当的间隔
    rectWidth := textWidth // 右边矩形的宽度

    // 调整左边矩形的宽度，使其比原来小一些
    leftRectWidth := 30 // 左边矩形宽度减少至 30（你可以根据实际需求调整）

    // 确保宽度是计算出来的矩形总宽度
    totalWidth := leftRectWidth + rectWidth

    svgContent := fmt.Sprintf(`
<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" viewBox="0 0 %d 20">
    <!-- 左边固定部分：背景 #515151，宽度调整为 leftRectWidth，包含左侧小圆角 -->
    <path d="
        M3 0 
        h%d 
        v20 
        h-%d 
        a3 3 0 0 1 -3 -3 
        v-14 
        a3 3 0 0 1 3 -3 
        z" fill="#515151" />
    <text x="10" y="15" font-size="12" fill="#ffffff">IP</text>

    <!-- 右边动态部分：背景 #95c10d -->
    <path d="
        M%d 0 
        h%d 
        a3 3 0 0 1 3 3 
        v14 
        a3 3 0 0 1 -3 3 
        h-%d 
        v-20 
        z" fill="#95c10d" />
    <text x="%d" y="15" font-size="12" fill="#ffffff">%s</text>
</svg>`, totalWidth, totalWidth, leftRectWidth-3, leftRectWidth-3, leftRectWidth, rectWidth-3, rectWidth-3, leftRectWidth+10, clientIP)

    return svgContent
}
func generateUASVG(uaInfo string) string {
    // 使用估算值，每个字符宽度为 5px（你可以根据实际需求调整）
    const charWidth = 6
    fmt.Println("UA标识：", uaInfo)
    // 计算文本宽度，不能在常量表达式中使用len(UAInfo)
    textWidth := len(uaInfo) * charWidth  // 计算文本宽度

    // 右边矩形宽度比文本宽度多一些，保证有适当的间隔
    rectWidth := textWidth + 30 // 右边矩形的宽度

    // 调整左边矩形的宽度，使其比原来小一些
    leftRectWidth := 40 // 左边矩形宽度减少至 30（你可以根据实际需求调整）

    // 确保宽度是计算出来的矩形总宽度
    totalWidth := leftRectWidth + rectWidth

    svgContent := fmt.Sprintf(`
<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" viewBox="0 0 %d 20">
    <!-- 左边固定部分：背景 #515151，宽度调整为 leftRectWidth，包含左侧小圆角 -->
    <path d="
        M3 0 
        h%d 
        v20 
        h-%d 
        a3 3 0 0 1 -3 -3 
        v-14 
        a3 3 0 0 1 3 -3 
        z" fill="#515151" />
    <text x="10" y="15" font-size="12" fill="#ffffff">UA</text>

    <!-- 右边动态部分：背景 #95c10d -->
    <path d="
        M%d 0 
        h%d 
        a3 3 0 0 1 3 3 
        v14 
        a3 3 0 0 1 -3 3 
        h-%d 
        v-20 
        z" fill="#95c10d" />
    <text x="%d" y="15" font-size="12" fill="#ffffff">%s</text>
</svg>`, totalWidth, totalWidth, leftRectWidth-3, leftRectWidth-3, leftRectWidth, rectWidth-3, rectWidth-3, leftRectWidth+10, uaInfo)

    return svgContent
}
// 判断用户代理并获取操作系统和浏览器信息
func getUAInfo(userAgent string) (string, string) {
	// 操作系统信息提取
	osPatterns := []struct {
		Name    string
		Pattern string
	}{
		{"Windows 10", `Windows NT 10\.0`},
		{"Windows 8.1", `Windows NT 6\.3`},
		{"Windows 8", `Windows NT 6\.2`},
		{"Windows 7", `Windows NT 6\.1`},
		{"Windows Vista", `Windows NT 6\.0`},
		{"Windows XP", `Windows NT 5\.1|Windows XP`},
		{"Mac OS X", `Mac OS X ([\d_\.]+)`},
		{"iPhone", `iPhone OS ([\d_\.]+)`},
		{"iPad", `iPad.*CPU OS ([\d_\.]+)`},
		{"Android", `Android ([\d\.]+)`},
		{"Linux", `Linux`},
	}

	operatingSystem := "未知操作系统"
	for _, os := range osPatterns {
		re := regexp.MustCompile(os.Pattern)
		match := re.FindStringSubmatch(userAgent)
		if len(match) > 0 {
			if len(match) > 1 {
				operatingSystem = fmt.Sprintf("%s %s", os.Name, match[1])
			} else {
				operatingSystem = os.Name
			}
			break
		}
	}

	// 浏览器信息提取
	browserPatterns := []struct {
		Name    string
		Pattern string
	}{
		{"Firefox", `Firefox/([\d\.]+)`},
		{"Chrome", `Chrome/([\d\.]+)`},
		{"Safari", `Safari/([\d\.]+)`},
		{"Edge", `Edg/([\d\.]+)`},
		{"IE", `MSIE ([\d\.]+)`},
		{"VivoBrowser", `VivoBrowser/([\d\.]+)`},
		{"Opera", `OPR/([\d\.]+)`},
	}

	browser := "未知浏览器"
	for _, br := range browserPatterns {
		re := regexp.MustCompile(br.Pattern)
		match := re.FindStringSubmatch(userAgent)
		if len(match) > 0 {
			browser = fmt.Sprintf("%s %s", br.Name, match[1])
			break
		}
	}

	return operatingSystem, browser
}


func main() {
    
    var (
        port    int
        showHelp bool
        showVersion bool
	daemon   bool
        email   string
        username   string
        password   string
        
    )

    // 使用flag包解析命令行参数
    flag.IntVar(&port, "p", 8080, "监听端口")
    flag.StringVar(&dataDir, "d", "", "指定数据存放目录路径")
    flag.StringVar(&dbDir, "db", "", "指定IP地址离线数据存放目录路径")
    flag.StringVar(&logDir, "log", "", "指定日志目录路径")
    flag.StringVar(&username, "u", "admin", "指定管理页面账户名")
    flag.StringVar(&password, "w", "admin", "指定管理页面密码")
    flag.BoolVar(&admin, "admin", false, "启用管理员模式")
    flag.StringVar(&email, "e", "请修改为你的邮箱", "指定邮箱")
    flag.BoolVar(&daemon, "daemon", false, "以后台模式运行")
    flag.BoolVar(&showHelp, "h", false, "帮助信息")
    flag.BoolVar(&showHelp, "help", false, "帮助信息")
    flag.BoolVar(&showVersion, "v", false, "版本号")
    flag.BoolVar(&showVersion, "version", false, "版本号")
    flag.Parse()
    
    //打印帮助信息
    if showHelp {
       colorText := func(color int, message string) string {
		return fmt.Sprintf("\x1b[1;%dm%s\x1b[0m", color, message)
	}

	fmt.Printf("\nUsage: \n\n")
	fmt.Printf("  %-16s %-14s %s\n", colorText(36, "-p"), colorText(34, "[端口号]"), "监听指定端口号")
	fmt.Printf("  %-16s %-14s %s\n", colorText(36, "-d"), colorText(34, "[文件路径]"), "指定数据存放的目录路径，默认当前程序路径的./short_data文件夹")
	fmt.Printf("  %-16s %-14s %s\n", colorText(36, "-db"), colorText(34, "[文件路径]"), "指定IP地址离线数据存放的目录路径，默认/tmp文件夹")
	fmt.Printf("  %-16s %-14s %s\n", colorText(36, "-log"), colorText(34, "[文件路径]"), "启用日志，并指定日志存放的目录路径")
	fmt.Printf("  %-16s %-14s %s\n", colorText(36, "-admin"), "", "启用管理员后台页面")
	fmt.Printf("  %-16s %-14s %s\n", colorText(36, "-e"), colorText(34, "[邮箱地址]"), "指定邮箱地址，修改页面的邮箱地址")
	fmt.Printf("  %-16s %-14s %s\n", colorText(36, "-u"), colorText(34, "[账户名]"), "指定管理页面的登陆账户名")
	fmt.Printf("  %-16s %-14s %s\n", colorText(36, "-w"), colorText(34, "[密码]"), "指定管理页面的登陆密码")
	fmt.Printf("  %-16s %-14s %s\n", colorText(36, "-daemon"), "", "以后台模式运行")
	fmt.Printf("  %-16s %-14s %s\n", colorText(36, "-v"), "", "版本号")
	fmt.Printf("  %-16s %-14s %s\n", colorText(36, "-h"), "", "帮助信息")
	
       return
   }
    
    //打印版本信息
    if showVersion {
       fmt.Println("Version:", Version)
       fmt.Println("Go Version:", runtime.Version())
       return
    }

    if daemon {
		runAsDaemon()
    }
    if email != "" {
		os.Setenv("Email", email)
    }
    authCredentials = map[string]string{username: password}
    // 获取当前二进制文件的目录并设为数据存放目录的/short_data子目录
    if dataDir == "" {
        exePath, err := filepath.Abs(os.Args[0])
        if err != nil {
            log.Fatalf("无法获取当前二进制文件的路径: %v", err)
        }
        dataDir = filepath.Join(filepath.Dir(exePath), "short_data")
    }

    // 获取IP离线数据存放目录
    if dbDir == "" {
        dbDir = "/tmp" // 默认路径为 /tmp
    }
    if _, err := os.Stat(dbDir); os.IsNotExist(err) {
    err := os.MkdirAll(dbDir, 0755)
    if err != nil {
        fmt.Println("无法创建IP离线数据存放目录:", err)
    }
    }
    // 如果 dbDir 最后没有 /，则加上 /
    if !strings.HasSuffix(dbDir, "/") {
	dbDir = dbDir + "/"
    }
    QQWryPath        = dbDir + "qqwry.dat"
    ZXIPv6WryPath    = dbDir + "zxipv6wry.db"
    GeoLite2CityPath = dbDir + "GeoLite2-City.mmdb"
    IPIPFreePath     = dbDir + "ipipfree.ipdb"
    Ip2RegionPath    = dbDir + "ip2region.xdb"
    CdnPath    = dbDir + "cdn.yml"
    Ip2locationPath = dbDir + "IP2LOCATION-LITE-DB3.IPV6.BIN"
    
    // 初始化各个查询实例
	geoip2Instance, _ = geoip.NewGeoIP(GeoLite2CityPath)
	qqwryInstance, _ = qqwry.NewQQwry(QQWryPath)
	ipipInstance, _ = ipip.NewIPIP(IPIPFreePath)
	ip2regionInstance, _ = ip2region.NewIp2Region(Ip2RegionPath)
	zxipv6wryInstance, _ = zxipv6wry.NewZXwry(ZXIPv6WryPath)
	ip2locationInstance, _ = ip2location.NewIP2Location(Ip2locationPath)
	cdnInstance, _ = cdn.NewCDN(CdnPath)
    
    // 创建数据存放目录（如果不存在）
    if _, err := os.Stat(dataDir); os.IsNotExist(err) {
        if err := os.MkdirAll(dataDir, 0755); err != nil {
            log.Fatalf("无法创建数据目录: %v", err)
        }
    }
    //设置日志处理文件
    setupLogging(logDir)
    //初始统计数据文件
    dataFilePath := filepath.Join(dataDir, "short_data.json")
    initializeData(dataFilePath)

    // 设置http请求处理程序
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 设置CORS相关头
   	 w.Header().Set("Access-Control-Allow-Origin", "*")  // 允许所有域名访问
    	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")  // 允许的请求方法
    	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")  // 允许的请求头

    	if r.Method == "OPTIONS" {
        	// 如果是OPTIONS请求，直接返回200 OK
        	w.WriteHeader(http.StatusOK)
        	return
    	}
	if r.URL.Path == "/api" {
        	// 处理/api
        	apiHandler(w, r, dataDir)
   	 } else if r.URL.Path == "/" {
        	// 获取客户端的IP地址
        	clientIP := getIP(r)
        
        // 获取请求的id参数
        id := r.URL.Query().Get("id")
	// 获取请求的ip参数，如果有值，则使用该ip值
        ipParam := r.URL.Query().Get("ip")
        if ipParam != "" {
            // 如果ip不为空，查询IP归属地
            ipInfo := queryIP(ipParam)
	    log.Printf("查询归属地： %s", ipInfo)
            // 找到第一个空格的位置，排除IP地址部分
            if idx := strings.Index(ipInfo, " "); idx != -1 {
                ipInfo = ipInfo[idx+1:] // 取空格后面的内容
            }
            w.Header().Set("Content-Type", "text/plain; charset=utf-8")
            w.Write([]byte(ipInfo)) // 返回剩余的内容（排除IP地址部分）
	    return
        }

        if id == "svg" {
            // 如果id是svg，生成SVG图像并返回
            // 查询IP地址信息
	    ipInfo := queryIP(clientIP)
	    log.Printf("生成svg： %s", ipInfo)
            svgContent := generateSVG(ipInfo)
            w.Header().Set("Content-Type", "image/svg+xml")
            w.Header().Set("Cache-Control", "no-cache")
            w.Write([]byte(svgContent))
        } else if id == "ip" {
            // 如果id是ip，直接返回IP地址
            ipInfo := queryIP(clientIP)
	    log.Printf("查询IP： %s", ipInfo)
            w.Header().Set("Content-Type", "text/plain; charset=utf-8")
            w.Write([]byte(ipInfo))
        } else if id == "ua" {
            // 获取用户代理信息
	    userAgent := r.Header.Get("User-Agent")
	    osInfo, browserInfo := getUAInfo(userAgent) // 确保接收函数返回值
	    UAInfo := osInfo + "/" + browserInfo
	    log.Printf("查询UA： %s", UAInfo)
            svgContent := generateUASVG(UAInfo)
            w.Header().Set("Content-Type", "image/svg+xml")
            w.Header().Set("Cache-Control", "no-cache")
            w.Write([]byte(svgContent))
        } else if id == "" {  
        // 处理主页
        indexHandler(w, r)
        }
    } else if r.URL.Path == "/admin" && admin {
		if !isAuthenticated(r) {
			// 如果未认证，重定向到认证页面
			http.Redirect(w, r, authenticationURL, http.StatusSeeOther)
			return
		}
		// 认证成功，处理 /admin 路由
		adminHandler(w, r, dataDir)
	} else if r.URL.Path == authenticationURL {
		// 处理认证路由
		authHandler(w, r)
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
func runAsDaemon() {
	switch runtime.GOOS {
	case "linux", "freebsd":
		if os.Getppid() != 1 {
			cmd := exec.Command(os.Args[0], os.Args[1:]...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			cmd.Stdout, cmd.Stderr, cmd.Stdin = nil, nil, nil
			err := cmd.Start()
			if err != nil {
				log.Fatalf("后台运行失败: %v", err)
			}
			os.Exit(0) 
		}

	case "windows":
		cmd := exec.Command(os.Args[0], os.Args[1:]...)
		err := cmd.Start()
		if err != nil {
			log.Fatalf("后台运行失败: %v", err)
		}
		os.Exit(0)

	default:
		log.Println("当前系统不支持后台模式")
	}
}
