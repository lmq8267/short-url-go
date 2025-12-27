package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"compress/gzip"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/lmq8267/go-counter-badge/badge"
	"github.com/natefinch/lumberjack"
	"github.com/zu1k/nali/pkg/cdn"
	"github.com/zu1k/nali/pkg/geoip"
	"github.com/zu1k/nali/pkg/ip2location"
	"github.com/zu1k/nali/pkg/ip2region"
	"github.com/zu1k/nali/pkg/ipip"
	"github.com/zu1k/nali/pkg/qqwry"
	"github.com/zu1k/nali/pkg/zxipv6wry"
)

//go:embed static/*
var content embed.FS

var (
	dataDir string
	dbDir   string
	admin   bool
	logDir  string
	// 错误尝试限制和锁定时间
	maxAttempts       = 5
	lockoutDuration   = 10 * time.Minute
	authenticationURL = "/admin-auth"
	authCredentials   = map[string]string{}
	lockoutData       = struct {
		sync.RWMutex
		attempts int
		lockout  time.Time
	}{}
	// 认证 cookie 的设置
	authCookieName  = "authenticated"
	authCookieValue = "true"
	authCookieAge   = 10 * time.Minute // 认证 cookie 的有效期
	ipCookieName    = "auth-ip"
	ipCookieValue   = "" // 动态设置

	redisClient   *redis.Client
	redisEnabled  bool
	redisAddr     string
	redisUsername string
	redisPassword string
	redisPrefix   string
	redisCtx      = context.Background()
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

	geoip2Instance      *geoip.GeoIP
	qqwryInstance       *qqwry.QQwry
	ipipInstance        *ipip.IPIPFree
	ip2regionInstance   *ip2region.Ip2Region
	zxipv6wryInstance   *zxipv6wry.ZXwry
	ip2locationInstance *ip2location.IP2Location
	cdnInstance         *cdn.CDN
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
	ClientIP         string `json:"client_ip"`
	Expiration       string `json:"expiration"`
	BurnAfterReading string `json:"burn_after_reading"`
	Type             string `json:"type"`
	LastUpdate       string `json:"last_update"`
}

// 定义根目录请求的数据结构
type Data struct {
	TotalRules       int    `json:"total_rules"`
	TodayNewRules    int    `json:"today_new_rules"`
	LastRuleUpdate   string `json:"last_rule_update"`
	TotalVisits      int    `json:"total_visits"`
	TodayVisits      int    `json:"today_visits"`
	LastVisitsUpdate string `json:"last_visits_update"`
	Email            string `json:"email"`
	Img              string `json:"img"`
}

// ApiResponse 是响应体的结构
type ApiResponse struct {
	Type     string `json:"type"`
	ShortURL string `json:"short_url"`
	URLName  string `json:"URL_NAME"`
}

// 存储接口
type Storage interface {
	SaveRule(code string, req ApiRequest) error
	LoadRule(code string) (ApiRequest, bool, error)
	DeleteRule(code string) error
	ListRules() ([]ApiRequest, error)
	SaveStats(data Data) error
	LoadStats() (Data, error)
}

// 本地文件存储实现
type FileStorage struct {
	dataDir string
}

type gzipResponseWriter struct {  
    http.ResponseWriter  
    writer *gzip.Writer  
}  
  
func (w gzipResponseWriter) Write(b []byte) (int, error) {  
    return w.writer.Write(b)  
}

func NewFileStorage(dataDir string) *FileStorage {
	return &FileStorage{dataDir: dataDir}
}

func (fs *FileStorage) SaveRule(code string, req ApiRequest) error {
	filePath := filepath.Join(fs.dataDir, code+".json")
	data, err := json.MarshalIndent(req, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(filePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return ioutil.WriteFile(filePath, data, 0644)
}

func (fs *FileStorage) LoadRule(code string) (ApiRequest, bool, error) {
	filePath := filepath.Join(fs.dataDir, code+".json")
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return ApiRequest{}, false, nil
		}
		return ApiRequest{}, false, err
	}

	var req ApiRequest
	err = json.Unmarshal(fileData, &req)
	return req, true, err
}

func (fs *FileStorage) DeleteRule(code string) error {
	filePath := filepath.Join(fs.dataDir, code+".json")
	return os.Remove(filePath)
}

func (fs *FileStorage) ListRules() ([]ApiRequest, error) {
	files, err := filepath.Glob(filepath.Join(fs.dataDir, "*.json"))
	if err != nil {
		return nil, err
	}

	var allData []ApiRequest
	for _, file := range files {
		if filepath.Base(file) == "short_data.json" {
			continue
		}

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

	return allData, nil
}

func (fs *FileStorage) SaveStats(data Data) error {
	dataFilePath := filepath.Join(fs.dataDir, "short_data.json")
	file, err := os.OpenFile(dataFilePath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Seek(0, 0); err != nil {
		return err
	}
	if err := file.Truncate(0); err != nil {
		return err
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func (fs *FileStorage) LoadStats() (Data, error) {
	dataFilePath := filepath.Join(fs.dataDir, "short_data.json")
	initializeData(dataFilePath)

	file, err := os.Open(dataFilePath)
	if err != nil {
		return Data{}, err
	}
	defer file.Close()

	var data Data
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&data)
	return data, err
}

// Redis存储实现
type RedisStorage struct {
	prefix string
}

func NewRedisStorage(prefix string) *RedisStorage {
	return &RedisStorage{prefix: prefix}
}

func (rs *RedisStorage) getRuleKey(code string) string {
	return fmt.Sprintf("%s:rule:%s", rs.prefix, code)
}

func (rs *RedisStorage) getStatsKey() string {
	return fmt.Sprintf("%s:stats", rs.prefix)
}

func (rs *RedisStorage) SaveRule(code string, req ApiRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return redisClient.Set(redisCtx, rs.getRuleKey(code), data, 0).Err()
}

func (rs *RedisStorage) LoadRule(code string) (ApiRequest, bool, error) {
	data, err := redisClient.Get(redisCtx, rs.getRuleKey(code)).Result()
	if err != nil {
		if err == redis.Nil {
			return ApiRequest{}, false, nil
		}
		return ApiRequest{}, false, err
	}

	var req ApiRequest
	err = json.Unmarshal([]byte(data), &req)
	return req, true, err
}

func (rs *RedisStorage) DeleteRule(code string) error {
	return redisClient.Del(redisCtx, rs.getRuleKey(code)).Err()
}

func (rs *RedisStorage) ListRules() ([]ApiRequest, error) {
	pattern := fmt.Sprintf("%s:rule:*", rs.prefix)
	keys, err := redisClient.Keys(redisCtx, pattern).Result()
	if err != nil {
		return nil, err
	}

	var allData []ApiRequest
	for _, key := range keys {
		data, err := redisClient.Get(redisCtx, key).Result()
		if err != nil {
			log.Printf("无法读取Redis键 %s: %v", key, err)
			continue
		}

		var req ApiRequest
		if err := json.Unmarshal([]byte(data), &req); err != nil {
			log.Printf("无法解析Redis键 %s的数据: %v", key, err)
			continue
		}

		allData = append(allData, req)
	}

	return allData, nil
}

func (rs *RedisStorage) SaveStats(data Data) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return redisClient.Set(redisCtx, rs.getStatsKey(), jsonData, 0).Err()
}

func (rs *RedisStorage) LoadStats() (Data, error) {
	data, err := redisClient.Get(redisCtx, rs.getStatsKey()).Result()
	if err != nil {
		if err == redis.Nil {
			// 如果Redis中没有统计数据，返回默认值
			return Data{}, nil
		}
		return Data{}, err
	}

	var stats Data
	err = json.Unmarshal([]byte(data), &stats)
	return stats, err
}

// 混合存储实现（Redis可用时只使用Redis，不可用时使用本地文件）
type HybridStorage struct {
	redis *RedisStorage
	file  *FileStorage
}

func NewHybridStorage(redis *RedisStorage, file *FileStorage) *HybridStorage {
	return &HybridStorage{redis: redis, file: file}
}

func (hs *HybridStorage) SaveRule(code string, req ApiRequest) error {  
    var redisErr, fileErr error  
      
    if redisEnabled {  
        // 保存到Redis  
        redisErr = hs.redis.SaveRule(code, req)  
        if redisErr != nil {  
            log.Printf("Redis保存失败: %v", redisErr)  
        }  
    }  
      
    // 始终保存到本地文件  
    fileErr = hs.file.SaveRule(code, req)  
    if fileErr != nil {  
        log.Printf("本地文件保存失败: %v", fileErr)  
    }  
      
    // 如果都失败才返回错误  
    if redisErr != nil && fileErr != nil {  
        return fmt.Errorf("Redis和本地文件保存都失败: Redis错误=%v, 文件错误=%v", redisErr, fileErr)  
    }  
      
    return nil  
}

func (hs *HybridStorage) LoadRule(code string) (ApiRequest, bool, error) {  
    // 优先从本地文件读取  
    req, found, err := hs.file.LoadRule(code)  
    if err != nil {  
        log.Printf("本地文件读取失败: %v，回退到Redis", err)  
        // 本地失败时，回退到Redis  
        if redisEnabled {  
            return hs.redis.LoadRule(code)  
        }  
        return req, found, err  
    }  
    return req, found, nil  
}

func (hs *HybridStorage) DeleteRule(code string) error {  
    var redisErr, fileErr error  
      
    if redisEnabled {  
        // 从Redis删除  
        redisErr = hs.redis.DeleteRule(code)  
        if redisErr != nil {  
            log.Printf("Redis删除失败: %v", redisErr)  
        }  
    }  
      
    // 从本地文件删除  
    fileErr = hs.file.DeleteRule(code)  
    if fileErr != nil {  
        log.Printf("本地文件删除失败: %v", fileErr)  
    }  
      
    // 如果都失败才返回错误  
    if redisErr != nil && fileErr != nil {  
        return fmt.Errorf("Redis和本地文件删除都失败: Redis错误=%v, 文件错误=%v", redisErr, fileErr)  
    }  
      
    return nil  
}

func (hs *HybridStorage) ListRules() ([]ApiRequest, error) {
	if redisEnabled {
		// 优先从从本地数据目录获取
		rules, err := hs.file.ListRules()
		if err != nil {
			log.Printf("本地文件列表获取失败: %v，回退到Redis", err)
			// 本地文件失败时，回退到Redis
			return hs.redis.ListRules()
		}
		return rules, nil
	}
	// Redis不可用时，从本地文件获取列表
	return hs.file.ListRules()
}

func (hs *HybridStorage) SaveStats(data Data) error {
	if redisEnabled {
		// Redis可用时，同时保存到Redis和本地文件
		var redisErr, fileErr error

		// 保存到Redis
		redisErr = hs.redis.SaveStats(data)
		if redisErr != nil {
			log.Printf("Redis保存统计数据失败: %v", redisErr)
		}

		// 保存到本地文件
		fileErr = hs.file.SaveStats(data)
		if fileErr != nil {
			log.Printf("本地文件保存统计数据失败: %v", fileErr)
		}

		// 如果都失败才返回错误
		if redisErr != nil && fileErr != nil {
			return fmt.Errorf("Redis和本地文件保存都失败: Redis错误=%v, 文件错误=%v", redisErr, fileErr)
		}

		return nil
	}
	// Redis不可用时，保存到本地文件
	return hs.file.SaveStats(data)
}

func (hs *HybridStorage) LoadStats() (Data, error) {  
    // 优先从本地文件读取  
    stats, err := hs.file.LoadStats()  
    if err != nil {  
        log.Printf("本地统计数据读取失败: %v，回退到Redis", err)  
        // 本地失败时，回退到Redis  
        if redisEnabled {  
            return hs.redis.LoadStats()  
        }  
        return stats, err  
    }  
    return stats, nil  
}

// 全局存储实例
var storage Storage

// 同步数据（双向智能同步策略 + 同步后统计更新）  
func syncLocalToRedis() {    
    if !redisEnabled {    
        return    
    }    
    
    log.Println("开始双向同步本地short_data与Redis的数据...")    
    
    fileStorage := NewFileStorage(dataDir)    
    redisStorage := NewRedisStorage(redisPrefix)    
    
    // 1. 同步统计数据（已有双向同步逻辑）    
    localStats, err := fileStorage.LoadStats()    
    if err != nil {    
        log.Printf("读取本地统计数据失败: %v", err)    
    } else {    
        redisStats, err := redisStorage.LoadStats()    
        if err != nil {    
            // Redis中没有统计数据，同步本地到Redis    
            if err := redisStorage.SaveStats(localStats); err != nil {    
                log.Printf("保存统计数据到Redis失败: %v", err)    
            }    
        } else {    
            // 比较并同步统计数据    
            localToRedis := localStats.TotalRules > redisStats.TotalRules || localStats.TotalVisits > redisStats.TotalVisits    
            redisToLocal := redisStats.TotalRules > localStats.TotalRules || redisStats.TotalVisits > localStats.TotalVisits    
    
            if localToRedis {    
                if err := redisStorage.SaveStats(localStats); err != nil {    
                    log.Printf("保存统计数据到Redis失败: %v", err)    
                }    
            } else if redisToLocal {    
                if err := fileStorage.SaveStats(redisStats); err != nil {    
                    log.Printf("保存Redis统计数据到本地失败: %v", err)    
                }    
            }    
        }    
    }    
    
    // 2. 获取本地和Redis的所有规则    
    localRules, err := fileStorage.ListRules()    
    if err != nil {    
        log.Printf("读取本地规则数据失败: %v", err)    
        return    
    }    
    
    redisRules, err := redisStorage.ListRules()    
    if err != nil {    
        log.Printf("读取Redis规则数据失败: %v", err)    
        return    
    }    
    
    // 3. 创建映射以便快速查找    
    localRuleMap := make(map[string]ApiRequest)    
    for _, rule := range localRules {    
        localRuleMap[rule.ShortCode] = rule    
    }    
    
    redisRuleMap := make(map[string]ApiRequest)    
    for _, rule := range redisRules {    
        redisRuleMap[rule.ShortCode] = rule    
    }    
    
    syncCount := 0    
    localToRedisCount := 0    
    redisToLocalCount := 0    
    
    // 4. 处理本地规则同步到Redis - 改为每次写入成功就计数    
    for code, localRule := range localRuleMap {    
        redisRule, existsInRedis := redisRuleMap[code]    
          
        shouldSync := false  
          
        if !existsInRedis {    
            // 本地有 → Redis没有：需要同步    
            shouldSync = true  
        } else {    
            // 本地有 → Redis有：比较更新时间    
            localTime, err1 := time.Parse("2006-01-02 15:04:05", localRule.LastUpdate)    
            redisTime, err2 := time.Parse("2006-01-02 15:04:05", redisRule.LastUpdate)    
    
            if err1 != nil || err2 != nil {    
                // 时间解析失败，默认同步    
                shouldSync = true  
            } else if localTime.After(redisTime) {    
                // 本地版本更新，需要同步    
                shouldSync = true  
            }    
        }    
    
        if shouldSync {    
            if err := redisStorage.SaveRule(code, localRule); err != nil {    
                log.Printf("同步规则 %s 到Redis失败: %v", code, err)    
            } else {    
                localToRedisCount++  // 每次写入成功就计数    
                // log.Printf("同步本地规则 %s 到Redis成功", code)    
            }    
        }    
    }    
    
    // 5. 处理Redis规则同步到本地 - 改为每次写入成功就计数    
    for code, redisRule := range redisRuleMap {    
        localRule, existsInLocal := localRuleMap[code]    
          
        shouldSync := false  
          
        if !existsInLocal {    
            // 本地没有 → Redis有：需要同步    
            shouldSync = true  
        } else {    
            // 本地有 → Redis有：比较更新时间    
            localTime, err1 := time.Parse("2006-01-02 15:04:05", localRule.LastUpdate)    
            redisTime, err2 := time.Parse("2006-01-02 15:04:05", redisRule.LastUpdate)    
    
            if err1 != nil || err2 != nil {    
                // 时间解析失败，默认同步    
                shouldSync = true  
            } else if redisTime.After(localTime) {    
                // Redis版本更新，需要同步    
                shouldSync = true  
            }    
        }    
    
        if shouldSync {    
            if err := fileStorage.SaveRule(code, redisRule); err != nil {    
                log.Printf("同步规则 %s 到本地失败: %v", code, err)    
            } else {    
                redisToLocalCount++  // 每次写入成功就计数    
                // log.Printf("同步Redis规则 %s 到本地成功", code)    
            }    
        }    
    }    
    
    syncCount = localToRedisCount + redisToLocalCount    
    log.Printf("双向数据同步完成: 本地→Redis %d 条，Redis→本地 %d 条，总计 %d 条", localToRedisCount, redisToLocalCount, syncCount)    
    
    // 6. 同步完成后重新统计并更新total_rules    
    log.Println("开始重新统计并更新后缀已使用数量...")    
    updateTotalRulesAfterSync()    
}

// 定期检查Redis连接并重连
func startRedisHealthCheck() {
	if !redisEnabled {
		return
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			_, err := redisClient.Ping(redisCtx).Result()
			if err != nil {
				log.Printf("Redis连接检查失败: %v", err)
				// 尝试重新连接
				if initRedis(redisAddr, redisUsername, redisPassword, redisPrefix) {
					log.Println("Redis重新连接成功，开始数据同步")
					syncLocalToRedis()
				}
			}
		}
	}()
}

// 配置文件读取修改，数据中获取指定键的字符串
func getStringValue(data map[string]interface{}, key string, defaultValue string) string {
	if value, ok := data[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue
		}
	}
	return defaultValue
}

// 配置文件读取，数据中获取指定键的数值
func getIntValue(data map[string]interface{}, key string, defaultValue int) int {
	if value, ok := data[key]; ok {
		if floatValue, ok := value.(float64); ok {
			return int(floatValue)
		}
	}
	return defaultValue
}

// 获取背景图片的环境变量，如果不存在则使用默认图片链接
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// 初始统计数据文件
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
		Img:              getEnvWithDefault("SHORT_IMG", "https://img-baofun.zhhainiao.com/pcwallpaper_ugc/static/a613b671bce87bdafae01938c7cad011.jpg"),
	}
	// 从完整路径中拆分目录和文件名
	dataDir := filepath.Dir(dataFilePath)
	dataFileName := filepath.Base(dataFilePath)

	// 检查文件是否存在，以及文件大小是否为 0
	fi, err := os.Stat(dataFilePath)
	if os.IsNotExist(err) || (err == nil && fi.Size() == 0) {
		// 文件不存在或为空，直接创建并写入初始数据
		createAndWrite(dataFilePath, initialData)
		return
	}

	// 文件存在且大小 > 0，则尝试打开并解析
	file, err := os.OpenFile(dataFilePath, os.O_RDWR, 0644)
	if err != nil {
		log.Fatalf("无法打开统计数据文件: %v", err)
	}
	defer file.Close()

	// 读取并解析 JSON
	var rawData map[string]interface{}
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&rawData); err != nil {
		// 解析失败（可能是无效 JSON），重建文件
		log.Printf("统计数据文件内容无效，重建文件: %v", err)
		file.Close()
		createAndWrite(dataFilePath, initialData)
		return
	}

	// 构建现有数据，补齐缺失字段
	existingData := Data{
		TotalRules:       getIntValue(rawData, "total_rules", initialData.TotalRules),
		TodayNewRules:    getIntValue(rawData, "today_new_rules", initialData.TodayNewRules),
		LastRuleUpdate:   getStringValue(rawData, "last_rule_update", initialData.LastRuleUpdate),
		TotalVisits:      getIntValue(rawData, "total_visits", initialData.TotalVisits),
		TodayVisits:      getIntValue(rawData, "today_visits", initialData.TodayVisits),
		LastVisitsUpdate: getStringValue(rawData, "last_visits_update", initialData.LastVisitsUpdate),
		Img:              getEnvWithDefault("SHORT_IMG", getStringValue(rawData, "img", initialData.Img)),
		Email:            getEnvWithDefault("SHORT_EMAIL", getStringValue(rawData, "email", initialData.Email)),
	}

	// 如果日期已变，重置当天计数
	if existingData.LastRuleUpdate != today {
		existingData.LastRuleUpdate = today
		existingData.TodayNewRules = 0
	}
	if existingData.LastVisitsUpdate != today {
		existingData.LastVisitsUpdate = today
		existingData.TodayVisits = 0
	}
	// 如果环境变量 Email 有变化，同步更新
	if envEmail := os.Getenv("Email"); envEmail != "" && existingData.Email != envEmail {
		existingData.Email = envEmail
	}

	// 重新统计 dataDir 目录下的 .json 规则文件数量（不含统计文件本身）
	totalRules := 0
	err = filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(info.Name()) == ".json" && info.Name() != dataFileName {
			totalRules++
		}
		return nil
	})
	if err != nil {
		log.Fatalf("无法统计 .json 文件数量: %v", err)
	}
	existingData.TotalRules = totalRules

	// 将文件内容截断后写入更新后的数据，带缩进
	if _, err := file.Seek(0, 0); err != nil {
		log.Fatalf("无法移动文件指针: %v", err)
	}
	if err := file.Truncate(0); err != nil {
		log.Fatalf("无法截断文件内容: %v", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(existingData); err != nil {
		log.Fatalf("无法更新统计数据文件: %v", err)
	}
}

// createAndWrite 创建文件并写入给定的 Data 对象
func createAndWrite(path string, data Data) {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		log.Fatalf("无法创建目录: %v", err)
	}
	file, err := os.Create(path)
	if err != nil {
		log.Fatalf("无法创建统计数据文件: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		log.Fatalf("无法写入初始统计数据: %v", err)
	}
}

// 随机生成8位字符的后缀
func generateRandomString(n int) string {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// 更新访问统计（同时更新到short_data.json和Redis）
func updateVisitStats() {
	stats, err := storage.LoadStats()
	if err != nil {
		log.Printf("读取统计数据失败: %v", err)
		return
	}

	// 获取当前上海时区日期
	loc := time.FixedZone("CST", 8*60*60)
	currentDate := time.Now().In(loc).Format("2006-01-02")

	// 更新访问统计
	if stats.LastVisitsUpdate != currentDate {
		stats.TodayVisits = 0
	}

	stats.TotalVisits++
	stats.TodayVisits++
	stats.LastVisitsUpdate = currentDate

	// 保存统计数据到混合存储（会同时保存到Redis和文件）
	if err := storage.SaveStats(stats); err != nil {
		log.Printf("保存统计数据失败: %v", err)
	} else {
		// log.Printf("访问统计已更新: TotalVisits=%d, TodayVisits=%d", stats.TotalVisits, stats.TodayVisits)
	}
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

	// 检查文件是否存在
	isNewRule := true
	existingReq, found, err := storage.LoadRule(req.ShortCode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if found {
		isNewRule = false
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

	// 使用存储接口保存规则
	if err := storage.SaveRule(req.ShortCode, req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 如果是新的规则，更新统计数据
	if isNewRule {
		// 读取当前统计数据
		stats, err := storage.LoadStats()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// 获取当前上海时区日期
		loc := time.FixedZone("CST", 8*60*60)
		currentDate := time.Now().In(loc).Format("2006-01-02")

		// 更新统计数据
		if stats.LastRuleUpdate != currentDate {
			stats.TodayNewRules = 0
		}

		stats.TotalRules++
		stats.TodayNewRules++
		stats.LastRuleUpdate = currentDate

		// 保存统计数据
		if err := storage.SaveStats(stats); err != nil {
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

// 统计数据获取函数
func loadStatsWithPriority() (Data, error) {  
    // 优先从本地文件获取统计数据  
    fileStorage := NewFileStorage(dataDir)  
    stats, err := fileStorage.LoadStats()  
    if err == nil {  
        return stats, nil  
    } else {  
        log.Printf("从本地文件获取统计数据失败: %v，回退到Redis", err)  
    }  
  
    // 本地不可用或失败时，使用Redis  
    if redisEnabled {  
        redisStorage := NewRedisStorage(redisPrefix)  
        stats, err := redisStorage.LoadStats()  
        if err == nil {  
            return stats, nil  
        } else {  
            log.Printf("从Redis获取统计数据失败: %v", err)  
        }  
    }  
  
    return Data{}, err  
}

// 同步完成后重新统计并更新total_rules
func updateTotalRulesAfterSync() {
	if !redisEnabled {
		return
	}

	// 从Redis获取所有规则数量
	redisStorage := NewRedisStorage(redisPrefix)
	rules, err := redisStorage.ListRules()
	if err != nil {
		log.Printf("获取Redis规则列表失败: %v", err)
		return
	}

	actualTotalRules := len(rules)
	// log.Printf("Redis中实际规则数量: %d", actualTotalRules)

	// 获取当前统计数据
	currentStats, err := loadStatsWithPriority()
	if err != nil {
		log.Printf("获取当前统计数据失败: %v", err)
		return
	}

	// 更新total_rules
	if currentStats.TotalRules != actualTotalRules {
		currentStats.TotalRules = actualTotalRules
		currentStats.LastRuleUpdate = time.Now().In(time.FixedZone("CST", 8*60*60)).Format("2006-01-02")

		// 同时更新Redis和本地文件
		fileStorage := NewFileStorage(dataDir)

		// 保存到Redis
		if err := redisStorage.SaveStats(currentStats); err != nil {
			log.Printf("更新Redis统计数据失败: %v", err)
		} else {
			// log.Printf("Redis 后缀已使用更新为: %d", actualTotalRules)
		}

		// 保存到本地文件
		if err := fileStorage.SaveStats(currentStats); err != nil {
			log.Printf("更新本地统计数据失败: %v", err)
		} else {
			// log.Printf("本地文件 后缀已使用 更新为: %d", actualTotalRules)
		}
	} else {
		// log.Printf("后缀已使用 已是最新值: %d，无需更新", actualTotalRules)
	}
}

func getHost(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

const ogImageBase64 = "data:image/jpeg;base64,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"

// 默认首页HTML文件
func indexHandler(w http.ResponseWriter, r *http.Request) {
	// 使用新的优先Redis的统计获取逻辑
	data, err := loadStatsWithPriority()
	if err != nil {
		http.Error(w, fmt.Sprintf("无法获取统计数据: %v", err), http.StatusInternalServerError)
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

	// 使用base64图片作为og:image  
    htmlString = strings.ReplaceAll(htmlString, "<head>",   
        `<head>  
        <meta property="og:title" content="简短分享 - 长网址缩短，文本分享，Html单页分享">  
        <meta property="og:description" content="免费的短链接生成服务，支持长网址缩短、文本分享、HTML单页分享">  
        <meta property="og:type" content="website">  
        <meta property="og:url" content="`+getHost(r)+`">  
        <meta property="og:image" content="`+ogImageBase64+`">  
        <meta property="og:image:width" content="431">  
        <meta property="og:image:height" content="357">  
        <meta property="og:site_name" content="简短分享">`)

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

	// 如果路径为空，则返回
	if path == "" {
		errMsg := map[string]string{"error": "空页面！"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errMsg)
		return
	}

	// 使用存储接口读取规则
	apiReq, found, err := storage.LoadRule(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !found {
		// 如果没有找到规则，重定向到根目录
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// 检查expiration字段
	if apiReq.Expiration != "" {
		// 解析expiration时间
		expirationTime, err := time.Parse("2006-01-02 15:04:05", apiReq.Expiration)
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
			// 如果过期，返回"链接已过期"并删除规则
			storage.DeleteRule(path)
			fmt.Fprintf(w, "链接已过期")
			return
		}
	}

	// 检查 burn_after_reading 的值，如果为 "true" 则删除规则
	if apiReq.BurnAfterReading == "true" {
		defer func() {
			storage.DeleteRule(path)
		}()
	}

	// 更新访问统计
	updateVisitStats()

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
		if r.URL.RawQuery != "" {
			apiReq.LongUrl += "?" + r.URL.RawQuery
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
		// ===== 防止 POST 被转成 GET =====
		if r.Method == http.MethodPost {
			// 读取原始请求体
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "读取POST请求体失败: "+err.Error(), http.StatusBadRequest)
				return
			}

			// 创建新的 POST 请求（模拟重定向后浏览器重新访问）
			req, err := http.NewRequest(http.MethodPost, apiReq.LongUrl, bytes.NewReader(body))
			if err != nil {
				http.Error(w, "创建新POST请求失败: "+err.Error(), http.StatusInternalServerError)
				return
			}

			// ===== 重新设置请求头（不要完全复制原来的）=====
			// 模拟浏览器重新访问后的头部
			req.Header.Set("User-Agent", "Mozilla/5.0 (GoRedirect/1.0)")
			req.Header.Set("Accept", "*/*")

			// 如果原请求有 Content-Type，则复制它（保留表单类型）
			if ct := r.Header.Get("Content-Type"); ct != "" {
				req.Header.Set("Content-Type", ct)
			}

			// 如果有自定义认证头或 token，也可以有选择性地复制
			if auth := r.Header.Get("Authorization"); auth != "" {
				req.Header.Set("Authorization", auth)
			}

			// 发起请求
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, "转发 POST 请求失败: "+err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			// ===== 返回目标响应给客户端 =====
			// 复制响应头
			for k, v := range resp.Header {
				w.Header()[k] = v
			}
			w.WriteHeader(resp.StatusCode)

			// 复制响应体
			io.Copy(w, resp.Body)
			return
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
			return
		}
		// 在现有HTML内容中追加OG标签  
    	htmlContent := apiReq.LongUrl
		// 查找head标签并插入OG meta标签  
    	ogTags := `  
    	<meta property="og:title" content="分享内容 - ` + apiReq.ShortCode + `">  
    	<meta property="og:description" content="通过简短分享生成的内容">  
    	<meta property="og:type" content="website">  
    	<meta property="og:url" content="` + getHost(r) + `/` + apiReq.ShortCode + `">  
    	<meta property="og:image" content="` + ogImageBase64 + `">  
    	<meta property="og:site_name" content="简短分享">`  
      
    	// 在<head>标签后插入OG标签  
    	htmlContent = strings.Replace(htmlContent, "<head>", "<head>"+ogTags, 1)
		
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(htmlContent))
	case "page":
		htmlContent, err := content.ReadFile("static/page.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// 追加OG标签到模板文件  
    	ogTags := `  
    	<meta property="og:title" content="分享页面 - ` + apiReq.ShortCode + `">  
    	<meta property="og:description" content="通过简短分享生成的页面内容">  
    	<meta property="og:type" content="website">  
    	<meta property="og:url" content="` + getHost(r) + `/` + apiReq.ShortCode + `">  
    	<meta property="og:image" content="` + ogImageBase64 + `">  
    	<meta property="og:site_name" content="简短分享">`

		responseHtml := strings.Replace(string(htmlContent), "<head>", "<head>"+ogTags, 1)
		responseHtml = strings.Replace(responseHtml, "{长内容}", apiReq.LongUrl, -1)
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
		if r.URL.RawQuery != "" {
			apiReq.LongUrl += "?" + r.URL.RawQuery
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
				Name:     authCookieName,
				Value:    authCookieValue,
				Path:     "/",
				Expires:  time.Now().Add(authCookieAge),
				HttpOnly: true,
			})

			http.SetCookie(w, &http.Cookie{
				Name:     ipCookieName,
				Value:    ip,
				Path:     "/",
				Expires:  time.Now().Add(authCookieAge),
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
							<label>密码: <input type="password" name="password" id="password-input" onfocus="this.type='text'" onblur="this.type='password'" /></label>
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
						<label>密码: <input type="password" name="password" id="password-input" onfocus="this.type='text'" onblur="this.type='password'" /></label>
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
	// 检查客户端是否支持gzip  
    if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {  
        w.Header().Set("Content-Encoding", "gzip")  
        gz := gzip.NewWriter(w)  
        defer gz.Close()  
        w = gzipResponseWriter{ResponseWriter: w, writer: gz}  
    }
	// 处理清理日志请求
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

	// 处理删除请求 - 使用混合存储优先删除Redis
	if r.Method == http.MethodPost && r.FormValue("mode") == "delete" {
		shortCode := r.FormValue("shortcode")
		if shortCode == "" {
			http.Error(w, "错误：缺少必要的参数", http.StatusBadRequest)
			return
		}

		// 使用混合存储删除（优先Redis，失败时回退到本地文件）
		err := storage.DeleteRule(shortCode)
		if err != nil {
			log.Printf("删除规则 %s 失败: %v", shortCode, err)
			http.Error(w, "删除失败", http.StatusInternalServerError)
			return
		}

		// 删除成功后更新total_rules统计
		updateTotalRulesAfterSync()

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("删除成功"))
		return
	}

	// 处理批量删除请求  
if r.Method == http.MethodPost && r.FormValue("mode") == "batch-delete" {  
	shortCodes := r.FormValue("shortcodes")  
	if shortCodes == "" {  
		http.Error(w, "错误：缺少必要的参数", http.StatusBadRequest)  
		return  
	}  
  
	codeList := strings.Split(shortCodes, ",")  
	successCount := 0  
	failCount := 0  
  
	for _, code := range codeList {  
		if code == "" {  
			continue  
		}  
		err := storage.DeleteRule(strings.TrimSpace(code))  
		if err != nil {  
			log.Printf("删除规则 %s 失败: %v", code, err)  
			failCount++  
		} else {  
			successCount++  
		}  
	}  
  
	// 删除成功后更新total_rules统计  
	if successCount > 0 {  
		updateTotalRulesAfterSync()  
	}  
  
	w.WriteHeader(http.StatusOK)  
	w.Write([]byte(fmt.Sprintf("批量删除完成：成功 %d 个，失败 %d 个", successCount, failCount)))  
	return  
}  
  
// 处理删除过期请求  
if r.Method == http.MethodPost && r.FormValue("mode") == "delete-expired" {  
	allData, err := storage.ListRules()  
	if err != nil {  
		http.Error(w, fmt.Sprintf("无法读取规则数据：%v", err), http.StatusInternalServerError)  
		return  
	}  
  
	now := time.Now()  
	successCount := 0  
	failCount := 0  
  
	for _, rule := range allData {  
		if rule.Expiration != "" && rule.Expiration != "null" {  
			expirationTime, err := time.Parse("2006-01-02 15:04:05", rule.Expiration)  
			if err != nil {  
				// 尝试其他时间格式  
				expirationTime, err = time.Parse(time.RFC3339, rule.Expiration)  
				if err != nil {  
					continue  
				}  
			}  
			  
			if expirationTime.Before(now) {  
				err := storage.DeleteRule(rule.ShortCode)  
				if err != nil {  
					log.Printf("删除过期规则 %s 失败: %v", rule.ShortCode, err)  
					failCount++  
				} else {  
					successCount++  
				}  
			}  
		}  
	}  
  
	// 删除成功后更新total_rules统计  
	if successCount > 0 {  
		updateTotalRulesAfterSync()  
	}  
  
	w.WriteHeader(http.StatusOK)  
	w.Write([]byte(fmt.Sprintf("删除过期完成：成功删除 %d 个，失败 %d 个", successCount, failCount)))  
	return  
}

	// 处理编辑请求 - 使用混合存储优先保存到Redis
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

		// 检查规则是否存在
		_, found, err := storage.LoadRule(shortCode)
		if err != nil {
			http.Error(w, "错误：无法读取规则", http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, "错误：规则不存在", http.StatusNotFound)
			return
		}

		// 设置更新时间
		loc := time.FixedZone("CST", 8*60*60)
		data.LastUpdate = time.Now().In(loc).Format("2006-01-02 15:04:05")

		// 使用混合存储保存（优先Redis，失败时回退到本地文件）
		err = storage.SaveRule(shortCode, data)
		if err != nil {
			log.Printf("保存规则 %s 失败: %v", shortCode, err)
			http.Error(w, "错误：无法保存规则", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("修改成功"))
		return
	}

	// 使用混合存储优先读取本地数据
	allData, err := storage.ListRules()
	if err != nil {
		http.Error(w, fmt.Sprintf("无法读取规则数据：%v", err), http.StatusInternalServerError)
		return
	}

	// 生成HTML响应
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	renderAdminPage(w, r, allData)
}

// 生成/admin页面的HTML响应
func renderAdminPage(w http.ResponseWriter, r *http.Request, data []ApiRequest) {
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
    			min-width: fit-content;  
   	 			margin: 0 auto;  
    			padding: 20px;  
    			background-color: #fff;  
    			box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);  
    			border-radius: 8px;  
    			overflow-x: auto;
				max-width: 100vw; /* 防止超出视窗宽度 */
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
				margin: 10px 0;
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
				padding: 6px;
				text-align: center;
				overflow: hidden;
				text-overflow: ellipsis;
			}
			td:nth-child(2) {  
    			width: 300px;  
    			max-width: 300px;  
    			white-space: nowrap;  
    			overflow: hidden;  
    			text-overflow: ellipsis;  
    			word-wrap: break-word;  
    			word-break: break-all;  
			}  
			td:nth-child(2).truncated {  
    			cursor: pointer;  
    			color: #007bff;  
    			text-decoration: underline;  
    			transition: all 0.3s ease;  
			}  
			td:nth-child(2).truncated:hover {  
    			color: #0056b3;  
   				background-color: #f0f8ff;  
			}  
			td:nth-child(2).expanded {  
    			white-space: pre-wrap; /* 保留换行和空格 */
    			max-width: none;  
    			cursor: pointer;  
				color: #000; /* 展开后恢复黑色 */
    			background-color: #f0f8ff;  
			}
			td:last-child {  
    			white-space: nowrap;  
			}  
			td:last-child button {  
    			display: inline-block;  
    			margin: 0 2px;  
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
        			width: 95%;  
        			padding: 10px;  
        			overflow-x: auto; 
					min-width: fit-content;
    			}  
    			table {  
        			min-width: 900px;  
        			font-size: 14px;  
    			}  
    			th, td {  
        			padding: 8px 4px;  
    			}  
    			td:last-child button {  
        			display: block;  
       	 			margin: 2px 0;  
        			width: 100%;  
    			}  
    			td:nth-child(1) {  
        			width: 200px;  
        			max-width: 200px;  
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
		/* 加载弹窗样式 */  
.loading-popup {  
    display: none;  
    position: fixed;  
    top: 0;  
    left: 0;  
    width: 100%;  
    height: 100%;  
    background-color: rgba(0, 0, 0, 0.5);  
    backdrop-filter: blur(5px);  
    z-index: 9999;  
    justify-content: center;  
    align-items: center;  
}  
  
.loading-content {  
    background: white;  
    border-radius: 12px;  
    padding: 30px;  
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);  
    text-align: center;  
    min-width: 200px;  
}  
  
.loading-spinner {  
    width: 40px;  
    height: 40px;  
    border: 4px solid #f3f3f3;  
    border-top: 4px solid #007bff;  
    border-radius: 50%;  
    animation: spin 1s linear infinite;  
    margin: 0 auto 15px;  
}  
  
.loading-text {  
    font-size: 16px;  
    color: #333;  
    font-weight: 500;  
}  
  
@keyframes spin {  
    0% { transform: rotate(0deg); }  
    100% { transform: rotate(360deg); }  
}
.search-button-group {    
    display: flex !important;    
    justify-content: space-between !important;    
    align-items: center !important;    
    margin: 8px 0 !important;    
    flex-wrap: nowrap !important;    
}  
  
.search-input {    
    width: 100% !important;  /* 占用剩余所有空间 */  
    max-width: 900px !important;  /* 设置最大宽度限制 */  
    min-width: 200px !important;  /* 设置最小宽度 */  
    padding: 8px 12px;    
    border: 1px solid #ddd;    
    border-radius: 6px;    
    font-size: 14px;    
    outline: none;    
    transition: border-color 0.3s ease;    
    flex: 1;  /* 关键：让搜索框占用剩余空间 */  
}  
  
.button-group {  
    display: flex !important;  
    gap: 8px;  
    margin: 0 !important;  
    flex-wrap: nowrap !important;  
    align-items: center !important;  
    flex-shrink: 0;  /* 防止按钮组被压缩 */  
}
  
.vue-btn {  
	padding: 8px 16px;  
	border: none;  
	border-radius: 6px;  
	font-size: 14px;  
	font-weight: 500;  
	cursor: pointer;  
	transition: all 0.3s ease;  
	outline: none;  
	position: relative;  
	overflow: hidden;  
}  
  
.vue-btn:disabled {  
	opacity: 0.5;  
	cursor: not-allowed;  
	transform: none !important;  
}  
  
.vue-btn-primary {  
	background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);  
	color: white;  
}  
  
.vue-btn-primary:hover:not(:disabled) {  
	transform: translateY(-2px);  
	box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);  
}  
  
.vue-btn-success {  
	background: linear-gradient(135deg, #84fab0 0%, #8fd3f4 100%);  
	color: #2c5f2d;  
}  
  
.vue-btn-success:hover:not(:disabled) {  
	transform: translateY(-2px);  
	box-shadow: 0 4px 12px rgba(132, 250, 176, 0.4);  
}  
  
.vue-btn-danger {  
	background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);  
	color: white;  
}  
  
.vue-btn-danger:hover:not(:disabled) {  
	transform: translateY(-2px);  
	box-shadow: 0 4px 12px rgba(245, 87, 108, 0.4);  
}  
  
.vue-btn-warning {  
	background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);  
	color: #7a4f01;  
}  
  
.vue-btn-warning:hover:not(:disabled) {  
	transform: translateY(-2px);  
	box-shadow: 0 4px 12px rgba(250, 112, 154, 0.4);  
}  
  
/* 复选框样式 */  
.checkbox-wrapper {  
	display: flex;  
	align-items: center;  
	justify-content: center;  
}  
  
.custom-checkbox {  
	width: 18px;  
	height: 18px;  
	cursor: pointer;  
	position: relative;  
}  
  
.custom-checkbox:checked {  
	accent-color: #667eea;  
}  
  
/* Vue样式弹窗 */  
.vue-modal {  
	display: none;  
	position: fixed;  
	top: 0;  
	left: 0;  
	width: 100%;  
	height: 100%;  
	background: rgba(0, 0, 0, 0.5);  
	z-index: 9999;  
	animation: fadeIn 0.3s ease;  
}  
  
.vue-modal.show {  
	display: flex;  
	justify-content: center;  
	align-items: center;  
}  
  
.vue-modal-content {  
	background: white;  
	border-radius: 12px;  
	padding: 24px;  
	max-width: 400px;  
	width: 90%;  
	box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);  
	animation: slideUp 0.3s ease;  
	position: relative;  
}  
  
.vue-modal-header {  
	font-size: 18px;  
	font-weight: 600;  
	color: #2c3e50;  
	margin-bottom: 16px;  
	text-align: center;  
}  
  
.vue-modal-body {  
	font-size: 14px;  
	color: #5a6c7d;  
	line-height: 1.6;  
	margin-bottom: 24px;  
	text-align: center;  
}  
  
.vue-modal-footer {  
	display: flex;  
	gap: 12px;  
	justify-content: center;  
}  
  
@keyframes fadeIn {  
	from { opacity: 0; }  
	to { opacity: 1; }  
}  
  
@keyframes slideUp {  
	from {   
		opacity: 0;  
		transform: translateY(30px);  
	}  
	to {   
		opacity: 1;  
		transform: translateY(0);  
	}  
}  
  
/* 隐藏的按钮组 */  
.hidden-buttons {  
	display: none;  
}  
  
.hidden-buttons.show {  
	display: flex;  
}
/* 复选框列样式 */  
th:first-child,  
td:first-child {  
    width: 50px !important;  
    min-width: 50px !important;  
    max-width: 50px !important;  
    text-align: center;  
    padding: 8px !important;  
    display: none; /* 默认隐藏整个列 */  
}  
/* 多选模式下显示复选框列 */  
.multi-select-mode th:first-child,  
.multi-select-mode td:first-child {  
    display: table-cell; /* 多选模式下显示 */  
}  

.checkbox-wrapper {    
    display: flex;    
    align-items: center;    
    justify-content: center;    
}
.back-to-top-btn {  
    position: fixed;  
    bottom: 30px;  
    right: 30px;  
    padding: 12px 20px;  
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);  
    color: white;  
    border: none;  
    border-radius: 6px;  /* 改为6px，与其他Vue按钮一致 */  
    cursor: pointer;  
    display: none;  
    align-items: center;  
    justify-content: center;  
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);  
    transition: all 0.3s ease;  
    z-index: 1000;  
    font-size: 16px;  
    font-weight: 600;  
    white-space: nowrap;  
}
  
.back-to-top-btn:hover {  
    transform: translateY(-2px);  
    box-shadow: 0 6px 16px rgba(102, 126, 234, 0.5);  
}  
  
.back-to-top-btn.show {  
    display: flex;  
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
				}
				if (filter === "") {
					// 清空搜索时：先隐藏所有行，然后应用分页  
        			for (i = 1; i < tr.length; i++) {  
            			tr[i].style.display = "none";  
        			} 
        			// 保持当前页数和每页显示数量，重新应用分页  
        			updateTablePagination();  
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
				
				// 重新初始化长链接展开功能    
    			setTimeout(function() {  
        			initLongUrlToggle();  
        			// 如果在多选模式，也要更新复选框状态  
        			if (multiSelectMode) {  
            			updateDeleteButton();  
        			}  
    			}, 100);
				// 重置全选复选框状态  
    			var selectAllCheckbox = document.getElementById("selectAllCheckbox");  
    			if (selectAllCheckbox) {  
        			selectAllCheckbox.checked = false;  
    			}
				// 检查当前页选中状态  
    			if (multiSelectMode) {  
        			updateSelectAllCheckbox();  
    			}
			}

			function isTextTruncated(element) {  
    			return element.scrollWidth > element.clientWidth;  
			}  
  
			function toggleLongUrl(cell) {  
    			if (cell.classList.contains('expanded')) {  
        			cell.classList.remove('expanded');  
        			cell.title = '点击展开完整内容';  
    			} else {  
        			cell.classList.add('expanded');  
        			cell.title = '点击收起内容';  
    			}  
			}
  
			function initLongUrlToggle() {  
    			var longUrlCells = document.querySelectorAll('td:nth-child(2)');  
    			longUrlCells.forEach(function(cell) {  
        			// 检查文本是否被截断  
        			if (isTextTruncated(cell)) {  
            			cell.classList.add('truncated');  
            			cell.title = '点击展开完整内容';  
            			cell.onclick = function() {  
                			toggleLongUrl(this);  
            			};  
        			} else {  
            			// 短链接不添加任何交互  
            			cell.title = '';  
            			cell.onclick = null;  
        			}  
    			});  
			}
			
			function changePageSize() {
				var select = document.getElementById("pageSizeSelect");
				pageSize = parseInt(select.value);
				localStorage.setItem("pageSize", pageSize);
				currentPage = 1;
				updateTablePagination();
			}

			function updatePageSizeSelect() {
				var select = document.getElementById("pageSizeSelect");
				if (!select) {  
        			console.log("pageSizeSelect element not found");  
        			return;  
    			}
				for (var i = 0; i < select.options.length; i++) {
					if (parseInt(select.options[i].value) === pageSize) {
						select.selectedIndex = i;
						break;
					}
				}
			}

			function deleteRow(shortcode) {
				if (confirm("确定要删除此项吗？")) {
					showLoading();
					var deleteBtn = event.target;  
        			var row = deleteBtn.closest('tr');
					var xhr = new XMLHttpRequest();
					xhr.open("POST", "/admin?mode=delete", true);
					xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
					xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
					xhr.send("shortcode=" + encodeURIComponent(shortcode));
					xhr.onload = function() {
						hideLoading();
						if (xhr.status === 200) {
						   if (xhr.responseText.includes('删除成功')) {
						   	  // 成功：移除行并更新统计  
                    		  row.style.display = 'none'; // 先隐藏  
                    		  setTimeout(function() {  
                        			row.remove(); // 然后移除  
                    		  }, 100);
						      alert('删除成功');
						   } else {
						      alert('删除失败');
						   }
						}
					};
					xhr.onerror = function() {  
            			hideLoading(); // 隐藏加载弹窗  
            			alert('网络错误，删除失败');  
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
                    input.value = cells[i].textContent;
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
			var originalValues = {};
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

			showLoading();

			var xhr = new XMLHttpRequest();
			xhr.open("POST", "/admin?mode=edit", true);
			xhr.setRequestHeader("Content-Type", "application/json");
			xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
			xhr.send(JSON.stringify(data));
			xhr.onload = function() {
				hideLoading();
				if (xhr.status === 200) {
				   if (xhr.responseText.includes('修改成功')) {
				   	  // 成功：更新这一行的显示内容  
                	for (var i = 0; i < cells.length - 1; i++) {  
                    	var field = cells[i].getAttribute("data-field");  
                    	if (field) {  
                        	var input = cells[i].querySelector("input, textarea, select");  
                        	cells[i].textContent = input.value;  
                        	cells[i].setAttribute("data-original", input.value);  
                    	}  
                	}  
                	// 恢复编辑按钮状态  
                	row.querySelector("button.edit").style.display = "inline-block";  
               		 row.querySelector("button.submit").style.display = "none";  
                	row.classList.remove("editing");
				      alert('修改成功');
				   } else {
				      alert('修改失败');
				   }
				}
			};
			xhr.onerror = function() {  
        		hideLoading(); // 隐藏加载弹窗  
        		alert('网络错误，修改失败');  
    		};
		}

		function cancelEdit(row) {
			var cells = row.getElementsByTagName("td");
			for (var i = 0; i < cells.length; i++) {
				if (i < cells.length - 1) { // 跳过最后一列（操作按钮）
					var field = cells[i].getAttribute("data-field");
					if (field) {
						cells[i].textContent = cells[i].querySelector("input, textarea, select").value;
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
		var sortOrder = 'asc'; // 'asc' 或 'desc'  
  
		function sortByLastUpdate() {  
    		var table = document.getElementById("dataTable");  
    		var tbody = table.getElementsByTagName("tbody")[0];  
    		var rows = Array.from(tbody.getElementsByTagName("tr"));  
      
    		rows.sort(function(a, b) {  
        		var dateA = a.getElementsByTagName("td")[8].innerText; // 最后更新时间在第9列索引8  
        		var dateB = b.getElementsByTagName("td")[8].innerText;  
          
        		if (!dateA) return 1;  
        		if (!dateB) return -1;  
          
        		var timeA = new Date(dateA).getTime();  
        		var timeB = new Date(dateB).getTime();  
          
        		if (sortOrder === 'asc') {  
            		return timeA - timeB;  
        		} else {  
            		return timeB - timeA;  
        		}  
    		});  
      
    		// 清空tbody并重新添加排序后的行  
    		tbody.innerHTML = '';  
    		rows.forEach(function(row) {  
        		tbody.appendChild(row);  
    		});  
      
    		// 切换排序顺序并更新箭头  
    		sortOrder = sortOrder === 'asc' ? 'desc' : 'asc';  
    		document.getElementById("sortArrow").innerText = sortOrder === 'asc' ? '↓' : '↑';  
      
    		// 重新应用分页  
    		updateTablePagination();  
		}
		var expirationSortOrder = 'asc'; // 'asc' 或 'desc'  
  
function sortByExpiration() {  
    var table = document.getElementById("dataTable");  
    var tbody = table.getElementsByTagName("tbody")[0];  
    var rows = Array.from(tbody.getElementsByTagName("tr"));  
      
    rows.sort(function(a, b) {  
        var dateA = a.getElementsByTagName("td")[5].innerText; // 到期时间在第6列 索引5  
        var dateB = b.getElementsByTagName("td")[5].innerText;  
          
        // 空值处理：将空值放在最后  
        if (!dateA || dateA.trim() === '') return 1;  
        if (!dateB || dateB.trim() === '') return -1;  
          
        var timeA = new Date(dateA).getTime();  
        var timeB = new Date(dateB).getTime();  
          
        if (expirationSortOrder === 'asc') {  
            return timeA - timeB; // 升序：最旧的最新依次往下  
        } else {  
            return timeB - timeA; // 降序：最新到最旧依次往下  
        }  
    });  
      
    // 清空tbody并重新添加排序后的行  
    tbody.innerHTML = '';  
    rows.forEach(function(row) {  
        tbody.appendChild(row);  
    });  
      
    // 切换排序顺序并更新箭头  
    expirationSortOrder = expirationSortOrder === 'asc' ? 'desc' : 'asc';  
    document.getElementById("expirationSortArrow").innerText = expirationSortOrder === 'asc' ? '↓' : '↑';  
      
    // 重新应用分页  
    updateTablePagination();  
}
		function showLoading() {  
    var popup = document.getElementById("loadingPopup");  
    popup.style.display = "flex";  
}  
  
function hideLoading() {  
    var popup = document.getElementById("loadingPopup");  
    popup.style.display = "none";  
}
// 多选功能相关变量  
var multiSelectMode = false;  
  
// 切换多选模式  
function toggleMultiSelect() {  
	multiSelectMode = !multiSelectMode;  
	var table = document.getElementById("dataTable");
	var hiddenButtons = document.getElementById("hiddenButtons");  
	var multiSelectText = document.getElementById("multiSelectText");  
	var checkboxes = document.querySelectorAll(".row-checkbox");  
	var selectAllCheckbox = document.getElementById("selectAllCheckbox");  
	  
	if (multiSelectMode) {  
		table.classList.add("multi-select-mode");  
		hiddenButtons.classList.add("show");  
		multiSelectText.textContent = "关闭多选";  
		// 显示所有复选框  
		checkboxes.forEach(function(checkbox) {  
			checkbox.style.display = "block";  
		});  
		selectAllCheckbox.style.display = "block";  
	} else { 
		table.classList.remove("multi-select-mode");
		hiddenButtons.classList.remove("show");  
		multiSelectText.textContent = "启用多选";  
		// 隐藏所有复选框并取消选中  
		checkboxes.forEach(function(checkbox) {  
			checkbox.style.display = "none";  
			checkbox.checked = false;  
		});  
		selectAllCheckbox.style.display = "none";  
		selectAllCheckbox.checked = false;  
		updateDeleteButton();  
	}  
}  
  
// 全选当前页  
function selectAll() {  
    var checkboxes = document.querySelectorAll("#dataTable tbody tr:not([style*='display: none']) .row-checkbox");  
    var selectAllCheckbox = document.getElementById("selectAllCheckbox");  
    checkboxes.forEach(function(checkbox) {  
        if (checkbox.style.display !== "none") {  
            checkbox.checked = true;  
        }  
    });  
    selectAllCheckbox.checked = true;  
    updateDeleteButton();  
}  
  
// 取消全选当前页  
function deselectAll() {  
    var checkboxes = document.querySelectorAll("#dataTable tbody tr:not([style*='display: none']) .row-checkbox");  
    var selectAllCheckbox = document.getElementById("selectAllCheckbox");  
    checkboxes.forEach(function(checkbox) {  
        checkbox.checked = false;  
    });  
    selectAllCheckbox.checked = false;  
    updateDeleteButton();  
}

// 取消所有页面的选中  
function deselectAllPages() {  
    var checkboxes = document.querySelectorAll(".row-checkbox");  
    var selectAllCheckbox = document.getElementById("selectAllCheckbox");  
      
    checkboxes.forEach(function(checkbox) {  
        checkbox.checked = false;  
    });  
    selectAllCheckbox.checked = false;  
    updateDeleteButton();  
}
  
// 切换全选状态（当前页）  
function toggleSelectAll() {  
    var selectAllCheckbox = document.getElementById("selectAllCheckbox");  
    var checkboxes = document.querySelectorAll("#dataTable tbody tr:not([style*='display: none']) .row-checkbox");  
      
    checkboxes.forEach(function(checkbox) {  
        if (checkbox.style.display !== "none") {  
            checkbox.checked = selectAllCheckbox.checked;  
        }  
    });  
    updateDeleteButton();  
}
  
// 更新删除选中按钮状态  
function updateDeleteButton() {  
	var checkboxes = document.querySelectorAll(".row-checkbox:checked");  
	var deleteBtn = document.getElementById("deleteSelectedBtn");
	var deselectAllPagesBtn = document.getElementById("deselectAllPagesBtn"); 
	  
	if (checkboxes.length > 0) {  
		deleteBtn.disabled = false;
		deselectAllPagesBtn.disabled = false;
		deleteBtn.textContent = "删除选中的 " + checkboxes.length + " 条";
	} else {  
		deleteBtn.disabled = true;
		deselectAllPagesBtn.disabled = true;
		deleteBtn.textContent = "删除选中";
	}  
}

// 检查当前页是否全选并更新表头复选框  
function updateSelectAllCheckbox() {  
    var currentPageCheckboxes = document.querySelectorAll("#dataTable tbody tr:not([style*='display: none']) .row-checkbox");  
    var selectAllCheckbox = document.getElementById("selectAllCheckbox");  
      
    var allChecked = true;  
    var anyChecked = false;  
      
    currentPageCheckboxes.forEach(function(checkbox) {  
        if (checkbox.style.display !== "none") {  
            if (checkbox.checked) {  
                anyChecked = true;  
            } else {  
                allChecked = false;  
            }  
        }  
    });  
      
    // 只有当前页全部选中时才勾选表头复选框  
    selectAllCheckbox.checked = allChecked && anyChecked;  
}
  
// 显示确认弹窗  
function showConfirmModal(title, message, onConfirm) {  
	var modal = document.getElementById("confirmModal");  
	var modalTitle = document.getElementById("modalTitle");  
	var modalMessage = document.getElementById("modalMessage");  
	var confirmBtn = document.getElementById("modalConfirmBtn");  
	  
	modalTitle.textContent = title;  
	modalMessage.textContent = message;  
	  
	// 移除之前的事件监听器  
	var newConfirmBtn = confirmBtn.cloneNode(true);  
	confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);  
	  
	// 添加新的事件监听器  
	newConfirmBtn.addEventListener("click", function() {  
		onConfirm();  
		closeModal();  
	});  
	  
	modal.classList.add("show");  
}  
  
// 关闭弹窗  
function closeModal() {  
	var modal = document.getElementById("confirmModal");  
	modal.classList.remove("show");  
}  
  
// 删除过期项目  
function deleteExpired() {  
	showConfirmModal(  
		"删除过期项目",  
		"确定要删除所有已过期的项目吗？此操作不可恢复！",  
		function() {  
			showLoading();  
			var xhr = new XMLHttpRequest();  
			xhr.open("POST", "/admin?mode=delete-expired", true);  
			xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");  
			xhr.send();  
			xhr.onload = function() {  
				hideLoading();  
				if (xhr.status === 200) {  
					// 获取所有过期的行并移除  
                    var rows = document.querySelectorAll("#dataTable tbody tr");  
                    rows.forEach(function(row) {  
                        var expirationCell = row.getElementsByTagName("td")[5];  
                        if (expirationCell) {  
                            var expirationText = expirationCell.innerText;  
                            if (expirationText && expirationText !== "") {  
                                var expirationTime = new Date(expirationText);  
                                if (expirationTime < new Date()) {  
                                    row.style.display = 'none';  
                                    setTimeout(function() {  
                                        row.remove();  
                                    }, 100);  
                                }  
                            }  
                        }  
                    });  
                    updateTablePagination();  
                    alert(xhr.responseText);  
				} else {  
					alert("删除过期项目失败");  
				}  
			};  
			xhr.onerror = function() {  
				hideLoading();  
				alert("网络错误，操作失败");  
			};  
		}  
	);  
}  
  
// 删除选中项目  
function deleteSelected() {  
	var checkboxes = document.querySelectorAll(".row-checkbox:checked");  
	if (checkboxes.length === 0) {  
		alert("请先选择要删除的项目");  
		return;  
	}  
	  
	var shortCodes = [];  
    var rowsToRemove = [];  
    checkboxes.forEach(function(checkbox) {  
        shortCodes.push(checkbox.value);  
        rowsToRemove.push(checkbox.closest('tr'));  
    });  
	  
	showConfirmModal(  
		"删除选中项目",  
		"确定要删除选中的 " + checkboxes.length + " 个项目吗？此操作不可恢复！",  
		function() {  
			showLoading();  
			var xhr = new XMLHttpRequest();  
			xhr.open("POST", "/admin?mode=batch-delete", true);  
			xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");  
			xhr.send("shortcodes=" + encodeURIComponent(shortCodes.join(",")));  
			xhr.onload = function() {  
				hideLoading();  
				if (xhr.status === 200) {  
					// 移除选中的行  
                    rowsToRemove.forEach(function(row) {  
                        row.style.display = 'none';  
                        setTimeout(function() {  
                            row.remove();  
                        }, 100);  
                    });  
                    updateTablePagination();  
                    alert(xhr.responseText);  
				} else {  
					alert("批量删除失败");  
				}  
			};  
			xhr.onerror = function() {  
				hideLoading();  
				alert("网络错误，操作失败");  
			};  
		}  
	);  
}  
  
// 页面加载时隐藏复选框  
window.onload = function() {  
	var savedPageSize = localStorage.getItem("pageSize");  
	if (savedPageSize) {  
		pageSize = parseInt(savedPageSize);  
	}  
	updatePageSizeSelect();  
	updateTablePagination();  
	// 初始化长链接展开功能  
    initLongUrlToggle();  
	  
	// 隐藏所有复选框  
	var checkboxes = document.querySelectorAll(".row-checkbox");  
	var selectAllCheckbox = document.getElementById("selectAllCheckbox");  
	checkboxes.forEach(function(checkbox) {  
		checkbox.style.display = "none";  
	});  
	if (selectAllCheckbox) {  
		selectAllCheckbox.style.display = "none";  
	}  
};
// 滚动监听和回到顶部功能  
window.addEventListener('scroll', function() {  
    var table = document.getElementById('dataTable');  
    var backToTopBtn = document.getElementById('backToTop');  
      
    if (table) {  
        var tableRect = table.getBoundingClientRect();  
        // 当表头顶部超出视窗时显示按钮  
        if (tableRect.top < 0) {  
            backToTopBtn.classList.add('show');  
        } else {  
            backToTopBtn.classList.remove('show');  
        }  
    }  
});  
  
function scrollToTop() {  
    window.scrollTo({  
        top: 0,  
        behavior: 'smooth'  
    });  
}
		</script>
	</head>
	<body>
		<h2>管理页面</h2>
		<div class="container">
			<div class="search-button-group">  
    			<!-- 按钮组 -->    
    			<div class="button-group">    
        			<button class="vue-btn vue-btn-primary" onclick="toggleMultiSelect()">    
            			<span id="multiSelectText">多选</span>    
        			</button>    
        			<button class="vue-btn vue-btn-danger" onclick="deleteExpired()">删除过期</button>    
        			<div id="hiddenButtons" class="hidden-buttons">    
						<!-- <button class="vue-btn vue-btn-success" onclick="selectAll()">全选</button> --> 
						<!-- <button class="vue-btn vue-btn-warning" onclick="deselectAll()">取消全选</button> --> 
						<button id="deselectAllPagesBtn" class="vue-btn vue-btn-warnin" onclick="deselectAllPages()" disabled>取消所有选中</button>
            			<button id="deleteSelectedBtn" class="vue-btn vue-btn-danger" onclick="deleteSelected()" disabled>删除选中</button>    
        			</div>    
    			</div>  
				<input type="text" id="searchInput" onkeyup="searchTable()" placeholder="搜索关键词..." class="search-input">  
			</div>
			<table id="dataTable">
				<thead>
					<tr>
						<th style="width: 50px;">  
							<div class="checkbox-wrapper">    
        						<input type="checkbox" id="selectAllCheckbox" class="custom-checkbox" onchange="toggleSelectAll()">  
    						</div>
						</th>
						<th>长链接内容</th>
						<th>后缀</th>
						<th>密码</th>
						<th>客户端IP</th>
						<th onclick="sortByExpiration()" style="cursor: pointer;">到期时间 <span id="expirationSortArrow">↕</span></th>
						<th>阅后即焚</th>
						<th>类型</th>
						<th onclick="sortByLastUpdate()" style="cursor: pointer;">最后更新时间 <span id="sortArrow">↕</span></th>
						<th>操作</th>
					</tr>
				</thead>
				<tbody>
					{{range .Data}} 
					<tr>
						<td>  
							<div class="checkbox-wrapper">  
								<input type="checkbox" class="custom-checkbox row-checkbox" value="{{.ShortCode}}" onchange="updateDeleteButton(); updateSelectAllCheckbox()">  
							</div>  
						</td>
						<td data-field="LongUrl" title="点击可展开完整内容">{{.LongUrl}}</td>
						<td>  
    					{{if .ShortCode}}  
        					<a href="{{$.Host}}/{{.ShortCode}}" target="_blank" style="color: #007bff; text-decoration: underline;">{{.ShortCode}}</a>  
    					{{else}}  
        					{{.ShortCode}}  
    					{{end}}  
						</td>
						<td data-field="Password">{{.Password}}</td>
						<td>  
    					{{if .ClientIP}}  
        					<a href="{{$.Host}}?ip={{.ClientIP}}" target="_blank" style="color: #007bff; text-decoration: underline;">{{.ClientIP}}</a>  
    					{{else}}  
        					{{.ClientIP}}  
    					{{end}}  
						</td>
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
				<option value="200">每页 200 项</option>
				<option value="500">每页 500 项</option>
				<option value="1000">每页 1000 项</option>
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
	<!-- Vue样式确认弹窗 -->  
<div id="confirmModal" class="vue-modal">  
	<div class="vue-modal-content">  
		<div class="vue-modal-header" id="modalTitle">确认操作</div>  
		<div class="vue-modal-body" id="modalMessage">确定要执行此操作吗？</div>  
		<div class="vue-modal-footer">  
			<button class="vue-btn vue-btn-primary" onclick="closeModal()">取消</button>  
			<button class="vue-btn vue-btn-danger" id="modalConfirmBtn">确认</button>  
		</div>  
	</div>  
</div>
<!-- 悬浮回到顶部按钮 -->  
<button id="backToTop" class="back-to-top-btn" onclick="scrollToTop()">  
    顶部  
</button>
	<!-- 加载弹窗 -->  
<div id="loadingPopup" class="loading-popup">  
    <div class="loading-content">  
        <div class="loading-spinner"></div>  
        <div class="loading-text">处理中...</div>  
    </div>  
</div>
		<br><br><br>
	</body>
	</html>
	`
	pageContent := strings.ReplaceAll(adminTemplate, "{{LOG_CONTENT}}", logContent)
	// 创建包含Host信息的数据结构
	type AdminData struct {
		Host string
		Data []ApiRequest
	}

	adminData := AdminData{
		Host: getHost(r),
		Data: data,
	}
	// 渲染页面
	tmpl, err := template.New("admin").Parse(pageContent)
	if err != nil {
		http.Error(w, "无法解析模板", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, adminData)
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
			MaxSize:    10,   // MB
			MaxBackups: 1,    // 保留3个旧日志文件
			MaxAge:     28,   // 保留日志文件的最大天数
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

	result, err = queryzxipv6wry(ip)
	if err == nil && result != "" {
		fmt.Println("Zxipv6wry查询结果：", ip, result)
		return ip + " " + result
	}

	result, err = queryIp2Region(ip)
	if err == nil && result != "" {
		fmt.Println("Ip2Region查询结果：", ip, result)
		return ip + " " + result
	}

	result, err = queryGeoip2(ip)
	if err == nil && result != "" {
		fmt.Println("GeoIP查询结果：", ip, result)
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

	// 如果所有查询都没有结果，使用原IP
	fmt.Println("未查询到IP区域信息，返回原始IP：", ip)
	return ip
}

// 生成SVG内容
func generateSVG(clientIP string) ([]byte, bool) {
	// 创建 badge 结构体
	flatBadge := badge.Badge{
		FontType:             badge.Verdana,
		LeftText:             "IP",
		LeftTextColor:        "#fff",
		LeftBackgroundColor:  "#515151",
		RightText:            clientIP,
		RightTextColor:       "#fff",
		RightBackgroundColor: "#95c10d",
		XRadius:              "3", // 圆角
		YRadius:              "3",
	}

	// 使用 badge writer 渲染
	badgeWriter, err := badge.NewWriter()
	if err != nil {
		// 只记录错误，返回失败标记
		log.Printf("创建badge writer失败: %v", err)
		return nil, false
	}

	svg, err := badgeWriter.RenderFlatBadge(flatBadge)
	if err != nil {
		// 只记录错误，返回失败标记
		log.Printf("渲染IP SVG失败: %v", err)
		return nil, false
	}

	return svg, true
}

func generateUASVG(uaInfo string) ([]byte, bool) {
	flatBadge := badge.Badge{
		FontType:             badge.Verdana,
		LeftText:             "UA",
		LeftTextColor:        "#fff",
		LeftBackgroundColor:  "#515151",
		RightText:            uaInfo,
		RightTextColor:       "#fff",
		RightBackgroundColor: "#95c10d",
		XRadius:              "3", // 圆角
		YRadius:              "3",
	}

	// 使用 badge writer 渲染
	badgeWriter, err := badge.NewWriter()
	if err != nil {
		// 只记录错误，返回失败标记
		log.Printf("创建badge writer失败: %v", err)
		return nil, false
	}

	svg, err := badgeWriter.RenderFlatBadge(flatBadge)
	if err != nil {
		// 只记录错误，返回失败标记
		log.Printf("渲染UA SVG失败: %v", err)
		return nil, false
	}

	return svg, true
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

// 初始化Redis连接
func initRedis(addr, username, password, prefix string) bool {
	if addr == "" {
		return false
	}

	options := &redis.Options{
		Addr: addr,
		DB:   0, // 默认数据库
	}

	if username != "" {
		options.Username = username
	}
	if password != "" {
		options.Password = password
	}

	client := redis.NewClient(options)

	// 测试连接
	_, err := client.Ping(redisCtx).Result()
	if err != nil {
		log.Printf("Redis连接失败: %v，将使用本地文件存储", err)
		return false
	}

	redisClient = client
	redisEnabled = true
	redisAddr = addr
	redisUsername = username
	redisPassword = password
	redisPrefix = prefix

	log.Printf("Redis连接成功: %s，前缀: %s", addr, prefix)
	return true
}

// 关闭Redis连接
func closeRedis() {
	if redisClient != nil {
		redisClient.Close()
	}
}

// 异步初始化所有IP数据库实例
func initializeIPDatabases() {
	log.Println("开始初始化IP数据库...")

	// 初始化各个查询实例
	var err error
	geoip2Instance, err = geoip.NewGeoIP(GeoLite2CityPath)
	if err != nil {
		log.Printf("GeoIP2数据库初始化失败: %v", err)
	} else {
		log.Println("GeoIP2数据库初始化成功")
	}

	qqwryInstance, err = qqwry.NewQQwry(QQWryPath)
	if err != nil {
		log.Printf("QQwry数据库初始化失败: %v", err)
	} else {
		log.Println("QQwry数据库初始化成功")
	}

	ipipInstance, err = ipip.NewIPIP(IPIPFreePath)
	if err != nil {
		log.Printf("IPIP数据库初始化失败: %v", err)
	} else {
		log.Println("IPIP数据库初始化成功")
	}

	ip2regionInstance, err = ip2region.NewIp2Region(Ip2RegionPath)
	if err != nil {
		log.Printf("IP2Region数据库初始化失败: %v", err)
	} else {
		log.Println("IP2Region数据库初始化成功")
	}

	zxipv6wryInstance, _ = zxipv6wry.NewZXwry(ZXIPv6WryPath)
	if err != nil {
		log.Printf("ZXIPv6数据库初始化失败: %v", err)
	} else {
		log.Println("ZXIPv6数据库初始化成功")
	}

	ip2locationInstance, err = ip2location.NewIP2Location(Ip2locationPath)
	if err != nil {
		log.Printf("IP2Location数据库初始化失败: %v", err)
	} else {
		log.Println("IP2Location数据库初始化成功")
	}

	cdnInstance, err = cdn.NewCDN(CdnPath)
	if err != nil {
		log.Printf("CDN数据库初始化失败: %v", err)
	} else {
		log.Println("CDN数据库初始化成功")
	}

	// log.Println("IP数据库异步初始化完成")
}

func runAsDaemon() {
	switch runtime.GOOS {
	case "linux", "freebsd":
		if os.Getppid() != 1 {
			cmd := exec.Command(os.Args[0], os.Args[1:]...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			cmd.Stdout, cmd.Stderr, cmd.Stdin = nil, nil, nil
			
			// 显式传递环境变量  
            cmd.Env = os.Environ()
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

func main() {

	var (
		port        int
		showHelp    bool
		showVersion bool
		daemon      bool
		email       string
		username    string
		password    string
		// 新增Redis参数
		redisAddrFlag     string
		redisUsernameFlag string
		redisPasswordFlag string
		redisPrefixFlag   string
	)

	// 使用flag包解析命令行参数
	flag.IntVar(&port, "p", 8080, "监听端口")
	flag.StringVar(&dataDir, "d", "", "指定本地数据存放目录路径，默认当前程序路径的./short_data文件夹")
	flag.StringVar(&dbDir, "db", "", "指定IP地址库离线数据存放目录路径，默认/tmp文件夹")
	flag.StringVar(&logDir, "log", "", "指定日志目录路径")
	flag.StringVar(&username, "u", "admin", "指定管理页面账户名")
	flag.StringVar(&password, "w", "admin", "指定管理页面密码")
	flag.BoolVar(&admin, "admin", false, "启用管理页面管理短链数据，网页路径/admin")
	flag.StringVar(&email, "e", "请修改为你的邮箱", "指定网页中的联系邮箱")
	flag.BoolVar(&daemon, "daemon", false, "以后台模式运行")
	// 新增Redis参数
	flag.StringVar(&redisAddrFlag, "redis-addr", "", "Redis服务器地址 (例如: localhost:6379)")
	flag.StringVar(&redisUsernameFlag, "redis-user", "", "Redis用户名")
	flag.StringVar(&redisPasswordFlag, "redis-pass", "", "Redis密码")
	flag.StringVar(&redisPrefixFlag, "redis-pre", "short", "Redis数据前缀，默认为short，连接相同的redis数据库时用于区分不同应用")

	flag.BoolVar(&showHelp, "h", false, "帮助信息")
	flag.BoolVar(&showHelp, "help", false, "帮助信息")
	flag.BoolVar(&showVersion, "v", false, "版本号")
	flag.BoolVar(&showVersion, "version", false, "版本号")
	flag.Parse()

	// 环境变量优先级处理
	if envPort := os.Getenv("SHORT_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			port = p
		}
	}
	if envDataDir := os.Getenv("SHORT_DATA_DIR"); envDataDir != "" {
		dataDir = envDataDir
	}
	if envDbDir := os.Getenv("SHORT_DB_DIR"); envDbDir != "" {
		dbDir = envDbDir
	}
	if envLogDir := os.Getenv("SHORT_LOG_DIR"); envLogDir != "" {
		logDir = envLogDir
	}
	if envAdmin := os.Getenv("SHORT_ADMIN"); envAdmin != "" {
		admin = envAdmin == "true" || envAdmin == "1"
	}
	if envEmail := os.Getenv("SHORT_EMAIL"); envEmail != "" {
		email = envEmail
	}
	if envUsername := os.Getenv("SHORT_USERNAME"); envUsername != "" {
		username = envUsername
	}
	if envPassword := os.Getenv("SHORT_PASSWORD"); envPassword != "" {
		password = envPassword
	}
	if envDaemon := os.Getenv("SHORT_DAEMON"); envDaemon != "" {
		daemon = envDaemon == "true" || envDaemon == "1"
	}
	if envRedisAddr := os.Getenv("SHORT_REDIS_ADDR"); envRedisAddr != "" {
		redisAddrFlag = envRedisAddr
	}
	if envRedisUser := os.Getenv("SHORT_REDIS_USER"); envRedisUser != "" {
		redisUsernameFlag = envRedisUser
	}
	if envRedisPass := os.Getenv("SHORT_REDIS_PASS"); envRedisPass != "" {
		redisPasswordFlag = envRedisPass
	}
	if envRedisPre := os.Getenv("SHORT_REDIS_PRE"); envRedisPre != "" {
		redisPrefixFlag = envRedisPre
	}

	//打印帮助信息
	if showHelp {
		colorText := func(color int, message string) string {
			return fmt.Sprintf("\x1b[1;%dm%s\x1b[0m", color, message)
		}

		// 使用固定宽度确保对齐
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

		return
	}

	//打印版本信息
	if showVersion {
		fmt.Println("Version:", Version)
		fmt.Println("Go Version:", runtime.Version())
		return
	}
	
	//设置日志处理文件
	setupLogging(logDir)
	
	// 初始化Redis连接
	redisConnected := initRedis(redisAddrFlag, redisUsernameFlag, redisPasswordFlag, redisPrefixFlag)

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
	QQWryPath = dbDir + "qqwry.dat"
	ZXIPv6WryPath = dbDir + "zxipv6wry.db"
	GeoLite2CityPath = dbDir + "GeoLite2-City.mmdb"
	IPIPFreePath = dbDir + "ipipfree.ipdb"
	Ip2RegionPath = dbDir + "ip2region.xdb"
	CdnPath = dbDir + "cdn.yml"
	Ip2locationPath = dbDir + "IP2LOCATION-LITE-DB3.IPV6.BIN"

	// 初始化各个查询实例
	go initializeIPDatabases()

	// 创建数据存放目录（如果不存在）
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			log.Fatalf("无法创建数据目录: %v", err)
		}
	}

	// 初始化存储层
	fileStorage := NewFileStorage(dataDir)
	var redisStorage *RedisStorage
	if redisConnected {
		redisStorage = NewRedisStorage(redisPrefix)
		storage = NewHybridStorage(redisStorage, fileStorage)

		// 同步本地数据到Redis
		syncLocalToRedis()

		// 启动Redis健康检查
		startRedisHealthCheck()
	} else {
		storage = fileStorage
	}
	
	//初始统计数据文件
	dataFilePath := filepath.Join(dataDir, "short_data.json")
	initializeData(dataFilePath)

	// 设置http请求处理程序
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 设置CORS相关头
		w.Header().Set("Access-Control-Allow-Origin", "*")                              // 允许所有域名访问
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, HEAD, OPTIONS") // 允许的请求方法
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")   // 允许的请求头

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

				svgContent, success := generateSVG(ipInfo)
				if !success {
					return // 失败时不响应
				}

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
				svgContent, success := generateUASVG(UAInfo)
				if !success {
					return // 失败时不响应
				}
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
	// 设置信号处理
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
  
	// 启动HTTP服务器
	go func() {
    	if err := http.Serve(ln, nil); err != nil {
        	if !errors.Is(err, net.ErrClosed) {
            	log.Printf("服务器错误: %v", err)
        	}
    	}
	}()
  
	// 等待退出信号
	<-c
	log.Println("程序正在退出...")
	closeRedis()
	ln.Close()
	os.Exit(0)
}
