<div align="center">

  # short-url 缩短链接服务
<img alt="GitHub Created At" src="https://img.shields.io/github/created-at/lmq8267/vnt?logo=github&label=%E5%88%9B%E5%BB%BA%E6%97%A5%E6%9C%9F">
<a href="https://deepwiki.com/lmq8267/short-url-go"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
<a href="https://github.com/lmq8267/short-url-go/releases"><img src="https://img.shields.io/github/downloads/lmq8267/short-url-go/total?logo=github&label=%E4%B8%8B%E8%BD%BD%E9%87%8F"/></a>
<a href="https://github.com/lmq8267/short-url-go/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/lmq8267/short-url-go?logo=github&label=%E8%B4%A1%E7%8C%AE%E8%80%85"/></a>
<a href="https://github.com/lmq8267/short-url-go/releases/"><img src="https://img.shields.io/github/release/lmq8267/short-url-go?logo=github&label=%E6%9C%80%E6%96%B0%E7%89%88%E6%9C%AC"/></a>
<a href="https://github.com/lmq8267/short-url-go/issues"><img src="https://img.shields.io/github/issues-raw/lmq8267/short-url-go?logo=github&label=%E9%97%AE%E9%A2%98"/></a>
<a href="https://github.com/lmq8267/short-url-go/discussions"><img src="https://img.shields.io/github/discussions/lmq8267/short-url-go?logo=github&label=%E8%AE%A8%E8%AE%BA"/></a>
<a href="GitHub repo size"><img src="https://img.shields.io/github/repo-size/lmq8267/short-url-go?logo=github&label=%E4%BB%93%E5%BA%93%E5%A4%A7%E5%B0%8F"/></a>
<a href="https://github.com/lmq8267/short-url-go/actions?query=workflow%3ABuild"><img src="https://img.shields.io/github/actions/workflow/status/lmq8267/short-url-go/build.yml?branch=main&logo=github&label=%E6%9E%84%E5%BB%BA%E7%8A%B6%E6%80%81" alt="Build status"/></a>
<a href="https://hub.docker.com/r/lmq8267/shortener"><img src="https://img.shields.io/docker/pulls/lmq8267/shortener?color=%2348BB78&logo=docker&label=%E6%8B%89%E5%8F%96%E9%87%8F" alt="Downloads"/></a>
 
 ![](https://tt.cnqq.cloudns.ch/?id=svg)
 
</div>



 纯AI的产的 <br>
### 预览
![](./image/UI预览.png)

### 参数
```bash
-p [端口号]              监听指定端口号,默认8080                              环境变量：SHORT_PORT
-d [目录路径]            指定数据存放目录路径，默认当前程序路径的./short_data   环境变量：SHORT_DATA_DIR
-db [目录路径]           指定IP离线数据库存放目录路径，默认/tmp                环境变量：SHORT_DB_DIR
-log [目录路径]          指定日志输出文件的目录路径                           环境变量：SHORT_LOG_DIR
-e [邮箱地址]            指定邮箱地址，修改页面的邮箱地址                     环境变量：SHORT_EMAIL
-admin                  启用后台管理页面（/admin 后缀进入管理员页面）         环境变量：SHORT_ADMIN (启用:true/1)
-u [帐号]                指定管理页面账户名                                  环境变量：SHORT_USERNAME
-w [密码]                指定管理页面密码                                    环境变量：SHORT_PASSWORD
-daemon                 以后台模式运行                                       环境变量：SHORT_DAEMON (启用:true/1)
-redis-addr [地址:端口]  Redis服务器地址 (例如: localhost:6379)               环境变量：SHORT_REDIS_ADDR
-redis-user [用户名]     Redis用户名 (可选)                                  环境变量：SHORT_REDIS_USER
-redis-pass [密码]       Redis密码 (可选)                                    环境变量：SHORT_REDIS_PASS
-redis-pre [前缀]        Redis数据前缀，默认为short，连接相同的redis数据库时用于区分不同应用  环境变量：SHORT_REDIS_PRE
-v                      版本号  
-h / --help             帮助信息
```

### 运行
```bash
./shortener -p 8080 -e email@test.cloudns.be -log /tmp/shortener/ -admin -u admin -w wodemima 
```

```bash
# 采用Redis数据库保存，可以 -d 指定本地数据保存到 /tmp/short_data 因为连接Redis时 同时也会继续保存在本地，数据实时互通同步更新的
./shortener -p 8080 -e email@test.cloudns.be -log /tmp/shortener/ -admin -u admin -w wodemima -d /tmp/short_data -redis-addr 192.168.2.1:6379 -redis-pass 123456
```

浏览器输入`http://本地ip:8080`打开主页<br>

数据保存在`./short_data/`目录里,以后缀名.json保存，重置后缀密码，直接清除里面的`"password": "",`即可<br>
更换背景图在`./short_data/short_data.json`里面的`"img": "你的图片.jpg"` 或者 环境变量 `SHORT_IMG='你的图片链接'`

使用cf的转发规则，可以去掉端口<br>
例如在serv00免费服务器部署<br>
在serv00运行后，去cf添加服务器的IP记录
![](./image/CF解析A记录.png)
然后再去添加转发规则
![](./image/建立转发规则.png)
![](./image/设置你的域名.png)
这样就可以直接使用你的域名访问了

```
#shell查询IP地址

curl -4 http://你的域名地址/?id=ip
curl -6 http://你的域名地址/?id=ip
```

### API
```badh
curl -ks 'http://你的域名地址/api' -X POST -d '{ \
  "longUrl": "长链接", \
  "shortCode": "后缀", \
  "type": "link", \
  "expiration": "", \
  "burn_after_reading": false, \
  "password": "" \
}'
```
其中 `longUrl` 表示 长链接或者文本内容<br>
`shortCode` 表示 后缀<br>
`type` 表示功能 `link`是链接 `text`是文本 `html`是网页<br>
`expiration` 表示有效期（分钟） 整数，留空表示永久有效<br>
`burn_after_reading` 表示是否启用阅后即焚 `false`关闭 `true`开启<br>
`password` 表示后缀密码，下次更新这个后缀的内容需要使用相同的密码才能更新<br>

shell的更新短链接示例
```bash
#!/bin/bash

#IP地址
ip="110.123.146.27:51018"

#后缀
hz="caddy888"

#密码
mm="password"

# 构建单行 JSON 数据（推荐用 printf 避免换行）
json_data=$(printf '{"longUrl":"%s","shortCode":"%s","password":"%s","expiration":"","burn_after_reading":"false","type":"link"}' "$IPadd" "$hz" "$mm")


# 发送 POST 请求并获取返回值
status=$(curl -Lk --post301 --post302 -X POST \
  -H 'Content-Type: application/json' \
  -d "$json_data" \
  "http://你的域名/api")

# 检查返回的 JSON 数据是否包含预期内容
if [[ "$status" == *"\"type\":\"link\""* && "$status" == *"\"short_url\""* && "$status" == *"\"URL_NAME\":\"${hz}\""* ]]; then
  echo "更新${ip}记录成功！"
else
  echo "失败！返回的数据：$status"
fi
```

### Docker
```bash
docker run --name shortener -p 12345:8080/tcp -v /etc/short_data:/usr/bin/short_data --restart=always -d lmq8267/shortener

```

```bash
# 连接Redis数据库
docker run --name shortener -p 12345:8080/tcp --restart=always -d lmq8267/shortener -redis-addr 192.168.2.1:6379 -redis-pass 123456

```
其中`-p 12345:8080/tcp` 表示映射主机上的`12345`端口到容器内部`8080`端口 可以自定义你的端口<br>
     `-v /etc/short_data/:/usr/bin/short_data/` 表示挂载主机上的`/etc/short_data/`文件夹到容器内部的数据库目录`/usr/bin/short_data/`<br>
     输入你的`http://主机IP:12345`访问主页，数据目录挂载到了主机上的`/etc/short_data/`文件夹里查看 <br>
<br> docker-compose.yaml

```bash
version: '3.9'
services:
    shortener:
        image: lmq8267/shortener
        restart: always
        volumes:
            - '/etc/short_data:/usr/bin/short_data'
        ports:
            - '12345:8080/tcp'
        container_name: shortener

```

```bash
# 连接Redis数据库
version: '3.9'
services:
    shortener:
        image: lmq8267/shortener
        restart: always
        ports:
            - '12345:8080/tcp'
        container_name: shortener
        command: '-redis-addr 192.168.2.1:6379 -redis-pass 123456'

```
