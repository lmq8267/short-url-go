![image](https://github.com/user-attachments/assets/dc956887-0a3e-4fb7-8651-d0b60fb56838)# short-url 缩短链接服务
<p align="center">
<a href="https://github.com/lmq8267/short-url-go/releases"><img src="https://img.shields.io/github/downloads/lmq8267/short-url-go/total"/></a
<a href="https://github.com/lmq8267/short-url-go/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/lmq8267/short-url-go"/></a
<a href="https://github.com/lmq8267/short-url-go/releases/"><img src="https://img.shields.io/github/release/lmq8267/short-url-go"/></a
<a href="https://github.com/lmq8267/short-url-go/issues"><img src="https://img.shields.io/github/issues-raw/lmq8267/short-url-go"/></a
<a href="https://github.com/lmq8267/short-url-go/discussions"><img src="https://img.shields.io/github/discussions/lmq8267/short-url-go"/></a
<a href="GitHub repo size"><img src="https://img.shields.io/github/repo-size/lmq8267/short-url-go?color=red&style=flat-square"/></a
<a href="https://github.com/lmq8267/short-url-go/actions?query=workflow%3ABuild"><img src="https://img.shields.io/github/actions/workflow/status/lmq8267/short-url-go/build.yml?branch=main" alt="Build status"/></a
<a href="https://hub.docker.com/r/lmq8267/shortener"><img src="https://img.shields.io/docker/pulls/lmq8267/shortener?color=%2348BB78&logo=docker&label=pulls" alt="Downloads"/></a
</p>

<br> 纯AI的产的 <br>
### 预览
[tt.cnqq.cloudns.ch](https://tt.cnqq.cloudns.ch/)
![](./image/UI预览.png)

### 参数
```bash
-p [端口号] 监听指定端口号,默认8080
-d [目录路径] 指定数据存放目录路径，默认当前程序路径的./short_data
-log [目录路径] 指定日志输出文件的目录路径
-e [邮箱地址] 指定邮箱地址，修改页面的邮箱地址
-admin     启用后台管理页面（/admin 后缀进入管理员页面）
-u [帐号] 指定管理页面账户名
-w [密码] 指定管理页面密码
```

### 运行
```bash
./shortener -p 8080 -e email@test.cloudns.be -log /tmp/shortener/ -admin -u admin -w wodemima &
```
浏览器输入`http://本地ip:8080`打开主页<br>
[s4.serv00.com:8828](http://s4.serv00.com:8828)

数据保存在`./short_data/`目录里,以后缀名.json保存，重置后缀密码，直接清除里面的`"password": "",`即可<br>
更换背景图在`./short_data/short_data.json`里面的`"img": "你的图片.jpg"`

使用cf的转发规则，可以去掉端口<br>
例如在serv00免费服务器部署<br>
在serv00运行后，去cf添加服务器的IP记录
![](./image/CF解析A记录.png)
然后再去添加转发规则
![](./image/建立转发规则.png)
![](./image/设置你的域名.png)
这样就可以直接使用你的域名访问了
[tt.cnqq.cloudns.ch](https://tt.cnqq.cloudns.ch/)

### API
```badh
curl -k 'http://你的域名地址/api' -X POST -d '{ \
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

我的ifname嵌套脚本，打开只显示域名不会总是跳转IP（只能域名http跳转IP的http 不能跨域）
```bash
#!/bin/bash

#IP地址
ip="110.123.146.27:51018"

#后缀
hz="caddy888"

#密码
mm="password"

# 构建单行 JSON 数据不能换行
json_data=$(cat <<EOF
{"longUrl":"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><meta http-equiv=\"X-UA-Compatible\" content=\"ie=edge\"><title>/</title><style>body, html {margin: 0; padding: 0; height: 100%; overflow: hidden;} iframe {width: 100%; height: 100%; border: none;}</style></head><body><iframe src=\"http://$ip\"></iframe></body></html>","shortCode":"$hz","password":"$mm","expiration":"","burn_after_reading":"false","type":"html"}
EOF
)

# 发送 POST 请求并获取返回值
status=$(curl -Lk 'https://域名/api' -X POST \
-H 'Content-Type: application/json' \
-d "$json_data")

# 检查返回的 JSON 数据是否包含预期内容
if [[ "$status" == *"\"type\":\"html\""* && "$status" == *"\"short_url\":\"http://域名/${hz}\""* && "$status" == *"\"URL_NAME\":\"${hz}\""* ]]; then
  echo "更新${ip}记录成功！"
else
  echo "失败！返回的数据：$status"
fi
```

### Docker
```bash
docker run --name shortener -p 12345:8080/tcp -v /etc/short_data:/usr/bin/short_data --restart=always -d lmq8267/shortener

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
