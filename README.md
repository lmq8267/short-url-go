# short-url 缩短链接服务
<p align="center">
<a href="https://github.com/lmq8267/short-url-go/releases"><img src="https://img.shields.io/github/downloads/lmq8267/short-url-go/total"/></a
<a href="https://github.com/lmq8267/short-url-go/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/lmq8267/short-url-go"/></a
<a href="https://github.com/lmq8267/short-url-go/releases/"><img src="https://img.shields.io/github/release/lmq8267/short-url-go"/></a
<a href="https://github.com/lmq8267/short-url-go/issues"><img src="https://img.shields.io/github/issues-raw/lmq8267/short-url-go"/></a
<a href="https://github.com/lmq8267/short-url-go/discussions"><img src="https://img.shields.io/github/discussions/lmq8267/short-url-go"/></a
<a href="GitHub repo size"><img src="https://img.shields.io/github/repo-size/lmq8267/short-url-go?color=red&style=flat-square"/></a
<a href="https://github.com/lmq8267/short-url-go/actions?query=workflow%3ABuild"><img src="https://img.shields.io/github/actions/workflow/status/lmq8267/short-url-go/build.yml?branch=main" alt="Build status"/></a
</p>

### 预览
[tt.cnqq.cloudns.ch](https://tt.cnqq.cloudns.ch/)
![](./image/UI预览.png)

### 参数
```bash
-p [端口号] 监听指定端口号,默认8080
-d [目录路径] 指定数据存放目录路径，默认当前程序路径的./short_data
-e [邮箱地址] 指定邮箱地址，修改页面的邮箱地址
-f  后台运行,此模式下请加-d 参数指定数据路径
```

### 运行
```bash
./shortener -p 8080 -e email@test.cloudns.be 
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
