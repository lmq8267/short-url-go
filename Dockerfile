FROM docker.io/golang AS builder
WORKDIR /build
COPY . .
ENV CGO_ENABLED=0
RUN go build

FROM scratch
COPY --from=builder /build/shortener /usr/bin/shortener
# 创建数据目录
RUN mkdir -p /usr/bin/short_data
  
# 设置所有环境变量及其默认值
ENV TZ=Asia/Shanghai
ENV SHORT_PORT=8080
ENV SHORT_DATA_DIR=/usr/bin/short_data
ENV SHORT_DB_DIR=/tmp
ENV SHORT_LOG_DIR=""
ENV SHORT_ADMIN=false
ENV SHORT_EMAIL="请修改为你的邮箱"
ENV SHORT_USERNAME=admin
ENV SHORT_PASSWORD=admin
ENV SHORT_DAEMON=false
ENV SHORT_REDIS_ADDR=""
ENV SHORT_REDIS_USER=""
ENV SHORT_REDIS_PASS=""
ENV SHORT_REDIS_PRE=short
ENV SHORT_IMG="https://img-baofun.zhhainiao.com/pcwallpaper_ugc/static/a613b671bce87bdafae01938c7cad011.jpg"
# 映射端口  
EXPOSE 8080
  
ENTRYPOINT ["/usr/bin/shortener"]
