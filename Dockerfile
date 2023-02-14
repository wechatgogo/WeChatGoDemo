FROM golang:alpine as builder
MAINTAINER LiXunHuan(lxh@cxh.cn)

# 创建工作目录，修改alpine源为中科大的源，安装必要工具
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories && \
  apk update && \
  apk upgrade && \
  apk add ca-certificates gcc g++ && update-ca-certificates && \
  apk add --update tzdata && \
  rm -rf /var/cache/apk/*

ENV TZ=Asia/Shanghai

WORKDIR /builder
COPY . .
RUN go build -o wechat && ls -lh && chmod +x ./wechat

FROM golang:alpine as runner
MAINTAINER LiXunHuan(lxh@cxh.cn)

WORKDIR /app
COPY --from=builder /builder/wechat ./wechat
COPY --from=builder /builder/swagger/ ./swagger/
COPY --from=builder /builder/conf/ ./conf/
CMD ./wechat