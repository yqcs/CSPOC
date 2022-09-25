# Cobalt Strike 存储型XSS RCE CVE-2022-39197

### 运行参数：

> ### -u: Cobaltstrike http监听的地址，如 http://127.0.0.1:8500
>
>### -p: Payload，如 `<html><img src=http://127.0.0.1/log.png>` 不宜过长
>

### 演示：
![!est](run.png)
![main](img.png)

### 打包命令：go build -ldflags "-s -w"

---

## QQ 群：

### [点击加入：528118163](https://jq.qq.com/?_wv=1027&k=azWZhmSy)

## 加群 / 合作 / 联系（左） | 公众号：遮天实验室（右）

<img src="https://heartsk.com/static/wx.jpg" width="200"><img src="https://github.com/yqcs/ZheTian/blob/master/images/wxgzh.jpg" width="200">