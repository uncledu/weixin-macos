package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
	
	"github.com/frida/frida-go/frida"
)

// 全局变量，保持 Frida 脚本对象
var (
	fridaScript *frida.Script
	session     *frida.Session
	taskId      = int64(0x20000000)
	
	msgChan    = make(chan *SendMsg, 10)
	finishChan = make(chan struct{})
)

type SendMsg struct {
	UserId  string
	Content string
}

// SendRequest 请求结构体
type SendRequest struct {
	Message []*Message `json:"message"`
	UserID  string     `json:"user_id"`
}

type Message struct {
	Type string           `json:"type"`
	Data *SendRequestData `json:"data"`
}

type SendRequestData struct {
	Id   string `json:"id"`
	Text string `json:"text"`
}

func initFridaGadget() {
	mgr := frida.NewDeviceManager()
	// 连接到 Gadget 默认端口
	device, err := mgr.AddRemoteDevice("127.0.0.1:27042", frida.NewRemoteDeviceOptions())
	if err != nil {
		log.Printf("❌ 无法连接 Gadget: %v\n", err)
		os.Exit(1)
	}
	
	session, err = device.Attach("Gadget", nil)
	if err != nil {
		log.Printf("❌ 附加失败: %v\n", err)
		os.Exit(1)
	}
	
	loadJs()
	
}

func initFrida() {
	// 1. 获取本地设备管理器
	mgr := frida.NewDeviceManager()
	
	// 2. 枚举并获取本地设备 (TypeLocal)
	device, err := mgr.DeviceByType(frida.DeviceTypeLocal)
	if err != nil {
		log.Fatalf("无法获取本地设备: %v", err)
	}
	
	log.Println("正在尝试 Attach 到微信...")
	session, err = device.Attach(47516, nil)
	if err != nil {
		log.Fatalf("Attach 失败 (请检查 SIP 状态或权限): %v", err)
	}
	
	loadJs()
}

func loadJs() {
	js, _ := os.ReadFile("./script.js")
	script, err := session.CreateScript(string(js))
	if err != nil {
		log.Printf("❌ 创建脚本失败: %v\n", err)
		os.Exit(1)
	}
	
	// 打印 JS 里的 console.log
	script.On("message", func(rawMsg string) {
		var msg map[string]interface{}
		json.Unmarshal([]byte(rawMsg), &msg)
		
		msgType := msg["type"].(string)
		
		switch msgType {
		case "send":
			if p, ok := msg["payload"]; ok {
				if pMap, ok := p.(map[string]interface{}); ok {
					if t, ok := pMap["type"]; ok {
						if t.(string) == "send" {
							go SendHttpReq(msg)
						} else if t.(string) == "finish" {
							finishChan <- struct{}{}
						}
					}
				}
			}
		case "log":
			// 这里处理 console.log
			log.Printf("[JS日志] %s\n", msg["payload"])
		case "error":
			// 这里处理 JS 脚本报错
			log.Printf("[❌脚本报错] %s\n", msg["description"])
		}
	})
	
	if err := script.Load(); err != nil {
		log.Printf("❌ 加载脚本失败: %v\n", err)
		os.Exit(1)
	}
	
	fridaScript = script
	log.Println("✅ Frida 已就绪，微信控制通道已打通")
}

func sendHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
		return
	}
	
	req := new(SendRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		http.Error(w, "无效的 JSON", http.StatusBadRequest)
		return
	}
	
	// 参数校验
	if len(req.Message) == 0 || req.UserID == "" {
		http.Error(w, "参数缺失", http.StatusBadRequest)
		return
	}
	
	text := ""
	for _, v := range req.Message {
		if v.Type == "text" {
			text = v.Data.Text
		}
	}
	
	msgChan <- &SendMsg{
		UserId:  req.UserID,
		Content: text,
	}
	
	json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
	})
}

func SendWorker() {
	for m := range msgChan {
		currTaskId := atomic.AddInt64(&taskId, 1)
		log.Printf("📩 收到任务: %d\n", currTaskId)
		
		// 1. 创建一个 1 秒超时的上下文
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		
		// 必须在处理完后释放 context 资源
		defer cancel()
		
		// 2. 使用 channel 接收 Frida 返回结果
		resChan := make(chan interface{}, 1)
		
		go func() {
			// 在子协程中执行阻塞的 Frida 调用
			result := fridaScript.ExportsCall("manualTrigger", currTaskId, m.UserId, m.Content)
			resChan <- result
		}()
		
		// 3. 核心：通过 select 监听“完成”或“超时”
		select {
		case result := <-resChan:
			log.Printf("✅ 任务 %d 执行成功: %v\n", currTaskId, result)
		case <-ctx.Done():
			// 此时已经过了 1 秒，resChan 还没收到数据
			log.Printf("⏰ 任务 %d 执行超时！\n", currTaskId)
		case <-finishChan:
			log.Printf("🛑 收到完成信号，任务 %d 完成\n", currTaskId)
		}
	}
}

func main() {
	initFrida()
	go SendWorker()
	
	http.HandleFunc("/send_private_msg", sendHandler)
	
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-stop
		log.Println("\n正在释放 Frida 资源并退出...")
		os.Exit(0)
	}()
	
	// 3. 启动服务
	port := ":58080"
	log.Printf("🌐 HTTP 服务启动在 http://127.0.0.1%s\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Printf("❌ 服务启动失败: %v\n", err)
	}
	
}

func SendHttpReq(msg map[string]interface{}) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic: %v\n", r)
		}
	}()
	
	time.Sleep(1 * time.Second)
	// 这里处理你的 X1 数据
	jsonData, err := json.Marshal(msg["payload"])
	if err != nil {
		log.Printf("JSON 序列化失败: %v\n", err)
		return
	}
	
	log.Printf("发送数据: %s\n", string(jsonData))
	
	// 4. 创建 POST 请求
	req, err := http.NewRequest("POST", "http://127.0.0.1:36060/onebot", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("创建请求失败: %v\n", err)
		return
	}
	
	// 5. 设置 Header (OneBot 接口通常要求 application/json)
	h := hmac.New(sha1.New, []byte("MuseBot"))
	h.Write(jsonData)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", "sha1="+hex.EncodeToString(h.Sum(nil)))
	
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	// 6. 执行请求
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("请求执行失败: %v\n", err)
		return
	}
	defer resp.Body.Close()
	
	// 7. 读取返回结果
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取响应失败: %v\n", err)
		return
	}
	
	log.Printf("状态码: %d 返回内容: %s\n", resp.StatusCode, string(body))
}
