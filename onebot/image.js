// 1. 获取微信主模块的基地址
var baseAddr = Process.getModuleByName("WeChat").base;
if (!baseAddr) {
    console.error("[!] 找不到 WeChat 模块基址，请检查进程名。");
}
console.log("[+] WeChat base address: " + baseAddr);


// 触发函数地址,不同版本的地址看wechat_version 中的json文件复制过来
var sendMessageCallbackFunc = ptr(0x0);
var messageCallbackFunc1 = baseAddr.add(0x7fa0b18);

// 这个必须是绝对位置
var triggerX1Payload = ptr(0x175ED6600);
var triggerFuncAddr = baseAddr.add(0x448A858);
var req2bufEnterAddr = baseAddr.add(0x34566C0);
var req2bufExitAddr = baseAddr.add(0x34577D8);
var protobufAddr = baseAddr.add(0x2275BFC);
var buf2RespAddr = baseAddr.add(0x347BD44);
var patchProtobufFunc1 = baseAddr.add(0x2275BB8)
var patchProtobufFunc2 = baseAddr.add(0x2275BD8);
var protobufDeleteAddr = baseAddr.add(0x2275C14);
var CndOnCompleteAddr = baseAddr.add(0x34154E0);

var runReadWriteAddr = baseAddr.add(0x450F518)
var runReadWriteAddr1 = baseAddr.add(0x450F51C);

// 触发函数X0参数地址
var globalMessagePtr = ptr(0);

// 消息体的一些指针地址
var cgiAddr = ptr(0);
var callBackFuncAddr = ptr(0);
var callBackFuncAddr2 = ptr(0);
var callBackFuncAddr3 = ptr(0);

var sendMessageAddr = ptr(0);
var messageAddr = ptr(0);
var contentAddr = ptr(0);
var insertMsgAddr = ptr(0);
var receiverAddr = ptr(0);
var htmlContentAddr = ptr(0);
var protoX1PayloadAddr = ptr(0);

// 消息的taskId
var taskIdGlobal = 0x20000090 // 最好比较大，不和原始的微信消息重复
var receiverGlobal = "wxid_7wd1ece99f7i21"
var senderGlobal = "wxid_ldftuhe36izg19"
var lastSendTime = 0;
var globalImageCdnKey = "";
var globalAesKey1 = "";
var globalAesKey2 = "";

// 打印消息的地址，便于查询问题
function printAddr() {
    console.log("[+] Addresses:");
    console.log("    - cgiAddr: " + cgiAddr);
    console.log("    - callBackFuncAddr: " + callBackFuncAddr);
    console.log("    - sendMessageAddr: " + sendMessageAddr);
    console.log("    - contentAddr: " + contentAddr);
    console.log("    - globalMessagePtr: " + globalMessagePtr);
    console.log("    - triggerX1Payload: " + triggerX1Payload);
}

// 辅助函数：写入 Hex 字符串
function patchHex(addr, hexStr) {
    const bytes = hexStr.split(' ').map(h => parseInt(h, 16));
    addr.writeByteArray(bytes);
    addr.add(bytes.length).writeU8(0); // 终止符
}

// 初始化进行内存的分配
function setupSendMessageDynamic() {
    console.log("[+] Starting Dynamic Message Patching...");

    // 1. 动态分配内存块（按需分配大小）
    // 分配原则：字符串给 64-128 字节，结构体按实际大小分配
    cgiAddr = Memory.alloc(128);
    callBackFuncAddr = Memory.alloc(16);
    callBackFuncAddr2 = Memory.alloc(16);
    callBackFuncAddr3 = Memory.alloc(16);
    sendMessageAddr = Memory.alloc(256);
    messageAddr = Memory.alloc(512);
    contentAddr = Memory.alloc(16);
    receiverAddr = Memory.alloc(24);
    htmlContentAddr = Memory.alloc(24);


    // A. 写入字符串内容
    patchHex(cgiAddr, "2f 63 67 69 2d 62 69 6e 2f 6d 69 63 72 6f 6d 73 67 2d 62 69 6e 2f 75 70 6c 6f 61 64 6d 73 67 69 6d 67");
    patchHex(contentAddr, " ");

    // B. 构建 SendMessage 结构体 (X24 基址位置)
    sendMessageAddr.add(0x00).writeU64(0);
    sendMessageAddr.add(0x08).writeU64(0);
    sendMessageAddr.add(0x10).writePointer(sendMessageCallbackFunc);
    sendMessageAddr.add(0x18).writeU64(1);
    sendMessageAddr.add(0x20).writeU32(taskIdGlobal);
    sendMessageAddr.add(0x28).writePointer(messageAddr);

    console.log(" [+] sendMessageAddr Object: ", hexdump(sendMessageAddr, {
        offset: 0,
        length: 48,
        header: true,
        ansi: true
    }));

    // C. 构建 Message 结构体
    messageAddr.add(0x00).writePointer(messageCallbackFunc1);
    messageAddr.add(0x08).writeU32(taskIdGlobal);
    messageAddr.add(0x0c).writeU32(0x6e);
    messageAddr.add(0x10).writeU64(0x3);
    messageAddr.add(0x18).writePointer(cgiAddr);
    messageAddr.add(0x20).writeU64(0x22);
    messageAddr.add(0x28).writeU64(uint64("0x8000000000000030"));
    messageAddr.add(0x30).writeU64(uint64("0x0000000001010100"));

    console.log(" [+] messageAddr Object: ", hexdump(messageAddr, {
        offset: 0,
        length: 64,
        header: true,
        ansi: true
    }));

    console.log(" [+] Dynamic Memory Setup Complete. - Message Object: " + messageAddr);
}

setImmediate(setupSendMessageDynamic);

// 辅助函数：写入 Hex 字符串
function patchHex(addr, hexStr) {
    const bytes = hexStr.split(' ').map(h => parseInt(h, 16));
    addr.writeByteArray(bytes);
    addr.add(bytes.length).writeU8(0); // 终止符
}


function patchProtoBuf() {
    Memory.patchCode(patchProtobufFunc1, 4, code => {
        const cw = new Arm64Writer(code, {pc: patchProtobufFunc1});
        cw.putNop();
        cw.flush();
    });

    console.log("[+] Patching BL to NOP at " + patchProtobufFunc1 + " completed.");

    Memory.patchCode(patchProtobufFunc2, 4, code => {
        const cw = new Arm64Writer(code, {pc: patchProtobufFunc2});
        cw.putNop();
        cw.flush();
    });

    console.log("[+] Patching BL to NOP at " + patchProtobufFunc2 + " completed.");

    Memory.patchCode(protobufDeleteAddr, 4, code => {
        const cw = new Arm64Writer(code, {pc: protobufDeleteAddr});
        cw.putNop();
        cw.flush();
    });

    console.log("[+] Patching BL DELETE to NOP at " + protobufDeleteAddr + " completed.");
}

setImmediate(patchProtoBuf);

function manualTrigger(taskId, sender, receiver) {
    console.log("[+] Manual Trigger Started...");
    if (!taskId || !receiver) {
        console.error("[!] taskId or Receiver or Content is empty!");
        return "fail";
    }

    // 获取当前时间戳 (秒)
    const timestamp = Math.floor(Date.now() / 1000);
    lastSendTime = timestamp
    taskIdGlobal = taskId;
    // receiverGlobal = receiver;
    // senderGlobal = sender;

    messageAddr.add(0x08).writeU32(taskIdGlobal);
    sendMessageAddr.add(0x20).writeU32(taskIdGlobal);

    console.log("start init payload")

    const payloadData = [
        0x6e, 0x00, 0x00, 0x00,                         // 0x00
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x08
        0x03, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // 0x10
        0x40, 0xec, 0x0e, 0x12, 0x01, 0x00, 0x00, 0x00, // 0x18
        0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x20 cgi的长度
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x28
        0x00, 0x01, 0x01, 0x01, 0x00, 0xAA, 0xAA, 0xAA, // 0x30
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // 0x38
        0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, // 0x40
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xAA, 0xAA, 0xAA, // 0x48
        0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xAA, 0xAA, 0xAA, // 0x50
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x58
        0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x60
        0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x2D, // 0x68 default-
        0x6C, 0x6F, 0x6E, 0x67, 0x6C, 0x69, 0x6E, 0x6B, // 0x70 longlink
        0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x10, // 0x78
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x80
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x88
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x90
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x98
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xA0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xA8
        0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0xB0
        0xC0, 0x66, 0xED, 0x75, 0x01, 0x00, 0x00, 0x00, // 0xB8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xC0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xC8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xD0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xD8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xE0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xE8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xF0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xF8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x100
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x108
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x110
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x118
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x120
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x128
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x130
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x138
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x140
        0x01, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0x148
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x150
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x158
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x160
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x168
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x170
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x178
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x180
        0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // 0x188
        0x98, 0x67, 0xED, 0x75, 0x01, 0x00, 0x00, 0x00, // 0x190
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x198
    ];

    // 从 0x175ED6604 开始写入 Payload
    triggerX1Payload.writeU32(taskIdGlobal);
    triggerX1Payload.add(0x04).writeByteArray(payloadData);
    triggerX1Payload.add(0x18).writePointer(cgiAddr);

    console.log("finished init payload")

    const MMStartTask = new NativeFunction(triggerFuncAddr, 'int64', ['pointer']);

    // 5. 调用函数
    try {
        // const arg1 = globalMessagePtr; // 第一个指针参数
        const arg2 = triggerX1Payload; // 第二个参数 0x175ED6600
        console.log(`[+] Calling MMStartTask  at ${triggerFuncAddr} with args: (${arg2})`);
        const result = MMStartTask(arg2);
        console.log("[+] Execution MMStartTask  Success. Return value: " + result);
        return "ok";
    } catch (e) {
        console.error("[!] Error trigger function  during execution: " + e);
        return "fail";
    }
}


// ReqBuf 进行拦截，替换入参数的消息指针
function attachReq2buf() {

    console.log("[+] Target Req2buf enter Address: " + req2bufEnterAddr);

    // 2. 开始拦截
    Interceptor.attach(req2bufEnterAddr, {
        onEnter: function (args) {
            if (!this.context.x1.equals(taskIdGlobal)) {
                return;
            }

            console.log("[+] 已命中目标Req2Buf地址:0x1033EE8E8 taskId:" + taskIdGlobal + "base:" + baseAddr);

            // 3. 获取 X24 寄存器的值
            const x24_base = this.context.x24;
            insertMsgAddr = x24_base.add(0x60);
            console.log("[+] 当前 Req2Buf X24 基址: " + x24_base);

            if (typeof sendMessageAddr !== 'undefined') {
                insertMsgAddr.writePointer(sendMessageAddr);
                console.log("[+] 成功! Req2Buf 已将 X24+0x60 指向新地址: " + sendMessageAddr +
                    "[+] Req2Buf 写入后内存预览: " + insertMsgAddr);
                console.log(hexdump(insertMsgAddr, {
                    offset: 0,
                    length: 16,
                    header: true,
                    ansi: true
                }))
                console.log(hexdump(sendMessageAddr, {
                    offset: 0,
                    length: 48,
                    header: true,
                    ansi: true
                }))
            } else {
                console.error("[!] 错误: 变量 sendMessageAddr 未定义，请确保已运行分配逻辑。");
            }
        }
    });

    // 在出口处拦截req2buf，把insertMsgAddr设置为0，避免被垃圾回收导致整个程序崩溃
    console.log("[+] Target Req2buf leave Address: " + req2bufExitAddr);
    Interceptor.attach(req2bufExitAddr, {
        onEnter: function (args) {
            if (!this.context.x25.equals(taskIdGlobal)) {
                return;
            }
            insertMsgAddr.writeU64(0x0);
            console.log("[+] 清空写入后内存预览: " + insertMsgAddr.readPointer());
            // receiverGlobal = "";
            send({
                type: "finish",
            })
        }
    });
}

setImmediate(attachReq2buf);

// 辅助函数：Protobuf Varint 编码 (对应 get_varint_timestamp_bytes)
function getVarintTimestampBytes() {
    let ts = Math.floor(Date.now() / 1000);
    let encodedBytes = [];
    let tempTs = ts >>> 0; // 强制转为 32位 无符号整数

    while (true) {
        let byte = tempTs & 0x7F;
        tempTs >>>= 7;
        if (tempTs !== 0) {
            encodedBytes.push(byte | 0x80);
        } else {
            encodedBytes.push(byte);
            break;
        }
    }
    return encodedBytes;
}

function stringToHexArray(str) {
    var utf8Str = unescape(encodeURIComponent(str));
    var arr = [];
    for (var i = 0; i < utf8Str.length; i++) {
        arr.push(utf8Str.charCodeAt(i)); // 获取字符的 ASCII 码 (即十六进制值)
    }
    return arr;
}

function generateRandom5ByteVarint() {
    let res = [];

    // 前 4 个字节：最高位(bit 7)必须是 1，低 7 位随机
    for (let i = 0; i < 4; i++) {
        let random7Bit = Math.floor(Math.random() * 128);
        res.push(random7Bit | 0x80); // 强制设置最高位为 1
    }

    // 第 5 个字节：最高位必须是 0，为了确保不变成 4 字节，低 7 位不能全为 0
    let lastByte = Math.floor(Math.random() * 127) + 1;
    res.push(lastByte & 0x7F); // 确保最高位为 0

    return res;
}

// 拦截 Protobuf 编码逻辑，注入自定义 Payload
function attachProto() {
    console.log("[+] proto注入拦截目标地址: " + protobufAddr);
    protoX1PayloadAddr = Memory.alloc(1024);
    console.log("[+] Frida 分配的 Payload 地址: " + protoX1PayloadAddr);

    Interceptor.attach(protobufAddr, {
        onEnter: function (args) {
            console.log("[+] Protobuf 拦截命中");

            // var sp = this.context.sp;
            // var firstValue = sp.readU32();
            // if (firstValue !== taskIdGlobal) {
            //     console.log("[+] Protobuf 拦截未命中，跳过...");
            //     return;
            // }

            const type = [0x0A, 0x40, 0x0A, 0x01, 0x00]
            const msgId = [0x10, 0xc6, 0xbc, 0x90, 0xb9, 0x08] // 时间戳
            const cpHeader = [0x1A, 0x10]
            // m30c4674f5a0b9d
            const cp = [0x6D, 0x33, 0x30, 0x63, 0x34, 0x36, 0x37, 0x34, 0x66, 0x35, 0x61, 0x30, 0x62, 0x39, 0x64, 0x30]

            const randomId = [0x20, 0xAF, 0xAC, 0x90, 0x93, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]
            const sysHeader = [0x2A, 0x15]
            // UnifiedPCMac 26 arm64
            const sys = [0x55, 0x6E, 0x69, 0x66, 0x69, 0x65, 0x64, 0x50, 0x43, 0x4D, 0x61, 0x63, 0x20, 0x32, 0x36, 0x20, 0x61, 0x72, 0x6D, 0x36, 0x34, 0x30]


            // 45872025384@chatroom_176787000_60_xwechat_1 只需要改这个时间戳就能重复发送
            const receiverMsgId = stringToHexArray(receiverGlobal).concat([0x5F])
                .concat(stringToHexArray(Math.floor(Date.now() / 1000).toString()))
                .concat([0x5F, 0x31, 0x36, 0x30, 0x5F, 0x78, 0x77, 0x65, 0x63, 0x68, 0x61, 0x74, 0x5F, 0x33]);

            // 0xb0, 0x02 是长度，需要看一下什么的长度
            const msgIdHeader = [0xb0, 0x02, 0x12, 0x2E, 0x0A, 0x2C]

            const senderHeader = [0x1A, senderGlobal.length + 2, 0x0A, senderGlobal.length];
            // wxid_xxxx 或者 chatroom
            const sender = stringToHexArray(senderGlobal);
            const receiverHeader = [0x22, receiverGlobal.length + 2, 0x0A, receiverGlobal.length]
            // wxid_xxxx
            const receiver = stringToHexArray(receiverGlobal)
            const randomId1 = [0x28, 0xF4, 0x0B]
            const type1 = [0x30, 0x00]
            const randomId2 = [0x38, 0xF4, 0x0B]
            const randomId3 = [0x42, 0x04, 0x08, 0x00, 0x12, 0x00]
            const randomId4 = [0x48, 0x03]
            const htmlHeader = [0x52, 0x32];

            const html = [0x3C,
                0x6D, 0x73, 0x67, 0x73, 0x6F, 0x75, 0x72, // 0x30 msgsour
                0x63, 0x65, 0x3E, 0x3C, 0x61, 0x6C, 0x6E, 0x6F, // 0x38 ce><alno
                0x64, 0x65, 0x3E, 0x3C, 0x66, 0x72, 0x3E, 0x31, // 0x40 de><fr>1
                0x3C, 0x2F, 0x66, 0x72, 0x3E, 0x3C, 0x2F, 0x61, // 0x48 </fr></a
                0x6C, 0x6E, 0x6F, 0x64, 0x65, 0x3E, 0x3C, 0x2F, // 0x50 lnode></
                0x6D, 0x73, 0x67, 0x73, 0x6F, 0x75, 0x72, // 0x58 msgsour
                0x63, 0x65, 0x3E                          // 0x60 ce>
            ];

            const cdnHeader = [0x58, 0x01, 0x60, 0x02, 0x68, 0x00, 0x7A, 0xB2, 0x01]
            // 3057 开头的cdn key
            const cdn = stringToHexArray(globalImageCdnKey);

            const cdn2Header = [0x82, 0x01, 0xB2, 0x01]
            const cdn2 = stringToHexArray(globalImageCdnKey)

            const aesKeyHeader = [0x8A, 0x01, 0x20]
            const aesKey = stringToHexArray(globalAesKey1)

            const randomId5 = [0x90, 0x01, 0x01, 0x98, 0x01, 0xFF, // 0x2C8
                0x13, 0xA0, 0x01, 0xFF, 0x13]

            const cdn3Header = [0xAA, 0x01, 0xB2, 0x01]
            const cdn3 = stringToHexArray(globalImageCdnKey)

            const randomId6 = [0xB0, 0x01, 0xF4, 0x0B]
            const randomId7 = [0xB8, 0x01, 0x68]
            const randomId8 = [0xC0, 0x01, 0x3A]
            const aesKey1Header = [0xCA, 0x01, 0x20]
            const aesKey1 = stringToHexArray(globalAesKey1)
            const aesKey2Header = [0xDA, 0x01, 0x20]
            const aesKey2 = stringToHexArray(globalAesKey2)

            const randomId9 = [0xE0, 0x01, 0xd9, 0xe7, 0xc7, 0xF3, 0x02]


            var left0 = [
                0xF0, 0x01, 0x00, 0xA0, 0x02, 0x00, // 0x3E0
                0xC8, 0x02, 0x00, 0x00 // 0x3E8
            ]

            const finalPayload = type.concat(msgId, cpHeader, cp, randomId, sysHeader, sys, msgIdHeader, receiverMsgId,
                senderHeader, sender, receiverHeader, receiver, randomId1, type1, randomId2, randomId3, randomId4, htmlHeader, html,
                cdnHeader, cdn, cdn2Header, cdn2, aesKeyHeader, aesKey, randomId5, cdn3Header, cdn3, randomId6, randomId7, randomId8,
                aesKey1Header, aesKey1, aesKey2Header, aesKey2, randomId9, left0)

            console.log("[+] Payload 准备写入");
            // dumpMemoryToHex(this.context.x1, 1024)
            // console.log("[+] 寄存器修改完成: X1=" + hexdump(this.context.x1, {
            //     offset: 0,
            //     length: 1024,
            //     header: true,
            //     ansi: true
            // }));

            protoX1PayloadAddr.writeByteArray(finalPayload);
            console.log("[+] Payload 已写入，长度: " + finalPayload.length);

            this.context.x1 = protoX1PayloadAddr;
            this.context.x2 = ptr(finalPayload.length);

            console.log("[+] 寄存器修改完成: X1=" + this.context.x1 + ", X2=" + this.context.x2, hexdump(protoX1PayloadAddr, {
                offset: 0,
                length: 1024,
                header: true,
                ansi: true
            }));
        },
    });
}

setImmediate(attachProto);

function toVarint(n) {
    let res = [];
    while (n >= 128) {
        res.push((n & 0x7F) | 0x80); // 取后7位，最高位置1
        n = n >> 7;                 // 右移7位
    }
    res.push(n); // 最后一位最高位为0
    return res;
}

function setReceiver() {
    console.log("[+] buf2RespAddr WeChat Base: " + baseAddr + "[+] Attaching to: " + buf2RespAddr);

    // 3. 开始拦截
    Interceptor.attach(buf2RespAddr, {
        onEnter: function (args) {
            const currentPtr = this.context.x1;
            let start = 0x1e;
            let senderLen = currentPtr.add(start).readU8();
            if (senderLen !== 0x14 && senderLen !== 0x13) {
                start = 0x1d;
                let senderLen = currentPtr.add(start).readU8();
                if (senderLen !== 0x14 && senderLen !== 0x13) {
                    return
                }
            }

            let senderPtr = currentPtr.add(start + 1);
            let sender = senderPtr.readUtf8String(senderLen);

            let receiverLenPtr = senderPtr.add(senderLen).add(3);
            let receiverLen = receiverLenPtr.readU8();
            let receiverStrPtr = receiverLenPtr.add(1);
            let receiver = receiverStrPtr.readUtf8String(receiverLen);

            let contentLenPtr = receiverStrPtr.add(receiverLen).add(6);
            if (isPrintableOrChinese(contentLenPtr, 1)) {
                contentLenPtr = contentLenPtr.add(-1);
            }
            const contentLenValue = readVarint(contentLenPtr)
            let contentPtr = contentLenPtr.add(contentLenValue.byteLength);
            var content = contentPtr.readUtf8String(contentLenValue.value);

            var selfId = receiver
            var msgType = "private"
            var groupId = ""
            var senderUser = sender
            var messages = [];
            messages.push({type: "text", data: {text: content}});

            if (sender.includes("@chatroom")) {
                msgType = "group"
                groupId = sender
                let splitIndex = -1;
                for (let i = 0; i < content.length; i++) {
                    if (content[i] === ':') {
                        splitIndex = i;
                        break;
                    }
                }

                senderUser = content.substring(0, splitIndex).trim();
                content = content.substring(splitIndex + 2).trim();

                messages = [];
                const parts = content.split('\u2005');
                for (let part of parts) {
                    part = part.trim();
                    if (!part.startsWith("@")) {
                        messages.push({type: "text", data: {text: part}});
                    }
                }

                const xmlPtr = contentPtr.add(contentLenValue.value).add(15);
                const xmlLenValue = readVarint(xmlPtr)
                const xml = xmlPtr.add(xmlLenValue.byteLength).readUtf8String(xmlLenValue.value);
                const atUserMatch = xml.match(/<atuserlist>([\s\S]*?)<\/atuserlist>/);
                const atUser = atUserMatch ? atUserMatch[1] : null;
                if (atUser) {
                    messages.push({type: "at", data: {qq: atUser}});
                }
            }

            send({
                message_type: msgType,
                user_id: senderUser, // 发送人的 ID
                self_id: selfId, // 接收人的 ID
                group_id: groupId, // 群 ID
                message_id: taskIdGlobal,
                type: "send",
                raw: {peerUid: taskIdGlobal},
                message: messages
            })
        },
    });
}

// 使用 setImmediate 确保在模块加载后执行
setImmediate(setReceiver)

function readVarint(addr) {
    let value = 0;
    let shift = 0;
    let count = 0;

    while (true) {
        let byte = addr.add(count).readU8();
        // 取低7位进行累加
        value |= (byte & 0x7f) << shift;
        count++; // 消耗了一个字节

        // 如果最高位是0，跳出循环
        if ((byte & 0x80) === 0) break;

        shift += 7;
        if (count > 5) return -1; // 安全校验，防止死循环
    }

    return {
        value: value,      // 最终长度数值 (例如 251)
        byteLength: count  // 长度字段占用的字节数 (例如 2)
    };
}

function dumpMemoryToHex(ptr, size) {
    try {
        // 1. 读取内存数据
        const buffer = ptr.readByteArray(size);
        const data = new Uint8Array(buffer);

        let output = "";
        let line = "";

        for (let i = 0; i < data.length; i++) {
            // 格式化为 0x00 形式
            const hex = "0x" + data[i].toString(16).padStart(2, '0').toUpperCase();
            line += hex;

            // 如果不是最后一个元素，添加逗号和空格
            if (i < data.length - 1) {
                line += ", ";
            }

            // 每 8 个字节输出一行
            if ((i + 1) % 8 === 0 || i === data.length - 1) {
                output += line + "\n";
                line = "";
            }
        }

        console.log("==================== MEMORY DUMP ====================");
        console.log(output);
        console.log("=====================================================");

    } catch (e) {
        console.log("[-] Dump 失败: " + e.message);
    }
}

function isPrintableOrChinese(startPtr, maxScanLength) {
    let offset = 0;
    while (offset < maxScanLength) {
        let b = startPtr.add(offset).readU8();

        if (b === 0) {
            // 扫描到 \0，且之前没有发现异常字节
            return offset > 0; // 如果第一个就是 \0，视为非字符串（可能是空指针）
        }

        // 判定逻辑：
        // 1. 可见 ASCII (32-126) 或 换行/制表符 (9, 10, 13)
        let isAscii = (b >= 32 && b <= 126) || (b === 9 || b === 10 || b === 13);

        // 2. 汉字 UTF-8 特征：第一个字节通常 >= 0x80 (128)
        // 严谨点：UTF-8 汉字首字节通常在 0xE4-0xE9 之间，后续字节在 0x80-0xBF 之间
        // 这里简化处理：如果是高位字符，我们暂时放行，由 readUtf8String 最终处理
        let isHighBit = (b >= 0x80);

        if (!isAscii && !isHighBit) {
            // 发现既不是 ASCII 也不是高位字节（如 0x01-0x1F 的控制字符），判定为指针
            return false;
        }
        offset++;
    }
    return true;
}

function patchCdnOnComplete() {
    Interceptor.attach(CndOnCompleteAddr, {
        onEnter: function (args) {
            console.log("[+] enter CndOnCompleteAddr");

            try {
                const x2 = this.context.x2;
                globalImageCdnKey = x2.add(0x60).readPointer().readUtf8String();
                globalAesKey1 = x2.add(0x78).readPointer().readUtf8String();
                globalAesKey2 = x2.add(0x90).readPointer().readUtf8String();
                console.log("[+] globalImageCdnKey: " + globalImageCdnKey + " globalAesKey1: " + globalAesKey1 + " globalAesKey2: " + globalAesKey2);
            } catch (e) {
                console.log("[-] Memory access error at onEnter: " + e);
            }
        }
    })
}

setImmediate(patchCdnOnComplete)

var uploadGlobalX0 = ptr(0)
var uploadFunc1Addr = ptr(0)
var uploadFunc2Addr = ptr(0)
var imageIdAddr = ptr(0)
var uploadAesKeyAddr1 = ptr(0)
var uploadAesKeyAddr2 = ptr(0)
var ImagePathAddr1 = ptr(0)
var ImagePathAddr2 = ptr(0)
var ImagePathAddr3 = ptr(0)
var uploadImagePayload = ptr(0);

function initMemo() {
    uploadFunc1Addr = Memory.alloc(24);
    uploadFunc2Addr = Memory.alloc(24);
    imageIdAddr = Memory.alloc(256);
    uploadAesKeyAddr1 = Memory.alloc(256);
    uploadAesKeyAddr2 = Memory.alloc(256);
    ImagePathAddr1 = Memory.alloc(256);
    ImagePathAddr2 = Memory.alloc(256);
    ImagePathAddr3 = Memory.alloc(256);
    uploadImagePayload = Memory.alloc(512);


    uploadFunc1Addr.writePointer(baseAddr.add(0x802b8b0));
    uploadFunc2Addr.writePointer(baseAddr.add(0x7fd5908));
    patchHex(imageIdAddr, "77 78 69 64 5F 37 77 64 31 65 63 65 39 39 66 37 69 32 31 5F 31 37 36 38 32 37 34 36 36 37 5F 32 33 32 5F 31");
    patchHex(uploadAesKeyAddr1, "37 65 61 34 31 64 35 36 39 66 37 30 35 33 35 37 37 38 30 39 36 38 65 39 31 30 34 32 38 34 63 66")
    patchHex(uploadAesKeyAddr2, "65 63 64 35 37 65 39 63 66 38 35 66 32 65 32 30 38 37 61 65 65 38 63 30 66 64 31 65 34 34 35 65")
    patchHex(ImagePathAddr1, "2F 55 73 65 72 73 2F 79 69 6E 63 6F 6E 67 2F 4C 69 62 72 61 72 79 2F 43 6F 6E 74 61 69 6E 65 72 73 2F 63 6F 6D 2E 74 65 6E 63 65 6E 74 2E 78 69 6E 57 65 43 68 61 74 2F 44 61 74 61 2F 44 6F 63 75 6D 65 6E 74 73 2F 78 77 65 63 68 61 74 5F 66 69 6C 65 73 2F 77 78 69 64 5F 6C 64 66 74 75 68 65 33 36 69 7A 67 31 39 5F 35 65 37 64 2F 74 65 6D 70 2F 30 34 65 62 61 61 62 37 65 33 65 61 36 30 35 30 65 32 36 66 66 33 31 64 38 39 63 63 31 32 31 65 2F 32 30 32 36 2D 30 31 2F 49 6D 67 2F 32 33 32 5F 31 37 36 38 32 37 33 36 36 37 2E 6A 70 67");
    patchHex(ImagePathAddr2, "2F 55 73 65 72 73 2F 79 69 6E 63 6F 6E 67 2F 4C 69 62 72 61 72 79 2F 43 6F 6E 74 61 69 6E 65 72 73 2F 63 6F 6D 2E 74 65 6E 63 65 6E 74 2E 78 69 6E 57 65 43 68 61 74 2F 44 61 74 61 2F 44 6F 63 75 6D 65 6E 74 73 2F 78 77 65 63 68 61 74 5F 66 69 6C 65 73 2F 77 78 69 64 5F 6C 64 66 74 75 68 65 33 36 69 7A 67 31 39 5F 35 65 37 64 2F 74 65 6D 70 2F 30 34 65 62 61 61 62 37 65 33 65 61 36 30 35 30 65 32 36 66 66 33 31 64 38 39 63 63 31 32 31 65 2F 32 30 32 36 2D 30 31 2F 49 6D 67 2F 32 33 32 5F 31 37 36 38 32 37 33 36 36 37 2E 6A 70 67");
    patchHex(ImagePathAddr3, "2F 55 73 65 72 73 2F 79 69 6E 63 6F 6E 67 2F 4C 69 62 72 61 72 79 2F 43 6F 6E 74 61 69 6E 65 72 73 2F 63 6F 6D 2E 74 65 6E 63 65 6E 74 2E 78 69 6E 57 65 43 68 61 74 2F 44 61 74 61 2F 44 6F 63 75 6D 65 6E 74 73 2F 78 77 65 63 68 61 74 5F 66 69 6C 65 73 2F 77 78 69 64 5F 6C 64 66 74 75 68 65 33 36 69 7A 67 31 39 5F 35 65 37 64 2F 74 65 6D 70 2F 30 34 65 62 61 61 62 37 65 33 65 61 36 30 35 30 65 32 36 66 66 33 31 64 38 39 63 63 31 32 31 65 2F 32 30 32 36 2D 30 31 2F 49 6D 67 2F 32 33 32 5F 31 37 36 38 32 37 33 36 36 37 2E 6A 70 67");
}

setImmediate(initMemo)


function manualUpload() {

    const payload = [
        0x20, 0x05, 0x33, 0x8C, 0x0B, 0x00, 0x00, 0x00, // 函数 10802b8b0 的指针
        0x00, 0x05, 0x33, 0x8C, 0x0B, 0x00, 0x00, 0x00, // 函数 107fd5908 的指针
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x40
        0xD0, 0x72, 0x20, 0x89, 0x0B, 0x00, 0x00, 0x00, // 图片id // 0x48
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x50
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x77, 0x78, 0x69, 0x64, 0x5F, 0x37, 0x77, 0x64, // 发送人 0x68
        0x31, 0x65, 0x63, 0x65, 0x39, 0x39, 0x66, 0x37,
        0x69, 0x32, 0x31, 0x00, 0x00, 0x00, 0x00, 0x13, // 发送人id长度
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x88
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0xAA, 0xAA, 0xAA, 0x01, 0x00, 0x00, 0x00, // 0x98
        0x00, 0x00, 0x00, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, // 0xa0
        0xA0, 0xBE, 0x2D, 0x8C, 0x0B, 0x00, 0x00, 0x00, // 某个aesid 7ea41d569f705357780968e9104284cf 0xa8
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xb0
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0xb8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x55, 0xDB, 0x89, 0x0B, 0x00, 0x00, 0x00, // 0xe0 图片地址 高清 /Users/yincong/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_ldftuhe36izg19_5e7d/temp/04ebaab7e3ea6050e26ff31d89cc121e/2026-01/Img/166_1768214492_hd.jpg
        0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xe8
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0xf0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0xf8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x100
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x108
        0x40, 0x54, 0xDB, 0x89, 0x0B, 0x00, 0x00, 0x00, // 0x110 图片地址 普清 /Users/yincong/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_ldftuhe36izg19_5e7d/temp/04ebaab7e3ea6050e26ff31d89cc121e/2026-01/Img/166_1768214492.jpg
        0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x118
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x120
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x5D, 0xDB, 0x89, 0x0B, 0x00, 0x00, 0x00, // 0x140 图片地址 缩略图 /Users/yincong/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/wxid_ldftuhe36izg19_5e7d/temp/04ebaab7e3ea6050e26ff31d89cc121e/2026-01/Img/166_1768214492_thumb.jpg
        0xB2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x148
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x150
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x158
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x160
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x168
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x170
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x178
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x180
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x188
        0x00, 0xAA, 0xAA, 0xAA, 0x01, 0x00, 0x00, 0x00, // 0x190
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x198
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x1a0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1a8
        0x00, 0x00, 0x00, 0x00, 0x0A, 0x0A, 0x0A, 0x0A, // 0x1b0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1b8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1c0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1c8
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1d0
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1d8 有个指针
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1e0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1e8
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x1f0
        0xD0, 0x78, 0x46, 0x8C, 0x0B, 0x00, 0x00, 0x00, // 0x1f8 某个key ecd57e9cf85f2e2087aee8c0fd1e445e
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x200
        0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // 0x208
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x210
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x218
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x220
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x228
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x230
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x238
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x240
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x248
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x250
        0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x258
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x260
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x268
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x270
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x278
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// 0x280
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // 0x288
    ]

    uploadImagePayload.writeByteArray(payload);
    uploadImagePayload.writePointer(uploadFunc1Addr);
    uploadImagePayload.add(0x08).writePointer(uploadFunc2Addr);
    uploadImagePayload.add(0x48).writePointer(imageIdAddr);
    uploadImagePayload.add(0xa8).writePointer(uploadAesKeyAddr1);
    uploadImagePayload.add(0xe0).writePointer(ImagePathAddr1);
    uploadImagePayload.add(0x110).writePointer(ImagePathAddr2);
    uploadImagePayload.add(0x140).writePointer(ImagePathAddr3);
    uploadImagePayload.add(0x1f8).writePointer(uploadAesKeyAddr2);


    const targetAddr = baseAddr.add(0x45DC834);
    const startC2cUpload = new NativeFunction(targetAddr, 'int64', ['pointer', 'pointer']);

    console.log("开始手动触发 C2C 上传...");
    const result = startC2cUpload(uploadGlobalX0, uploadImagePayload);
    console.log("调用结果: " + result);
}

function attachUploadMedia() {
    const targetAddr = baseAddr.add(0x45DC85C);
    Interceptor.attach(targetAddr, {
        onEnter: function (args) {
            console.log("[+] enter UploadMedia");
            uploadGlobalX0 = this.context.x0;
            console.log("UploadMedia x1: " + uploadGlobalX0);
        }
    })
}

setImmediate(attachUploadMedia);


rpc.exports = {
    manualTrigger: manualTrigger,
    manualUpload: manualUpload
};