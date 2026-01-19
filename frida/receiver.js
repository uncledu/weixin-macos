var baseAddr = Process.getModuleByName("WeChat").base;
if (!baseAddr) {
    console.error("[!] 找不到 WeChat 模块基址，请检查进程名。");
}
console.log("[+] WeChat base address: " + baseAddr);

function setReceiver() {
    var buf2RespAddr = baseAddr.add(0x347BD44);
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

            const x2 = this.context.x2.toInt32();
            const fields = getProtobufRawBytes(currentPtr, x2)

            const sender = fields[0]
            const receiver = fields[1]
            const content = fields[2]
            const xml = fields[3]

            if (sender === "" || receiver === "" || content === "" || xml === "") {
                console.log("字段缺失，无法解析 sender:" + sender + " receiver:" + receiver + hexdump(currentPtr, {
                    length: x2,
                    header: true,
                    ansi: true,
                }))
                return;
            }

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

                messages = [];
                const parts = content.split('\u2005');
                for (let part of parts) {
                    part = part.trim();
                    if (!part.startsWith("@")) {
                        messages.push({type: "text", data: {text: part}});
                    }
                }

                const atUserMatch = xml.match(/<atuserlist>([\s\S]*?)<\/atuserlist>/);
                const atUser = atUserMatch ? atUserMatch[1] : null;
                if (atUser) {
                    messages.push({type: "at", data: {qq: atUser}});
                }
            }

            const msgId = generateAESKey()
            send({
                message_type: msgType,
                user_id: senderUser, // 发送人的 ID
                self_id: selfId, // 接收人的 ID
                group_id: groupId, // 群 ID
                message_id: msgId,
                type: "send",
                raw: {peerUid: msgId},
                message: messages
            })
        },
    });
}

// 使用 setImmediate 确保在模块加载后执行
setImmediate(setReceiver)

function generateAESKey() {
    const chars = 'abcdef0123456789';
    let key = '';
    for (let i = 0; i < 32; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
}


function getProtobufRawBytes(pBuffer, scanSize) {
    const tags = [0x12, 0x1A, 0x2A, 0x52];
    let uint8Array;

    try {
        const mem = pBuffer.readByteArray(scanSize);
        if (!mem) return [];
        uint8Array = new Uint8Array(mem);
    } catch (e) {
        console.error("读取内存失败: " + e);
        return [];
    }

    let finalResults = [];

    let i = 0x1a;
    tags.forEach(targetTag => {
        let found = false;
        for (; i < uint8Array.length; i++) {
            if (uint8Array[i] === targetTag) {
                // 1. 解析 Varint 长度 (支持 1-5 字节长度标识)
                let length = 0;
                let shift = 0;
                let bytesReadForLen = 0;
                i = i + 1;

                while (i < uint8Array.length) {
                    let b = uint8Array[i];
                    length |= (b & 0x7F) << shift;
                    bytesReadForLen++;
                    i++;
                    if (!(b & 0x80)) break;
                    shift += 7;
                }

                // 2. 截取原始 Byte 数据
                if (i + length <= uint8Array.length) {
                    let rawData = uint8Array.slice(i, i + length);
                    finalResults.push(getCleanString(rawData));
                    i += length;
                } else {
                    finalResults.push(null); // 长度越界
                }

                found = true;
                break; // 找到第一个匹配的 Tag 就跳出
            }
        }
        if (!found) finalResults.push(null); // 未找到该 Tag
    });

    return finalResults;
}

function getCleanString(uint8Array) {
    var out = "";
    var i = 0;
    var len = uint8Array.length;

    while (i < len) {
        var c = uint8Array[i++];

        // 1. 处理单字节 (ASCII: 0xxxxxxx)
        if (c < 0x80) {
            // 只保留可见字符 (Space 32 到 ~ 126)
            if (c >= 32 && c <= 126) {
                out += String.fromCharCode(c);
            }
        }
        // 2. 处理双字节 (110xxxxx 10xxxxxx)
        else if ((c & 0xE0) === 0xC0 && i < len) {
            var c2 = uint8Array[i++];
            if ((c2 & 0xC0) === 0x80) {
                // 这种通常是特殊拉丁字母等，按需保留
                var charCode = ((c & 0x1F) << 6) | (c2 & 0x3F);
                out += String.fromCharCode(charCode);
            }
        }
        // 3. 处理三字节 (1110xxxx 10xxxxxx 10xxxxxx) -> 绝大多数汉字在此
        else if ((c & 0xF0) === 0xE0 && i + 1 < len) {
            var c2 = uint8Array[i++];
            var c3 = uint8Array[i++];
            if ((c2 & 0xC0) === 0x80 && (c3 & 0xC0) === 0x80) {
                var charCode = ((c & 0x0F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F);
                if (
                    (charCode >= 0x4E00 && charCode <= 0x9FA5) || // 基本汉字
                    (charCode >= 0x3000 && charCode <= 0x303F) || // 常用中文标点 (。，、)
                    (charCode >= 0xFF00 && charCode <= 0xFFEF) || // 全角符号/标点 (！：？)
                    (charCode >= 0x2000 && charCode <= 0x206F) || // 常用标点扩展 (含 \u2005)
                    (charCode >= 0x3400 && charCode <= 0x4DBF)    // 扩展 A 区汉字
                ) {
                    out += String.fromCharCode(charCode);
                }
            }
        }
        else if ((c & 0xF8) === 0xF0 && i + 2 < len) {
            var c2 = uint8Array[i++];
            var c3 = uint8Array[i++];
            var c4 = uint8Array[i++];
            if ((c2 & 0xC0) === 0x80 && (c3 & 0xC0) === 0x80 && (c4 & 0xC0) === 0x80) {
                // 计算 Unicode 码点
                var codePoint = ((c & 0x07) << 18) | ((c2 & 0x3F) << 12) | ((c3 & 0x3F) << 6) | (c4 & 0x3F);

                // Emoji 范围通常在 U+1F000 到 U+1F9FF 之间
                if (codePoint >= 0x1F000 && codePoint <= 0x1FADF) {
                    // 使用 fromCodePoint 处理 4 字节字符
                    out += String.fromCodePoint(codePoint);
                }
            }
        }
    }
    return out;
}