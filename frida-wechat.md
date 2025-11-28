基于微信4.1.5.17版本

注意点
1. 需要让frida启动微信才能通过内存地址找到代码位置        
```
MemoryAccessMonitor.enable(
    {
        base: ptr("0x60000173BCDA"),
        size: 0x200  // buffer 大小
    },
    {
        onAccess(details) {
            console.log("Access by:", DebugSymbol.fromAddress(details.from));
            console.log("Operation:", details.operation);
        }
    }
);
```

2. 通过ce确定内存位置        
![image](https://github.com/user-attachments/assets/5980e46a-d5b7-4556-b291-a9beca0cbf47)


3. 可以看到打印日志        
```
Access by: 0x10dc28ccc libGLESv2.dylib!0x250ccc (0x250ccc)
Operation: read
Access by: 0x10a08083c WeChat!0x580883c (0x10580883c)
Operation: read
7                  Access by: 0x18b233444 libsystem_malloc.dylib!nanov2_malloc
Operation: read
Access by: 0x10a08083c WeChat!0x580883c (0x10580883c)
Operation: read

定位到函数sub_105808800
```

sub_104622628 应该是日志打印的函数        
0x1057ee3a8 会打印输入框的文字        
0x105B7E990 QNSView handleKeyEvent:eventType 键盘事件        
sub_104A15520 -> sub_1049FB5BC -> sub_1049FB958->sub_1049FF850 -> sub_1049E9E68 -> sub_10461CE50 -> write 发送消息的方法        

["104565AD0", "104566E24", "1045CF820", "104590888", "1045BFED0", "104394290", "1043877CC", "104387764", "1043382C0"] 加密的方法        
1045BFED0 收消息 的入口之一，可以往上再追一下, 发消息也有可能是入口        
```
0x105527d30 WeChat!0x45bfd30 (0x1045bfd30)
0x1052fc2cc WeChat!0x43942cc (0x1043942cc)
0x1033c2a3c WeChat!0x245aa3c (0x10245aa3c)
0x10535389c WeChat!0x43eb89c (0x1043eb89c)
0x1052a0314 WeChat!0x4338314 (0x104338314)
0x105352e9c WeChat!0x43eae9c (0x1043eae9c)
0x103c465ac WeChat!0x2cde5ac (0x102cde5ac)
0x1033bcdd0 WeChat!0x2454dd0 (0x102454dd0)
0x1033e221c WeChat!0x247a21c (0x10247a21c)
0x10535389c WeChat!0x43eb89c (0x1043eb89c)
0x1052a0314 WeChat!0x4338314 (0x104338314)
0x105352e9c WeChat!0x43eae9c (0x1043eae9c)
0x103c465ac WeChat!0x2cde5ac (0x102cde5ac)
0x1033e1c64 WeChat!0x2479c64 (0x102479c64)
0x103d711bc WeChat!0x2e091bc (0x102e091bc)
0x104faea1c WeChat!0x4046a1c (0x104046a1c)
```

102454D74, 10247A138 每次发消息才执行，说明是入口，至少是入库的入口，可以作为入口作为突破 
102479A30 这个函数 调用 sub_103D6C730 出来的值
