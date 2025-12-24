执行use_struct.py脚本
然后执行trigger_send.py脚本，改task id， 改 cgi，改第一个指针即可，第一个指针sub_10444A99C 函数执行的x0
在req2buf中打断点，在x0+60处，patch指针0x1120eed40
更改0x1120eed40 的taskId
然后在protobuf编辑处打断点，执行脚本update_sendMsg.py