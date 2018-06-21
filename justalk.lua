--这个dissector只是把几个协议组合起来而已，并不是识别一种新的协议
--Justalk Cloud 固定包头5字节
do
    local JCP_NAME = "jcp"

    --创建一个Proto类的对象，表示一种协议
    local proto_jcp  = Proto(JCP_NAME,"Justalk Cloud Protocal")

    --创建几个ProtoField对象，就是主界面中部Packet Details窗格中能显示的那些属性
    local field_head = ProtoField.bytes(JCP_NAME..".head","head")

    --把ProtoField对象加到Proto对象上
    proto_jcp.fields = { field_head }

    --用Dissector.get函数可以获得另外一个协议的解析组件
    local distor_rtp = Dissector.get("rtp")
    assert(distor_rtp, "RTP dissector not found")

    local distor_dat = Dissector.get("data")
    assert(distor_dat, "DATA dissector not found")
    
    local function JustalkCloud_dissector(tvb, pinfo, root)
        local HEAD = 5
        --先检查报文长度，太短的不是我的协议
        if tvb:len() < HEAD+20 then return false end
        --@TODO 更多检查
        --if not bit32.btest(tvb(5,1):uint(), bit32.lshift(2, 6)) then return false end

        --现在知道是我的协议了，放心大胆添加Packet Details
        --
        --root:add会在Packet Details窗格中增加一行协议
        local tree = root:add(proto_jcp, tvb(0,HEAD))

        --tree:add，在Packet Details窗格中增加一行属性，
        --并指定要鼠标点击该属性时Packet Bytes窗格中会选中哪些字节
        local field = tree:add(field_head, tvb(0,HEAD))

        --调用另外一个dissector
        distor_rtp:call(tvb(HEAD):tvb(), pinfo, root)
        return true
    end

    --为Proto对象添加一个名为dissector的函数，
    --Wireshark会对每个“相关”数据包调用这个函数
    function proto_jcp.dissector(tvb, pinfo, root)
        if not JustalkCloud_dissector(tvb, pinfo, root) then
            --distor_dat这个dissector几乎是必不可少的；当发现不是我的协议时，就应该调用
            distor_dat:call(tvb, pinfo, root)
        end
    end

    --所有的dissector都是以“table”的形式组织的，table表示上级协议
    --这个是获得udp协议的DissectorTable，并且以端口号排列
    DissectorTable.get("udp.port"):add(0, proto_jcp);
end
