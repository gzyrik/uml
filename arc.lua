do
    local distor_dat = Dissector.get("data")
    local udp_encap_table = DissectorTable.get("udp.port")

    local ARC_NAME = "ARC"
    local ADDR_NAME= ARC_NAME ..".ADDR"
    local MPTH_NAME= "MPATH"
    local vals_bool ={[0]="False"}
    for i=1,0xFF do vals_bool[i] = "True" end

    local HeadType  = {[0]="Data","OobData","Ping","PingAck"}
    local Head_Data, Head_OobData, Head_Ping, Head_PingAck = 0, 1, 2, 3
    local PacketType= {[0]="Ctrl","Normal","FragFirst","FragSecond"}
    local Packet_Ctrl, Packet_Normal,Packet_FragFirst, Packet_FragSecond = 0, 1, 2, 3
    local CtrlType  = {[0]="EchoRequest", "EchoReply", "HostUnreach","PortUnreach","ReportCost"}
    local Ctrl_EchoRequest, Ctrl_EchoReply, Ctrl_ReportHostUnreach, Ctrl_ReportPortUnreach, Ctrl_ReportCost = 0, 1, 2, 3, 4
    local AddrType  = {[0]='', "RouterId", "ClientId", "Router&ClientId", "RefClientId",
    "Router&RefClientId", "ClientId&RefClientId", "Router&ClientId&RefClientId"}
    local Addr_RouterId, Addr_ClientId, Addr_RefClientId = 1, 2, 4
    local MPacketType = {[0]="Normal", "FragFirst", "FragSecond", "Report"}
    local MPacket_Normal, MPacket_FragFirst, MPacket_FragSecond, MPacket_Report = 0, 1, 2, 3, 4
    local MPathType = {[0]="C1_EP_CP", "C1_EP_C2", "C1_CP", "C1_C2"}
    local MPath_C1_EP_CP, MPath_C1_EP_C2, MPath_C1_CP, MPath_C1_C2 = 0, 1, 2, 3

    local proto_arc = Proto(ARC_NAME, "Application Router Control")
    local proto_addr= Proto(ADDR_NAME, "Application Router Addr")
    local proto_mpth= Proto(MPTH_NAME, "Multi Path")

    proto_arc.fields.sendSeqno      = ProtoField.uint16(ARC_NAME..".sendSeqno","Sequence Number",base.DEC)
    proto_arc.fields.sendTimestamp  = ProtoField.uint16(ARC_NAME..".sendTimestamp","Send Timestamp",base.DEC)
    proto_arc.fields.reportTimestamp= ProtoField.uint16(ARC_NAME..".reportTimestamp","Report Timestamp",base.DEC)         
    proto_arc.fields.reportLoss     = ProtoField.uint8 (ARC_NAME..".reportLoss","Report Loss", base.DEC)
    proto_arc.fields.headType       = ProtoField.uint8 (ARC_NAME..".headType","Head Type",base.DEC, HeadType,0x7)
    proto_arc.fields.packetType     = ProtoField.uint8 (ARC_NAME..".packetType","Packet Type",base.DEC, PacketType,0x70)
    proto_arc.fields.did            = ProtoField.uint32(ARC_NAME..".did","Did",base.DEC)
    proto_arc.fields.level          = ProtoField.uint8 (ARC_NAME..".level","Level",base.DEC)
    proto_arc.fields.pathCount      = ProtoField.uint8 (ARC_NAME..".pathCount","Path Count",base.DEC, nil, 0x3)
    proto_arc.fields.fromAddrType   = ProtoField.uint8 (ARC_NAME..".fromAddrType","From Addr Type",base.DEC, AddrType, 0x1c)
    proto_arc.fields.toAddrType     = ProtoField.uint8 (ARC_NAME..".toAddrType","To Addr Type",base.DEC, AddrType, 0xe0)
    proto_arc.fields.fromOverflow   = ProtoField.uint8 (ARC_NAME..".fromOverflow","From Overflow",base.DEC)
    proto_arc.fields.toOverflow     = ProtoField.uint8 (ARC_NAME..".toOverflow","To Overflow",base.DEC)
    proto_arc.fields.paths          = ProtoField.uint16(ARC_NAME..".paths","Path Id",base.DEC)
    proto_arc.fields.fromClientIpv4 = ProtoField.ipv4  (ARC_NAME..".fromClientIpv4","fromClientIp")
    proto_arc.fields.fromClientIpv6 = ProtoField.ipv6  (ARC_NAME..".fromClientIpv6","fromClientIp")
    proto_arc.fields.ctrlType       = ProtoField.uint8 (ARC_NAME..".ctrlType","Ctrl Type", base.DEC, CtrlType)
    proto_arc.fields.padding        = ProtoField.bytes (ARC_NAME..".padding","Padding")

    proto_addr.fields.routerId      = ProtoField.uint16(ADDR_NAME..".routerId","Router Id",base.DEC)
    proto_addr.fields.routerCost    = ProtoField.uint16(ADDR_NAME..".routerCost","Router Cost",base.DEC)
    proto_addr.fields.clientId      = ProtoField.uint32(ADDR_NAME..".clientId","Client Id",base.DEC)
    proto_addr.fields.clientCost    = ProtoField.uint16(ADDR_NAME..".clientCost","Client Cost",base.DEC)
    proto_addr.fields.refRouterId   = ProtoField.uint32(ADDR_NAME..".refRouterId","refRouter Id",base.DEC)
    proto_addr.fields.refClientId   = ProtoField.uint16(ADDR_NAME..".refClientId","refClient Id",base.DEC)
    proto_addr.fields.port          = ProtoField.uint16(ADDR_NAME..".port","port",base.DEC)

    proto_mpth.fields.type          = ProtoField.uint32(MPTH_NAME..".type","type",base.DEC, MPacketType, bit32.lshift(3, 30))
    proto_mpth.fields.path          = ProtoField.uint32(MPTH_NAME..".path","path",base.DEC, MPathType, bit32.lshift(3, 28))
    proto_mpth.fields.seqno         = ProtoField.uint32(MPTH_NAME..".seqno","seqno",base.DEC, nil, bit32.lshift(0x3FFF, 14))
    proto_mpth.fields.timestamp     = ProtoField.uint32(MPTH_NAME..".timestamp","timestamp",base.DEC, nil, 0x3FFF)

    local HEAD_SIZE = 8
    local function decodeHead(spec, tvb, root)
        local tree = root:add(proto_arc, tvb(0, HEAD_SIZE))
        tree:set_text(HeadType[spec.headType]..' '..PacketType[spec.packetType])
        spec.sendSeqno = tvb(0,2):uint()
        tree:add(proto_arc.fields.sendSeqno, tvb(0,2))
        tree:add(proto_arc.fields.sendTimestamp, tvb(2,2))
        tree:add(proto_arc.fields.reportTimestamp, tvb(4,2))
        tree:add(proto_arc.fields.reportLoss, tvb(6,1))
        tree:add(proto_arc.fields.headType, tvb(7,1))
        tree:add(proto_arc.fields.packetType, tvb(7,1))
        return tvb(HEAD_SIZE):tvb()
    end

    local INFO_SIZE = 8
    local function decodeInfo(spec, tvb, root)
        root:add(proto_arc.fields.did, tvb(0, 4))
        root:add(proto_arc.fields.level, tvb(4, 1))
        root:add(proto_arc.fields.pathCount, tvb(5, 1))
        root:add(proto_arc.fields.fromAddrType, tvb(5, 1))
        root:add(proto_arc.fields.toAddrType, tvb(5, 1))
        root:add(proto_arc.fields.fromOverflow, tvb(6, 1))
        root:add(proto_arc.fields.toOverflow, tvb(7, 1))
        return tvb(INFO_SIZE):tvb()
    end

    local function decodePaths(count, tvb, root)
        if count == 0 then return tvb end
        local tree, v = root:add(proto_arc, tvb(0, 2* count)),{}
        for i=0, count do
            v[i+1] = tvb(i*2,2):uint()
            tree:add(proto_arc.fields.paths, tvb(i*2,2))
        end
        tree:set_text(table.concat(v, ','))
        return tvb(count*2):tvb()
    end

    local ADDR_SIZE = {[0]=2, 6, 8, 12, 8, 12, 14, 18}; 
    local function decodeAddr(title, addrtype, tvb, root)
        local tree = root:add(proto_addr, tvb(0, ADDR_SIZE[bit32.band(addrtype,7)]))
        tree:set_text(title)
        local i=0
        local routerId,clientId,refRouterId,refClientId=0,0,0,0
        if bit32.band(addrtype, Addr_RouterId) ~= 0 then
            routerId = tvb(i,2):uint()
            tree:add(proto_addr.fields.routerId, tvb(i,2))
            tree:add(proto_addr.fields.routerCost, tvb(i+2,2))
            i = i + 4
        end
        if  bit32.band(addrtype, Addr_ClientId) ~= 0 then
            clientId = tvb(i,4):uint()
            tree:add(proto_addr.fields.clientId, tvb(i,4))
            tree:add(proto_addr.fields.clientCost, tvb(i+4,2))
            i = i + 6
        end
        if bit32.band(addrtype, Addr_RefClientId) ~= 0 then
            refRouterId, refClientId = tvb(i,2):uint(), tvb(i+2,4):uint()
            tree:add(proto_addr.fields.refRouterId, tvb(i,2))
            tree:add(proto_addr.fields.refClientId, tvb(i+2,4))
            i = i + 6
        end
        local port = tvb(i,2):uint()
        tree:add(proto_addr.fields.port, tvb(i,2))
        i = i + 2

        local info=''
        if refRouterId  == 0 then
            if routerId ~= 0 then info = routerId end
            if clientId ~= 0 then info = info .. '.' .. clientId end
        else
            info = refRouterId
            if refClientId ~= 0 then info = info .. '.' .. refClientId end
        end
        if port ~= 0 then info = info .. ':' .. port end
        tree:append_text(' ' .. info)

        return tvb(i):tvb(), info, port
    end

    local function decodeCtrl(tvb, root, info)
        local len = tvb:len()
        if len == 0 then return tvb end
        local ctrl = tvb(0, 1):uint()
        local tree = root:add(proto_arc, tvb())
        tree:set_text(CtrlType[ctrl])
        tree:add(proto_arc.fields.ctrlType, tvb(0, 1))
        table.insert(info, CtrlType[ctrl])
        return tvb(len):tvb()
    end

    local function decodePacket(spec, tvb, root, info)
        tvb = decodeInfo(spec, tvb, root)
        tvb = decodePaths(spec.pathCount, tvb, root)
        local tvb, fromAddrInfo, fromPort = decodeAddr("From Addr", spec.fromAddrType, tvb, root)
        local tvb, toAddrInfo, toPort = decodeAddr("To Addr", spec.toAddrType, tvb, root)
        if spec.fromClientIp then
            if bit32.band(spec.level, 4) ~= 0 then
                root:add(proto_arc.fields.fromClientIpv6, tvb(0,16))
                tvb = tvb(16):tvb()
            else
                root:add(proto_arc.fields.fromClientIpv4, tvb(0,4))
                tvb = tvb(4):tvb()
            end
        end
        if string.len(fromAddrInfo) > 0 or string.len(toAddrInfo) > 0 then
            table.insert(info, fromAddrInfo .. '→' .. toAddrInfo)
        end
        if spec.headType == Head_OobData then
            table.insert(info, 'len='.. tvb:len())
        elseif spec.packetType == Packet_Ctrl then
            tvb = decodeCtrl(tvb, root, info)
        elseif fromPort == 2 and toPort == 2 and tvb:len() >= 22 then
            local i, len = 5, tvb(1, 4):uint()
            local localPubHost, i, len = tvb(i, len):string(), i+len, 4
            local localPubPort, i, len = tvb(i, len):uint(), i+len, 4
            local i, len = i+len, tvb(i, len):uint()
            local localPrvHost, i, len = tvb(i, len):string(), i+len, 4
            local localPrvPort, i, len = tvb(i, len):uint(), i+len, 4
            local remotePubPort, i = tvb(i, len):uint(), i+len
            table.insert(info, string.format("%s:%s ~ %s:%d > %d", localPrvHost, localPrvPort, localPubHost, localPubPort, remotePubPort))
            tvb = tvb(i):tvb()
        else
            table.insert(info, string.format("len=%d, did=%d,level=%d", tvb:len(), spec.did, spec.level))
        end
        return tvb
    end

    local function decodeMpath(tvb, root)
        local range = tvb(0, 4)
        local head = range:uint()
        local mtype, mpath = bit32.rshift(head, 30), bit32.band(bit32.rshift(head, 28),3)
        local tree = root:add(proto_mpth, range)
        tree:set_text(MPacketType[mtype]..' '..MPathType[mpath])
        tree:add(proto_mpth.fields.type, range)
        tree:add(proto_mpth.fields.path, range)
        tree:add(proto_mpth.fields.seqno, range)
        tree:add(proto_mpth.fields.timestamp, range)
        return tvb(4):tvb()
    end

    local function arc_parse(tvb)
        local len, size = tvb:len(), HEAD_SIZE
        if len < size then return false end
        local b = tvb(7,1):uint()
        local spec = {headType = bit32.band(b, 7), packetType = bit32.rshift(b,4)}
        if spec.headType > Head_PingAck or spec.packetType > Packet_FragSecond then return false end

        if spec.headType < Head_Ping then
            size = HEAD_SIZE + INFO_SIZE
            if len < size then return false end
            spec.did, spec.level = tvb(HEAD_SIZE, 4):uint(), tvb(HEAD_SIZE+4, 1):uint()
            b = tvb(HEAD_SIZE+5, 1):uint()
            spec.fromAddrType = bit32.band(bit32.rshift(b, 2), 7)
            spec.toAddrType = bit32.band(bit32.rshift(b, 5), 7)
            spec.pathCount = bit32.band(b, 3) 
            spec.fromClientIp = (bit32.band(spec.fromAddrType, Addr_ClientId) ~= 0)
            size = size + spec.pathCount*2 + ADDR_SIZE[bit32.band(spec.fromAddrType,7)] + ADDR_SIZE[bit32.band(spec.toAddrType,7)]
            if spec.fromClientIp then
                if bit32.band(spec.level, 4) ~= 0 then
                    size = size + 16
                else
                    size = size + 4
                end
            end
            if len < size then return false end
            if spec.packetType == Packet_Ctrl then
                spec.ctrlType = tvb(size, 1):uint()
                size = len
            end
        end
        return spec, size
    end

    local function arc_dissector(tvb, pinfo, root)
        local spec, len = arc_parse(tvb)
        if not spec then return tvb end

        local tree = root:add(proto_arc, tvb(0, len))
        tvb = decodeHead(spec, tvb, tree)
        local info = {string.format("Seq=0x%X %s", spec.sendSeqno,
        spec.headType == Head_Data and PacketType[spec.packetType] or HeadType[spec.headType])}
        if spec.headType < Head_Ping then tvb = decodePacket(spec, tvb, tree, info) end

        pinfo.cols.info = table.concat(info, ' ')
        pinfo.cols.protocol = ARC_NAME
        return tvb
    end

    local function is_rtp(proto, tvb, len, off)
        if proto ~= 'rtp' or len < off+8 then return false end
        local b0 = tvb(off,1):uint()
        if bit32.rshift(b0, 6) ~= 2 then return false end
        local payload = tvb(off+1,1):uint()
        if payload == 192 or payload == 195 -- RTCP
            or ( 199 < payload and payload < 208) then
            return true
        end 
        if len < off+12 then return false end
        local CC = bit32.band(b0, 0xf)
        if off+12+CC*4 > len then return false end
        local X = (bit32.band(b0, 0x10) ~= 0)
        if X and len < off + 16 + CC*4 then return false end
        return true
    end

    local function is_jmp(proto, tvb,len, off)
        if proto ~= 'jmp' or len < 3 + off then return false end
        local jmptype = bit32.band(tvb(off+2,1):uint(),0xf)
        if jmptype > 6 then return false end
        if jmptype ~= 5 and len < 12+off then return false end
        return true
    end

    local distor_payload, payload
    proto_arc.prefs.padding = Pref.uint("Padding", 1, "Padding before payload")
    proto_arc.prefs.payload = Pref.string("Payload Protocal", "rtp", "payload protocal name")
    proto_arc.prefs.mpath   = Pref.bool("Has Mpath", false, "have Mpath head")
    function proto_arc.dissector(tvb, pinfo, root)
        tvb = arc_dissector(tvb, pinfo, root)
        local len = tvb:len()
        if len == 0 then return true end
        if len > 4 and proto_arc.prefs.mpath then tvb = decodeMpath(tvb, root) end
        local padding = proto_arc.prefs.padding
        if padding > 0 and len > padding then
            root:add(proto_arc.fields.padding, tvb(0,padding))
        end
        if payload ~= proto_arc.prefs.payload then
            payload = proto_arc.prefs.payload
            distor_payload = Dissector.get(payload)
        end
        if distor_payload and (
            is_rtp(payload, tvb, len, padding)
            or is_jmp(payload, tvb, len, padding)
            ) then
            return distor_payload:call(tvb(padding):tvb(), pinfo, root)
        else
            return distor_dat:call(tvb, pinfo, root)
        end
    end
    udp_encap_table:add(8000, proto_arc)
end
