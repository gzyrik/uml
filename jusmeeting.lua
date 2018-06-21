local distor_rtp = Dissector.get("rtp")
assert(distor_rtp, "RTP dissector not found")
local distor_dat = Dissector.get("data")
assert(distor_dat, "DATA dissector not found")
local udp_encap_table = DissectorTable.get("udp.port")
assert(udp_encap_table, "udp.port DissectorTable not found")



local JMP_SIZE = 12
local JMCP_SIZE= 3
local JMP_NAME = "jmp"
local JMCP_NAME = "jmcp"
local vals_bool ={[0]="False"}
for i=1,0xFF do vals_bool[i] = "True" end

do
    local vals_ctypes = {"Sr", "Rr", "Fir", "Tmmbr", "SAD", "ASAD","WAD","AWAD","Nack","NetW","SVRR"}
    local proto_jmcp = Proto(JMCP_NAME, "JusMeeting Control Protocal")
    local field_code = ProtoField.uint8(JMCP_NAME..".code","Code",base.DEC,vals_ctypes)
    local field_csize = ProtoField.uint8(JMCP_NAME..".csize","Code Size",base.DEC)
    local field_rr_fLost = ProtoField.uint8(JMCP_NAME..".rr.fLost","fractionLost",base.DEC)
    local field_rr_cLost = ProtoField.uint24(JMCP_NAME..".rr.cLost","cumulativeLost",base.DEC)
    local field_rr_eHSeq = ProtoField.uint32(JMCP_NAME..".rr.eHSeq","extendedHighSeqNum",base.DEC)
    local field_rr_jiter = ProtoField.uint32(JMCP_NAME..".rr.jiter","jitter",base.DEC)
    local field_rr_lstSR = ProtoField.uint32(JMCP_NAME..".rr.lstsr","lastSR",base.DEC)
    local field_rr_dSLSR = ProtoField.uint32(JMCP_NAME..".rr.dSLSR","delaySinceLastSR",base.DEC)
    local field_sr_paket = ProtoField.uint32(JMCP_NAME..".sr.paket","sendPacketCount",base.DEC, nil, 0x7FFFFFFF)
    local field_sr_bytes = ProtoField.uint32(JMCP_NAME..".sr.bytes","sendOctetCount",base.DEC)
    local field_sr_NTPms = ProtoField.uint32(JMCP_NAME..".sr.NTPms","NTPTimestamp",base.DEC)
    local field_wadtype  = ProtoField.uint16(JMCP_NAME..".wad","WAD Type",base.DEC)
    local field_tmmbr = ProtoField.uint32(JMCP_NAME..".tmmbr","Tmmbr kbps",base.DEC)
    local field_subindex = ProtoField.uint16(JMCP_NAME..".subindex","Target",base.HEX)
    local field_sublevel0 = ProtoField.uint8(JMCP_NAME..".sublevel0","Level0",base.HEX, nil, 0xF0)
    local field_sublevel1 = ProtoField.uint8(JMCP_NAME..".sublevel1","Level1",base.HEX, nil, 0x0F)
    local field_sublevel2 = ProtoField.uint8(JMCP_NAME..".sublevel2","Level2",base.HEX, nil, 0xF0)
    local field_sublevel3 = ProtoField.uint8(JMCP_NAME..".sublevel3","Level3",base.HEX, nil, 0x0F)
    local field_subidr   = ProtoField.uint8(JMP_NAME..".subIDR","IDR",base.DEC, vals_bool,0x80)
    proto_jmcp.fields = {
        field_code, field_csize,
        field_rr_fLost,field_rr_cLost,field_rr_eHSeq,field_rr_jiter,field_rr_lstSR,field_rr_dSLSR,
        field_sr_paket,field_sr_bytes,field_sr_NTPms,
        field_tmmbr,field_wadtype,
        field_subindex,field_sublevel0,field_sublevel1,field_sublevel2,field_sublevel3,field_subidr

    }
    local function HandleReceiverReport(tvb, i, tree)
        local rr = {}

        tree:add(field_rr_fLost, tvb(i, 1))
        table.insert(rr, "fLost="..tvb(i, 1):uint())
        i = i + 1

        tree:add(field_rr_cLost, tvb(i, 3))
        --table.insert(rr, "cLost="..tvb(i, 3):uint())
        i = i + 3

        tree:add(field_rr_eHSeq, tvb(i, 4))
        --table.insert(rr, "eHSeq="..tvb(i, 4):uint())
        i = i + 4

        tree:add(field_rr_jiter, tvb(i, 4))
        table.insert(rr, "jiter="..tvb(i, 4):uint())
        i = i + 4

        tree:add(field_rr_lstSR, tvb(i, 4))
        --table.insert(rr, "lstSR="..tvb(i, 4):uint())
        i = i + 4

        tree:add(field_rr_dSLSR, tvb(i, 4))
        --table.insert(rr, "dSLSR="..tvb(i, 4):uint())
        i = i + 4
        return table.concat(rr, ",")
    end
    local function HandleSenderReceiverReport(tvb, i, size, tree)
        if size<12 then return "" end

        local sr = {}
        local countAndR = tvb(i, 4):uint()
        local hasRR = bit32.btest(countAndR, 0x80000000)

        tree:add(field_sr_paket, tvb(i, 4))
        --table.insert(sr, "paket="..bit32.band(countAndR, 0x7fffffff))
        i = i + 4

        tree:add(field_sr_bytes, tvb(i, 4))
        --table.insert(sr, "bytes="..tvb(i,4):uint())
        i = i + 4

        tree:add(field_sr_NTPms, tvb(i, 4))
        --table.insert(sr, "NTPms="..tvb(i,4):uint())
        i = i + 4

        sr = table.concat(sr, ",")
        if hasRR and size>=32 then sr = sr .. ';'..HandleReceiverReport(tvb, i, tree) end
        return sr
    end
    local function HandleWAD(tvb, i, size, tree)
        tree:add(field_wadtype, tvb(i, 2))
        local appType = tvb(i, 2):uint()
        i = i+ 2
        local pktIndx = tvb(i, 2):uint()
        i = i+ 2
        local str = string.format("%x:%x", appType,pktIndx)
        if appType == 1 or appType == 2 then --SvcLevelRequest: video, screen
            local name = (appType == 1 and "video" or "scren")
            tree:add(field_subindex, tvb(i,2))
            local idx = tvb(i,2):uint()
            i = i + 2
            tree:add(field_sublevel0, tvb(i,1))
            tree:add(field_sublevel1, tvb(i,1))
            local level01 = tvb(i,1):uint()
            i = i + 1
            tree:add(field_sublevel2, tvb(i,1))
            tree:add(field_sublevel3, tvb(i,1))
            local level23 = tvb(i,1):uint()
            i = i + 1
            tree:add(field_subidr, tvb(i,1))
            local flag=tvb(i,1):uint()
            str = str .. string.format("|%s[%x:%02x%02x:%x]", name, idx,level01,level23,flag)
        elseif appType == 3 then -- kWADVideoCapture
            local fps = tvb(i, 1):uint()
            str = str .. string.format("|vcfps[%d]", fps)
        elseif appType == 4 then -- kWADAudio
            local audio = tvb(i, 1):uint()
            str = str .. string.format("|audio[%d]", audio)
        end
        return str
    end
    local function JMCP_dissector(tvb, pinfo, root)
        local i ,len = 0, tvb:len()
        local tree = root:add(proto_jmcp, tvb(0))
        local codes, str={}
        while i < len do
            local pt = bit32.band(tvb(i, 1):uint(), 0xff)
            local size = bit32.band(tvb(i+1, 1):uint(), 0xff)
            local csize = 1
            if size >= 252 then
                size = bit32.band(tvb(i+1, 2):uint(), 0x3ff)
                csize = 2
            end
            local stree = tree:add(vals_ctypes[pt], tvb(i, csize+size))
            stree:add(field_code, tvb(i, 1))
            stree:add(field_csize, tvb(i+1, csize))
            i = i + 1 + csize

            if pt == 1 then
                str = string.format("Sr(%s)", HandleSenderReceiverReport(tvb, i, size, stree))
            elseif pt == 4 then
                stree:add(field_tmmbr, tvb(i, 4))
                str = string.format("Tmmbr(%d)", tvb(i, 4):uint()/1000)
            elseif pt == 7 then
                str = string.format("WAD(%s)", HandleWAD(tvb, i, size, stree))
            elseif pt == 8 then
                str = string.format("AWAD(%x:%x)", tvb(i, 2):uint(), tvb(i+2, 2):uint())
            else
                str = vals_ctypes[pt]
                stree:add(tvb(i, size), str)
            end
            table.insert(codes, str)
            i = i + size
        end
        pinfo.cols.protocol = 'JMCP'
        pinfo.cols.info = table.concat(codes, ';')
        return true
    end

    function proto_jmcp.dissector(tvb, pinfo, root)
        if not JMCP_dissector(tvb, pinfo, root) then
            distor_dat:call(tvb, pinfo, root)
        end
    end
    udp_encap_table:add(0, proto_jmcp)

end
local distor_jmcp = Dissector.get(JMCP_NAME)
--jusmeeting protocal
do
    local vals_types= {[0] = "Generic", "Audio", "Video", "Screen", "Data", "JMCP", "Detect"}
    local vals_red={[0]="", [1]="Duplicate", [2]="Nack"}
    local proto_jmp = Proto(JMP_NAME, "JusMeeting Protocal")
    local field_index = ProtoField.uint16(JMP_NAME..".index","INDEX",base.HEX)
    local field_temporal = ProtoField.uint8(JMP_NAME..".temporal","TEMPORAL",base.DEC, nil, 0xf0)
    local field_type = ProtoField.uint8(JMP_NAME..".type","TYPE",base.DEC,vals_types, 0xf)
    local field_audfec = ProtoField.uint8(JMP_NAME..".audfec","AUDIO-FEC",base.DEC,vals_bool,0x80)
    local field_volume = ProtoField.uint8(JMP_NAME..".volume","VOLUME",base.DEC, nil,0x7f)
    local field_keyframe = ProtoField.uint8(JMP_NAME..".keyframe","KEY-FRAME",base.DEC, vals_bool,0x40)
    local field_svc= ProtoField.uint8(JMP_NAME..".svc","SVC",base.DEC, nil,0x30)
    local field_spatial= ProtoField.uint8(JMP_NAME..".spatial","SPATIAL",base.DEC, nil,0xc)
    local field_timestamp = ProtoField.uint32(JMP_NAME..".timestamp","TIMESTAMP",base.HEX)
    local field_sequence = ProtoField.uint16(JMP_NAME..".sequence","SEQUENCE",base.HEX)
    local field_compound = ProtoField.uint8(JMP_NAME..".compound","COMPOUND JMCP",base.DEC, vals_bool, 0x80)
    local field_redundant = ProtoField.uint8(JMP_NAME..".redundant","REDUNDANT",base.DEC, vals_red, 0x60)
    local field_payloadlen = ProtoField.uint16(JMP_NAME..".length","LENGTH",base.DEC, nil,0x7fff)

    proto_jmp.fields = {
        field_index, field_type,
        field_audfec, field_volume,
        field_temporal, field_keyframe, field_svc, field_spatial,
        field_timestamp, field_sequence, field_compound, field_redundant, field_payloadlen
    }
    
    local function JMP_dissector(tvb, pinfo, root)
        if tvb:len() < JMCP_SIZE then return false end
        local jmptype = bit32.band(tvb(2,1):uint(),0xf)
        if jmptype > 6 then return false end
        if jmptype ~= 5 and tvb:len() < JMP_SIZE then return false end

        local tree = root:add(proto_jmp, tvb(0, jmptype ~= 5 and JMP_SIZE or JMCP_SIZE))
        tree:add(field_index, tvb(0,2))
        tree:add(field_type, tvb(2,1))
        if jmptype == 5 then
            distor_jmcp:call(tvb(3):tvb(), pinfo, root)
            return true 
        elseif jmptype == 1 then
            tree:add(field_audfec, tvb(3,1))
            tree:add(field_volume, tvb(3,1))
        elseif jmptype == 2 or jmptype == 3 then
            tree:add(field_temporal, tvb(2,1))
            tree:add(field_keyframe, tvb(3,1))
            tree:add(field_svc, tvb(3,1))
            tree:add(field_spatial, tvb(3,1))
        end
        tree:add(field_timestamp, tvb(4,4))
        tree:add(field_sequence, tvb(8,2))
        tree:add(field_compound, tvb(10,1))
        tree:add(field_redundant, tvb(10,1))
        tree:add(field_payloadlen, tvb(10,2))
        distor_rtp:call(tvb(12):tvb(), pinfo, root)

        local info = pinfo.cols.info
        local red = bit32.rshift(tvb(10,1):uint(), 5)
        if red ~= 0  then
            info = string.format("%s:Seq=0x%X;",vals_red[red], tvb(8,2):uint())
        else
            info = string.format("%s,Seq=0x%X;",vals_types[jmptype], tvb(8,2):uint())..tostring(info)
        end
        pinfo.cols.info = info
        pinfo.cols.protocol = 'JMP'
        return true
    end

    function proto_jmp.dissector(tvb, pinfo, root)
        if not JMP_dissector(tvb, pinfo, root) then
            distor_dat:call(tvb, pinfo, root)
        end
    end
    udp_encap_table:add(0, proto_jmp)
end

local distor_jmp = Dissector.get(JMP_NAME)
--olive transport protocal
do
    local proto_jmp_olive = Proto(JMP_NAME..".olive","JusMeeting Protocal of Olive")
    local field_olive = ProtoField.uint32(JMP_NAME..".olive.index","index", base.HEX)
    proto_jmp_olive.fields = {field_olive}
    local function OLIVE_dissector(tvb, pinfo, root)
        local HEAD = 4
        if tvb:len() < HEAD+JMCP_SIZE then return false end
        local tree = root:add(proto_jmp_olive, tvb(0,HEAD))
        tree:add(field_olive, tvb(0,HEAD))
        distor_jmp:call(tvb(HEAD):tvb(), pinfo, root)
        return true
    end

    function proto_jmp_olive.dissector(tvb, pinfo, root)
        if not OLIVE_dissector(tvb, pinfo, root) then
            distor_dat:call(tvb, pinfo, root)
        end
    end
    udp_encap_table:add(0, proto_jmp_olive)
end

--justalk cloud transport protocal
do
    local proto_jmp_cloud = Proto(JMP_NAME..".cloud","JusMeeting Protocal of Cloud")
    local field_cloud = ProtoField.bytes(JMP_NAME..".cloud.unknown","unknown")
    proto_jmp_cloud.fields = {field_cloud}
    local function CLOUD_dissector(tvb, pinfo, root)
        local HEAD = 5
        if tvb:len() < HEAD+JMCP_SIZE then return false end
        local tree = root:add(proto_jmp_cloud, tvb(0,HEAD))
        tree:add(field_cloud, tvb(0,HEAD))
        distor_jmp:call(tvb(HEAD):tvb(), pinfo, root)
        return true
    end
    function proto_jmp_cloud.dissector(tvb, pinfo, root)
        if not CLOUD_dissector(tvb, pinfo, root) then
            distor_dat:call(tvb, pinfo, root)
        end
    end
    udp_encap_table:add(0, proto_jmp_cloud)
end
