do
 local p_jsm = Proto("jsm","jusmeeting");
 local VALS_BOOL1	= {[0] = "RTP", [1] = "RTCP"}
 local VALS_BOOL2	= {[0] = "JMP", [1] = "contains JMCP"}
 local f_olive = ProtoField.uint32("jsm.olive","OLIVE",base.HEX)
 local f_index = ProtoField.uint16("jsm.index","INDEX",base.DEC)
 local f_priority = ProtoField.uint8("jsm.index","priority",base.DEC, nil, 0xf0)
 local f_type = ProtoField.uint8("jsm.index","TYPE",base.DEC,nil, 0xf)
 local f_level = ProtoField.uint8("jsm.level","LEVEL",base.HEX, nil,0x7f)
 local f_bRtp = ProtoField.uint8("jsm.index","BRTP",base.DEC, VALS_BOOL1, 0x80)
 local f_timestamp = ProtoField.uint32("jsm.timestamp","TIMESTAMP",base.DEC)
 local f_sequence = ProtoField.uint16("jsm.sequence","SEQUENCE",base.DEC)
 local f_bCompound = ProtoField.uint8("jsm.compound","COMPOUND",base.DEC, VALS_BOOL2, 0x80)
 local f_payloadLen = ProtoField.uint16("jsm.length","LENGTH",base.DEC, nil,0x7fff)

 p_jsm.fields = {f_olive, f_index, f_priority, f_type, f_level, f_bRtp, f_timestamp, f_sequence, f_bCompound, f_payloadLen}

 function p_jsm.dissector(buf, pinfo, root)

   local t = root:add(p_jsm, buf(0,16))

   local f = t:add(f_olive, buf(0,4))
   t:add(f_index, buf(4,2))
   t:add(f_priority, buf(6,1))
   t:add(f_type, buf(6,1))
   t:add(f_level, buf(7,1))
   t:add(f_bRtp, buf(7,1))
   t:add(f_timestamp, buf(8,4))
   t:add(f_sequence, buf(12,2))
   t:add(f_bCompound, buf(14,1))
   t:add(f_payloadLen, buf(14,2))
   local eth_dis = Dissector.get("rtp")
   eth_dis:call(buf(16):tvb(), pinfo, root)
 end

 local p_jsm_cloud = Proto("jsm-cloud","jusmeeting-cloud");
 local f_cloud = ProtoField.uint16("cloud.index","index",base.DEC)
 p_jsm_cloud.fields = {f_cloud}
 function p_jsm_cloud.dissector(buf, pinfo, root)

   local t = root:add(p_jsm_cloud, buf(0,1))

   local f = t:add(f_cloud, buf(0,1))
   local eth_dis = Dissector.get("jsm")
   eth_dis:call(buf(1):tvb(), pinfo, root)
 end
 
 local udp_encap_table = DissectorTable.get("udp.port")
 udp_encap_table:add(0, p_jsm)
 udp_encap_table:add(0, p_jsm_cloud)
end