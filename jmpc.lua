local _QOS={}

--Packets:2558 RTT:5 Jitter:5 Lost:0 LostRatio:0 BitRate/BWE:33/1213
local function SendStatistic(value)
    _QOS.BitRate = _QOS.BitRate or {}
    for k, v in string.gmatch(value, "([%w/]+):([%w/]+)") do
        if string.find(k,'/') then
            local k0, k1 = string.match(k, "(%w*)/(%w*)");
            local v0, v1 = string.match(v, "(%w*)/(%w*)");
            _QOS[k0] = _QOS[k0] or {}
            _QOS[k1] = _QOS[k1] or {}
            table.insert(_QOS[k0], v0);
            table.insert(_QOS[k1], v1);
        else
            _QOS[k] = _QOS[k] or {}
            table.insert(_QOS[k], v);
        end
    end
end

io.input(arg[1])
io.output("index.html")
for line in io.lines() do
    local id, info, value = string.match(line, ".- JMP:  INFO: STATS: (%w*) (%w*): (.*)")
    if id and info and value then
        if id == "rikroom" and info == "SendStatistic" then SendStatistic(value) end
    end
end
_QOS.Packets=nil
_QOS.BWE=nil

io.write([[
<html>
 <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>Flot Examples</title>
    <script src="http://ajax.googleapis.com/ajax/libs/jquery/1.8.0/jquery.min.js"></script>
    <script src="http://people.iola.dk/olau/flot/jquery.flot.js"></script>
 </head>
    <body>
    <h1>Flot Examples</h1>

    <div id="placeholder" style="width:1280px;height:720px;"></div>

    <p>Simple example. You don't need to specify much to get an
       attractive look. Put in a placeholder, make sure you set its
       dimensions (otherwise the plot library will barf) and call the
       plot function with the data. The axes are automatically
       scaled.</p>

<script type="text/javascript">
$(function () {
]])

local _PLOT={}
for k,v in pairs(_QOS) do
    local d={}
    for i,s in pairs(v) do
        table.insert(d,"["..(i-1)..","..s.."]")
    end
    _PLOT[k] = d;
end

for k,v in pairs(_PLOT) do
    io.write("var ", k, "=[", table.concat(v, ','), "];\n")
end

io.write([[$.plot($("#placeholder"),[]], '\n');

for k,v in pairs(_PLOT) do
    io.write('{ label: "', k, '", data: ', k, "},\n")
end

io.write([[],{
yaxis:{
    min: -100,
},
});}); </script> </body> </html>]])

