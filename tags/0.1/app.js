var  config = require('./config');
//加载业务
var httpServices = config.service.httpServices;
var dnsServices = config.service.dnsServices;
var businesses = [];
var httpFunctions = {
  get301Data: function(location) {
    var bf =  new Buffer([
      'HTTP/1.1 301 Moved Permanently',
      'Server: GFW/5.1.8 (Kylin)',
      'Content-Type: text/html',
      'Content-Length: 13',
      'Connection: keep-alive',
      'Location: ' + location + '\r\n',
      '<html></html>'
    ].join('\r\n'));
    return {
      content: bf,
      length: bf.length,
    };
  },
  get200Data: function(content, contentType) {
    var bf =  new Buffer([
      'HTTP/1.1 200',
      'Server: GFW/5.1.8 (Kylin)',
      'Content-Type: ' + contentType,
      'Content-Length: ' + content.length,
      'Connection: keep-alive\r\n',
       content,
    ].join('\r\n'));
    return {
      content: bf,
      length: bf.length,
    };
  }
};
var dnsFunctions = {};
//加载http服务
for(var httpService in httpServices) {
  businesses['http_' + httpService ] = require('./scripts/http_' + httpServices[httpService])(httpFunctions);
}
//加载dns服务
for(var dnsService in dnsServices) {
  businesses['dns_' + dnsService ] = require('./scripts/dns_' + dnsServices[dnsService])(dnsFunctions);
}
var cluster = require('cluster');
var pcap = require('pcap');
var events =  require("events");
var WorkerGroup = [];
if (cluster.isMaster) {
  //开启收包端口的监听
  config.cases.forEach(function(cases) {
    pcap.createSession(cases.collect, cases.rule).on('packet', function (raw_packet) {
      //随机获取子线程,并将数据传递到子线程中
      worker = WorkerGroup[cases.send][parseInt(Math.random() * WorkerGroup[cases.send].length, 10)];
      worker.listen.emit('data', raw_packet, worker['sender'], new Date().getTime());
    });

    //注册个发包组件
    var sender = require('./node_modules/sender/build/Release/sender');
    dev = new Buffer(cases.send);
    sender.sendInit({
      dev: dev,
      length : dev.length,
    });

    //根据配置创建并登记每个发包端口的子线程
    WorkerGroup[cases.send] = [];
    for(i = 0 ; i < cases.thread; i++) {
      worker = cluster.fork();
      worker['listen'] = new events.EventEmitter().on('data', function(data, sender, start) {
        //子线程获取包后执行的分析和发包动作
        analysis(data, sender, start);
      });
      worker['sender'] = sender;
      WorkerGroup[cases.send].push(worker);
    }
  });
}

var statistic = {
  'http_boss.qzone.qq.com': 1,
  'http_wp.mail.qq.com': 1,
  'http_toruk.tanx.com': 1,
  'http_ecpm.tanx.com': 1,
  'http_apollon.t.taobao.com': 1,
  'http_tmatch.simba.taobao.com': 1,
  'http_pos.baidu.com': 1,
  'http_item.yhd.com': 1,
  'http_suggestion.baidu.com': 1,
  'http_cb.baidu.com': 1,
  'http_open.show.qq.com': 1,
  'http_www.baidu.com': 1,
};

function analysis(raw_packet, sender, start) {
  var packet = pcap.decode.packet(raw_packet);
  //分析http
  if(packet.link.ip.tcp && packet.link.ip.tcp.data) {
    var data =  packet.link.ip.tcp.data.toString(), http = {};
    if (data.match(/HTTP/)) {
      var arr = data.match(/^([A-Z]+)\s([^\s]+)\sHTTP\/(\d.\d)/);
      var host = data.match(/Host\:\s*([^\n\s\r]+)/i);
      if (arr) {
        http.method = arr[1];
        http.path = arr[2];
        //TODO host匹配暂时有问题, app端请求解析出错
        if (host) {
          //HTTP处理
          http.host = host[1];
          BodaData = getBodaoHttp(raw_packet);
          BodaData.data = httpFunctions.get200Data('<html>hello word </html>','text/html');
          if (statistic['http_' + http.host]) {
            console.log(http.host + ' , ' + BodaData.toString() + ' , ' + (new Date().getTime() - start) + ' , ' + http.path);
          }
          return;
          // business = businesses['http_' + http.host];
          // if (business) {
          //   httpData = business.data(http);
          //   if (httpData) {
          //     BodaData = getBodaoHttp(raw_packet);
          //     BodaData.httpData = httpData;
          //     sender.send(BodaData);
          //   }
          // }
        }
      }
    }
  }

  //分析dns
  dns = getDns(packet);
  if (dns) {
    console.log(dns);
    return;
  }
}

function getDns(packet) {
  if (packet) {
    if (!packet.link.ip.udp || !packet.link.ip.udp.dns) {
      return;
    }
    var ip = packet.link.ip;
    var dns = packet.link.ip.udp.dns;
    if (dns.header.qr === 0 && dns.question[0].qtype === 'A') {
      return {
          'id': dns.header.id,
          'qdcount': dns.header.qdcount,
          'dhost': packet.link.dhost,
          'shost': packet.link.shost,
          'qname': dns.question[0].qname,
          'sport': ip.udp.sport,
          'dport': ip.udp.dport,
          'packet_size': '',
      };
    }
  }
}
function  getBodaoHttp(raw_packet) {
    var bodao = {
        ei: {},
        ip: {},
        tcp: {},
        date: null,
    };
    bodao.ei.destination = raw_packet.slice(0,6);
    bodao.ei.source = raw_packet.slice(6,12);
    bodao.ei.type = raw_packet.slice(12,14);
    if (bodao.ei.type.toString('hex') == '8100') {
      bodao.ei.vlan_id = raw_packet.slice(14,16);
      //如果是vlan包，减掉vlan包的长度
      raw_packet = raw_packet.slice(4);
    }
    bodao.ip.version = bodao.ip.header_length = raw_packet.slice(14,15);
    bodao.ip.differentiaed_services_field = raw_packet.slice(15,16);
    bodao.ip.total_length = raw_packet.slice(16,18);
    bodao.ip.identification = raw_packet.slice(18,20);
    bodao.ip.flags = raw_packet.slice(20,21);
    bodao.ip.flagment_offset = raw_packet.slice(20,22);
    bodao.ip.time_to_live = raw_packet.slice(22,23);
    bodao.ip.protocol = raw_packet.slice(23,24);
    bodao.ip.header_checksum = raw_packet.slice(24,26);
    bodao.ip.source = raw_packet.slice(26,30);
    bodao.ip.destination = raw_packet.slice(30,34);
    bodao.tcp.source_port = raw_packet.slice(34,36);
    bodao.tcp.destination_port = raw_packet.slice(36,38);
    bodao.tcp.sequence_number = raw_packet.slice(38,42);
    bodao.tcp.ac_knowledgment_number = raw_packet.slice(42,46);
    bodao.tcp.header_length = raw_packet.slice(46,47);
    bodao.tcp.flags = raw_packet.slice(47,48);
    bodao.tcp.window_size_value = raw_packet.slice(48,50);
    bodao.tcp.checksum = raw_packet.slice(50,52);
    var oplen = 34 +  (bodao.tcp.header_length.readUInt8(0)>>2);
    bodao.tcp.options = raw_packet.slice(54 ,oplen );
    var datelen = bodao.ip.total_length.readUInt16BE(0) + 14;
    bodao.date = raw_packet.slice(oplen, datelen );
    return bodao;
}
process.on('uncaughtException', function(error) {
  console.log(error);
});
