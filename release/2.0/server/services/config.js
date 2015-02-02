var fs = require('fs');
var config = {
  db: null,
  log: null,
  config: {},
  assert: function(error) {
    if (error) {
      config.log.getLogger('config').error(error);
      throw '[config] ' + error;
    }
  },
  init: function(conf) {
    var log = config.log = require('../log');
    log.setLogger('config', conf.log_path + '/config.log');
    config.db = require('../service').getService('mysql');
  },
  uninit: function() {
  },
  put_createInterfaceConfig: function(req, res) {
    var db = config.db;
    try {
      var cfg = db.query('select http_method,analysts_cache FROM `base_info`');
      var cfg_inter = db.query('select inter1.name,inp.*,outp.out_num,inter2.name name2 from `interface` inter1 inner join `inpackage` inp inner join `interface` inter2 inner join `outpackage` outp on inter1.inter_id=inp.inter_id and inter2.inter_id=inp.inter_id2 and inter2.inter_id=outp.inter_id');
      if (!cfg || !cfg[0]) {
        throw '主配置暂未设置，请先配置！';
      }
      if (!cfg_inter || !cfg_inter[0]) {
        throw '发包口或者收包口暂未设置，请先配置！';
      }
      cfg = cfg[0];

      /**
      *配置全局Head
      */
      var cpuCount = require('os').cpus().length;
      var analysts_cache = 16;
      var http_spoofers = Math.round(3 * cpuCount / 4);
      var dns_spoofers = Math.round(3 * cpuCount / 4);
      if (cfg.analysts_cache == 2) {
        analysts_cache = 64;
        http_spoofers = cpuCount;
        dns_spoofers = cpuCount;
      }

      var cfg_head = 'max_dns_pkt_size 2048' + '\r\n' +
      'max_http_pkt_size 8192' + '\r\n' +
      'max_send_size 304K' + '\r\n' +
      'max_log_len 512' + '\r\n' +
      'pf_watermark 1' + '\r\n' +
      'dns_dmn_data_path dns_data\r\n' +
      'http_dmn_cfg_file http.conf\r\n' +
      'http_dmn_data_path http_data\r\n' +
      'analysts_cache ' + analysts_cache + '\r\n'
      'log_file /NoGFW/log/spoofer_log.log\r\n' +
      'statis_file /NoGFW/log/spoofer_statis.log\r\n';

      /**
      *配置http_method
      */
      var cfg_http_method = '<spo_hp_method>\r\n';
      var http = [
      'OPTIONS',
      'HEAD',
      'GET',
      'POST',
      'PUT',
      'DELETE',
      'TRACE',
      'CONNECT',
      'PATCH'
      ];
      for (var i = 0; i < 9; i++) {
        if (cfg.http_method[i] == i +1) {
          cfg_http_method += '\thttp_method ' + http[i] + '\r\n';
        }
      }
      cfg_http_method += '</spo_hp_method>\r\n\r\n';

      /**
      *配置sinffers和analysts
      */
      var seed = Math.ceil(Math.random()*9) + 123456;
      var cfg_sniffers = '';
      var cfg_analysts = '';
      var analy_msgid_arr = [];
      var http_msgid_arr = [];  //存放http_msgid的数组
      var dns_msgid_arr = [];  //存放dns_msgid的数组
      var http_num = [];  //存放当前http中进程个数的数组
      var dns_num = [];  //存放当前dns中进程个数的数组
      var tcp = [];  //存放既有tcp又有udp时tcp当前的msgid的位置的数组
      var udp = [];  //存放既有tcp又有udp时udp当前的msgid的位置的数组
      var tcp_inter = [];  //存放属于tcp的cfg_inter的下标的数组
      var udp_inter = [];  //存放属于udp的cfg_inter的下标的数组
      var tcp_udp_inter = []; //存放既有tcp又有udp时cfg_inter的下标的数组

      for (var i = 0; i < cfg_inter.length; i++) {
        var analy_msgid = '';
        var http_msgid = '';
        var dns_msgid = '';
        var snd_msgid = '';
        var filter = '\r\n';
        if (cfg_inter[i].type1 == '10') {
          filter += '\tfilter tcp\r\n';
          tcp_inter.push(i);
          http_num.push(cfg_inter[i].out_num);
          for (var j = 0; j < http_spoofers; j++) {
            http_msgid_arr.push(seed);
            http_msgid += '\thttp_msgid ' + seed++ + '\r\n';
          }
          for (var j = 0; j < http_spoofers; j++) {
            analy_msgid += '\tanaly_msgid ' + seed++ + '\r\n';
          }
        } else if (cfg_inter[i].type1 == '02') {
          filter += '\tfilter udp\r\n';
          udp_inter.push(i);
          dns_num.push(cfg_inter[i].out_num);
          for (var j = 0; j < dns_spoofers; j++) {
            dns_msgid_arr.push(seed);
            dns_msgid += '\tdns_msgid ' + seed++ + '\r\n';
          }
        } else if (cfg_inter[i].type1 == '12') {
          filter += '\tfilter tcp or udp\r\n';
          tcp_inter.push(i);
          tcp_udp_inter.push(i);
          tcp.push(http_num.length);
          udp.push(dns_num.length);
          http_num.push(cfg_inter[i].out_num);
          dns_num.push(cfg_inter[i].out_num);
          for (var j = 0; j < http_spoofers; j++) {
            http_msgid_arr.push(seed);
            http_msgid += '\thttp_msgid ' + seed++ + '\r\n';
          }
          for (var j = 0; j < http_spoofers; j++) {
            analy_msgid += '\tanaly_msgid ' + seed++ + '\r\n';
          }
          for (var j = 0; j < dns_spoofers; j++) {
            dns_msgid_arr.push(seed);
            dns_msgid += '\tdns_msgid ' + seed++ + '\r\n';
          }
        }
        var useing_lib = '\t';
        if (cfg_inter[i].type2 == 1) {
          useing_lib += 'useing_lib pcap\r\n';
        } else if (cfg_inter[i].type2 == 2) {
          if (cfg_inter[i].type3 == '10') {
            useing_lib += 'useing_lib pf\r\n\tdata_direc rx\r\n';
          } else if (cfg_inter[i].type3 == '02') {
            useing_lib += 'useing_lib pf\r\n\tdata_direc tx\r\n';
          }
        }
        cfg_analysts += '<spo_analysts>\r\n\tdev ' +  cfg_inter[i].name + '\r\n' + http_msgid + '</spo_analysts>\r\n\r\n';
        cfg_sniffers += '<spo_sniffer>\r\n\tdev_r ' + cfg_inter[i].name + filter + useing_lib + analy_msgid + dns_msgid + '\tproc_type sniffer\r\n\tcpuid 1\r\n</spo_sniffer>\r\n\r\n';
      }

      /**
      *配置http_spoofers
      */
      var http_snd_msgid_arr = [];
      var tcp_arr = [];
      var http_spoofer = '';
      for (var i = 0; i < http_num.length; i++) {
        var http_snd_msgid = '';
        for (var j = 0; j < http_num[i]; j++) {
          for (var k = 0; k < tcp.length; k++){
            if (i == tcp[k]) {
              tcp_arr.push(http_snd_msgid_arr.length);
              break;
            }
          }
          http_snd_msgid_arr.push(seed);
          http_snd_msgid += '\r\n\tsnd_msgid ' + seed++ ;
        }
        for (var k = 0; k < http_spoofers; k++) {
          http_spoofer += '<spo_http_spoofer>\r\n\trcv_msgid ' + http_msgid_arr[http_spoofers * i +k] + http_snd_msgid + '\r\n\tproc_type http_spoofer\r\n\tcpuid 3\r\n</spo_spoofer>\r\n\r\n';
        }
      }

      /**
      *配置dns_spoofers
      */
      var dns_snd_msgid_arr = [];
      var udp_arr = [];
      var dns_spoofer = '';
      for (var i = 0; i < dns_num.length; i++) {
        var dns_snd_msgid = '';
        var type = false;
        for(var j = 0; j< dns_num[i]; j++) {
          var flag = false;
          for (var k = 0; k < udp.length; k++){
            if (i == udp[k]) {
              udp_arr.push(dns_snd_msgid_arr.length);
              flag = true;
              type = true;
              break;
            }
          }
          if (!flag) {
            dns_snd_msgid_arr.push(seed);
            dns_snd_msgid += '\r\n\tsnd_msgid ' + seed++ ;
          }
        }
        if (!type) {
          for (var k = 0; k < dns_spoofers; k++) {
            dns_spoofer += '<spo_dns_spoofer>\r\n\trcv_msgid ' + dns_msgid_arr[dns_spoofers * i +k] + dns_snd_msgid + '\r\n\tproc_type dns_spoofer\r\n\tcpuid 3\r\n</spo_spoofer>\r\n\r\n';
          }
        }
      }
      for (var i = 0; i < tcp.length; i++) {
        var dns_snd_msgid = '';
        for (var j = 0; j < http_num[tcp[i]]; j++) {
          dns_snd_msgid += '\r\n\tsnd_msgid ' + http_snd_msgid_arr[tcp_arr[i + j]];
        }
        for (var k = 0; k < dns_spoofers; k++) {
          dns_spoofer += '<spo_dns_spoofer>\r\n\trcv_msgid ' + dns_msgid_arr[udp_arr[i + k]] + dns_snd_msgid + '\r\n\tproc_type dns_spoofer\r\n\tcpuid 3\r\n</spo_spoofer>\r\n\r\n';
        }
      }
      /**
      *配置spo_sender
      */
      var spo_sender = '';
      var location = 0;
      for (var i = 0; i < tcp_inter.length; i++) {
        for (var j = 0; j < http_num[i]; j++) {
          spo_sender += '<spo_sender>\r\n\tdev_s ' + cfg_inter[tcp_inter[i]].name2 + '\r\n\trcv_msgid ' + http_snd_msgid_arr[location] + '\r\n\tcpuid 3\r\n\tproc_type sender\r\n</spo_sender>\r\n\r\n';
          location++;
        }
      }
      var location = 0;
      for (var i = 0; i < udp_inter.length; i++) {
        for (var j = 0; j < dns_num[i]; j++) {
          spo_sender += '<spo_sender>\r\n\tdev_s ' + cfg_inter[udp_inter[i]].name2 + '\r\n\trcv_msgid ' + dns_snd_msgid_arr[location] + '\r\n\tcpuid 3\r\n\tproc_type sender\r\n</spo_sender>\r\n\r\n';
          location++;
        }
      }
      var bin_path = '/NoGFW/bin';
      var config_path = '/NoGFW/bin/config';
      if (!fs.existsSync(bin_path)) {
        fs.mkdirSync(bin_path);
      }
      if (fs.existsSync(config_path)) {
        fs.unlinkSync(config_path);
      }
      fs.appendFileSync(config_path, cfg_head + '\r\n\r\n' + cfg_http_method + cfg_analysts + cfg_sniffers + http_spoofer + dns_spoofer + spo_sender);
      res.send({
        success: true,
        msg: '生成config文件成功！'
      });
    } catch (e) {
      res.send({
        success: false,
        msg: e
      });
    }
  },

  put_createHttpDataConfig: function(req, res) {
    var db = config.db;
    var cfg = db.query('SELECT data.*,domain.domain FROM `http_data` data inner join `http_domain` domain inner join `http_rule` rule on rule.do_id=domain.do_id and rule.data_num=data.data_num');
    try {
      if (!cfg || !cfg[0]) {
        throw 'http_domain或http_data暂未配置，请先配置！';
      }
      var bin_path = './NoGFW/bin';
      if (!fs.existsSync(bin_path)) {
        fs.mkdirSync(bin_path);
      }
      var http_path = './NoGFW/bin/http_data';
      var dns_path = './NoGFW/bin/dns_data';
      //存在http_data文件夹，则删除该目录及其子目录和文件
      if (fs.existsSync(http_path)) {
        var files = [];
        files = fs.readdirSync(http_path);
        files.forEach(function(file, index) {
          var curPath = http_path + "/" + file;
          if (fs.statSync(curPath).isDirectory()) {
            deleteFolderRecursive(curPath);
          } else {
            fs.unlinkSync(curPath);
          }
        });
        fs.rmdirSync(http_path);
      }
      //存在dns_data文件夹，则删除该目录及其子目录和文件
      if (fs.existsSync(dns_path)) {
        var files = [];
        files = fs.readdirSync(dns_path);
        files.forEach(function(file, index) {
          var curPath = dns_path + "/" + file;
          if (fs.statSync(curPath).isDirectory()) {
            deleteFolderRecursive(curPath);
          } else {
            fs.unlinkSync(curPath);
          }
        });
        fs.rmdirSync(dns_path);
      }
      fs.mkdirSync(http_path);
      fs.mkdirSync(dns_path);
      for (i = 0; i < cfg.length; i++) {
        var filename = cfg[i].data_num + '@' + cfg[i].domain;
        if (fs.existsSync(http_path + "/" + filename)) {
          fs.unlinkSync(http_path + "/" + filename);
        }
        var tmp_head = cfg[i].head;
        var tmp_body = cfg[i].body;
        if (tmp_head.indexOf("/**/") == -1 && tmp_body.indexOf("/**/") == -1) {
          if (tmp_head.indexOf("$") == -1 && tmp_body.indexOf("$") == -1) {
            var head = tmp_head.split("\r\n");
            head[0] = head[0] + "\r\n/**/";
            var temp = "";
            for (var k = 0; k < head.length - 1; k++) {
              temp  += head[k] + "\r\n";
            }
            temp  += head[k];
            tmp_head = temp;
          } else if (tmp_body.indexOf("$") > -1) {
            var body = tmp_body.split("\r\n");
            var temp = "";
            for (var k = body.length - 1; k >= 0 ; k--) {
              if (body[k].indexOf("$") > -1) {
                body[k] += "\r\n/**/";
                break;
              }
            }
            for(var j = 0; j < body.length; j++) {
              temp += body[j] + "\r\n";
            }
            tmp_body = temp;
          } else if (tmp_head.indexOf("$") > -1 && tmp_body.indexOf("$") == -1) {
            var temp = "/**/\r\n" + tmp_body;
            tmp_body = temp;
          }
         }
        fs.appendFileSync(http_path + "/" + filename, tmp_head + '\r\n\r\n' + tmp_body);
      }
      res.send({
        success: true,
        msg: '生成data文件成功！'
      });
    } catch (e) {
      res.send({
        success: false,
        msg: e
      });
    }
  },
  put_createHttpRuleConfig: function(req, res) {
    var db = config.db;
    var cfg = db.query('SELECT do.domain,rule.* FROM `http_domain` do inner join `http_rule` rule on do.do_id=rule.do_id order by do.domain,rule.orders');
    try {
      if (!cfg || !cfg[0]) {
        throw 'http_domain或http_rule暂未配置，请先配置！';
      }
      var rule = '';
      for (var i = 0; i < cfg.length; i++) {
        if ( i == 0) {
          rule += '<spo_domain ' + cfg[i].domain + '>';
        } else if ( i > 0 ){
          if (cfg[i].domain != cfg[i - 1].domain) {
            rule += '\r\n</spo_domain>\r\n\r\n<spo_domain ' + cfg[i].domain + '>';
          }
        }
        rule += '\r\n\turl: ' + cfg[i].url + ',,,cookies: ' + cfg[i].cookies + ',,,referer: ' + cfg[i].referer + ',,,@' + cfg[i].data_num;
      }
      rule += '\r\n</spo_domain>';

      var bin_path = '/NoGFW/bin';
      var http_conf_path = '/NoGFW/bin/http.conf';
      if (!fs.existsSync(bin_path)) {
        fs.mkdirSync(bin_path);
      }
      if (fs.existsSync(http_conf_path)) {
        fs.unlinkSync(http_conf_path);
      }
      fs.writeFileSync(http_conf_path, rule);
      res.send({
        success: true,
        msg: '生成rule文件成功！'
      });
    } catch (e) {
      res.send({
        success: false,
        msg: e
      });
    }
  }
};

module.exports = config;
