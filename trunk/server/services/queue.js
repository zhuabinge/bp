var queue = {
  redisClient: null,
  db: null,
  log: null,
  timer: null,
  sysInfos: [],
  assert: function(error) {
    if (error) {
      queue.log.getLogger('queue').error(error);
      throw '[queue] ' + error;
    }
  },
  load: function() {
    if (queue.timer) {
      clearTimeout(queue.timer);
    }
    var sysInfos = queue.sysInfos;
    queue.sysInfos =  [];
    var length =  sysInfos.length,
    infoCount = {
      count: length,
      cpuSum: 0,
      memSum: 0,
      netPortSum: {},
    },
    cpu = 0, mem = 0;
    for (var i = length - 1; i >= 0; i--) {
      infoCount.cpuSum += sysInfos[i]['CPU'];
      infoCount.memSum += sysInfos[i]['Mem'];
      var netPorts = sysInfos[i]['netPort'];
      for (var j = netPorts.length - 1; j >= 0; j--) {
        var netPort = netPorts[j];
        if (!infoCount.netPortSum[netPort[0]]) {
          infoCount.netPortSum[netPort[0]] = {
            upSum: 0,
            downSum: 0,
          };
        }
        var netPortSum = infoCount.netPortSum[netPort[0]];
        netPortSum.upSum += netPort[1];
        netPortSum.downSum += netPort[2];
      }
    }

    queue.tosql(infoCount);
    queue.timer = setTimeout(queue.load, 1000 * 10);  // 每 60 秒重新装载
  },
  tosql: function(info) {
    //console.log( info);
    var db = queue.db;
    var date = parseInt(new Date().getTime() / 1000, 10);
    var cpu_mem_data = {
      count: info['count'],
      cpuSum: info['cpuSum'],
      memSum: info['memSum'],
    };
    var netport_data = info['netPortSum'];
    var created = parseInt(new Date().getTime() / 1000, 10);
    var sql_1 = db.format('replace into `cpu_mem` values ( FROM_UNIXTIME( ?, "%d%H%i"), ?, ? )', [date, JSON.stringify(cpu_mem_data),  created]);
    cfg_1 = db.execute(sql_1);
    var sql_2 = db.format('replace into `netport` values ( FROM_UNIXTIME( ?, "%d%H%i"), ?, ? )', [date, JSON.stringify(netport_data),  created]);
    cfg_2 = db.execute(sql_2);
  },
  init: function(conf) {
    var cache  = queue.redisClient = require('../service').getService('cache');
    var config = cache.config;
    var db = queue.db = require('../service').getService('mysql');
    var log = queue.log = require('../log');
    log.setLogger('queue', conf.log_path + '/queue.log');

    console.log();
    if (process.env.worker_id && process.env.worker_id == 0) {
      var queueClient =  cache.redis.createClient(
        config.port || 6379,
        config.hostname || '127.0.0.1'
        );
      queueClient.on('error', queue.assert);
      queueClient.on('message', function(channel, message) {
        queue[channel](message);
      });
      queueClient.on('subscribe', function(channel, count) {
        console.log('QUEUE 进程已启动 [' + process.pid + '], 队列: ' + channel + ', 订阅: ' + count);
      });
      conf.forEach(function (queueName) {
        queueClient.subscribe(queueName);
      });;
    }
    queue.db = require('../service').getService('mysql');
    queue.load();
  },
  uninit: function() {
  },
  sysinfoUpdate: function(message) {
    message = message.split('|');
    var sysInfo = {
      CPU: '',
      Mem: '',
      netPort: [],
      time: parseInt(new Date().getTime() / 1000 , 10) ,
    };
    for (var i = message.length - 1; i >= 0; i--) {
      var info = message[i].split(':');
      if (info[2]) {
        sysInfo.netPort.push([info[0], parseFloat(info[1]), parseFloat(info[2])]);
      } else {
        sysInfo[info[0]] =  parseFloat(info[1]);
      }
    }
    queue.redisClient.set('sysinfoUpdate/' + sysInfo.time, JSON.stringify(sysInfo), 60 * 5);
    queue.sysInfos.push(sysInfo);
  },
  put_CPU_MemData: function(req, res) {
    queue.redisClient.keys('sysinfoUpdate/*', function(result) {
      var orders = [];
      result.forEach(function (key) {
        orders.push(['get', key]);
      });
      var getData = function(orders, callback) {
          if (orders[0]) {
            queue.redisClient.client.multi(orders).exec(function(error, replies) {
              queue.assert(error);
              if (replies) {
                var data = [];
                replies.forEach(function(value) {
                   var json = JSON.parse(value);
                   data.push( {
                      CPU: json['CPU'] ? json['CPU'] : 0,
                      Mem: json['Mem'] ? json['Mem'] : 0,
                      time: json['time'] ? json['time'] : 0,
                    });
                });
                callback(data);
              } else {
                callback();
              }
            });
          } else {
            callback();
          }
      }
     getData(orders, function(data) {
         res.send({
            data: data,
          });
     });
    });
  },
  put_BaseInfoData: function (req, res) {
    queue.redisClient.keys('sysinfoUpdate/*', function(result) {
      var sysdata = [];
      var funcGet = function() {
        var datas = result.shift();
        if (!datas) {
          res.send({
            data: sysdata,
          });
        } else {
          queue.redisClient.get( datas, function (value) {
            if (value) {
              var json = JSON.parse(value);
              //console.log(json);
              temp = {
                netPort: json['netPort'] ? json['netPort'] : 0,
                time: json['time'] ? json['time'] : 0,
              };
              sysdata.push(temp);
              setImmediate(funcGet);
            } else {
              res.send({
                data: null,
              });
            }
          });
        }
      }
      setImmediate(funcGet);
    });
  },
};
module.exports = queue;
