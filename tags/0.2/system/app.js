#!/usr/bin/node
var config = require('./configs/config');
var log4js = require('log4js');
log4js.configure(__dirname + '/' + (config.log_configure || 'configs/log4js.json'), {
  cwd: __dirname
});
var os = require('os');
var loggerApp = log4js.getLogger('app'),
    loggerScripts = log4js.getLogger('script');
var cluster = require('cluster'), isMaster = cluster.isMaster, daemonize = false;
var pagesize = 8192;
if (os.arch() === 'x64') {
  pagesize = 4096;
}
pagesize = 8192;
// 退出函数
var onExit = function() {
  if (isMaster) {
    loggerApp.info('系统进程已终止');
    for (var i in cluster.workers) {
      process.kill(cluster.workers[i].process.pid, 'SIGKILL');
    }
  } else {
    loggerApp.info('监听msgId为 ' + evn.msgId + ' msgType为 ' + evn.msgType + ' 队列的子线程已经终止' );
  }
  setImmediate(function() {
    process.exit(1);
  });
};
process.on('SIGTERM', onExit);
process.on('SIGINT', onExit);
// 错误函数
var onError = function(error) {
  loggerApp.fatal(error);
  //onExit();
};
process.on('uncaughtException', function(error) {
  onError(error);
});

do {
  var argv = process.argv, op = 'start';
  if (argv.length == 3) {
    op = argv[2];
  }
  if (op !== 'start' && op !== 'stop' && op !== 'restart') {
    loggerApp.info('无效的启动参数');
    break;
  }
  daemonize = config.app.daemonize || false;

  if (isMaster) {
    var pid = config.app.pid || __dirname + '/app.pid', removePid = false, fs = require('fs');
    if (op === 'stop' || op === 'restart') {
      if (!fs.existsSync(pid)) {
        loggerApp.info('找不到已启动的系统进程');
        break;
      } else {
        var processPid = parseInt(fs.readFileSync(pid, 'ascii'), 10);
        if (!isNaN(processPid)) {
          process.kill(processPid);
        }
      }
      if (op === 'stop') {
        break;
      } else {
        // 等待 pid 文件删除
        while (fs.existsSync(pid)) {}
      }
    }
    if (fs.existsSync(pid)) {
      loggerApp.info('系统进程已存在');
      break;
    }
    if (daemonize) {
      // 后台运行
      if (process.env.__daemonize === undefined) {
        process.env.__daemonize = true;
        var child = require('child_process').spawn(argv[1], [], {
          stdio: [0, 1, 2],
          cwd: process.cwd,
          env: process.env,
          detached: true
        });
        child.unref();
        // 后台进程已启动，主进程关闭
        process.exit(1);
        break;
      }
    }
    fs.writeFileSync(pid, process.pid, 'ascii');
    removePid = true;
    process.on('exit', function() {
      if (removePid && fs.existsSync(pid)) {
        fs.unlinkSync(pid);
      }
    });
    var instances  = [];
    config.app.instances.forEach(function(instance) {
      cluster.fork(instance);
    });
  } else {
    //开启子线程
    //进行redis的连接
/*    var redis = require('redis'), cache;
    //初始化缓存
    cache = redis.createClient(
      config.cache_port || 6379,
      config.cache_host || '127.0.0.1'
    );
    cache.on('error', function(error) {
      loggerApp.fatal('[cache] ' + error, true);
      loggerApp.fatal('子进程异常终止', true);
      process.exit(1);
    });
*/
    var cookie = require('cookie');
    var urlparser = require('url');
    var querystring = require('querystring');
    var util = {
      parseUrl: function(url) {
        var params = urlparser.parse(url);
        params.query = querystring.parse(params.query);
        return params;
      },
      parseCookies: function(cookies) {
        return cookie.parse(cookies);
      },
      cacheGet: function(k, callback) {
        cache.get(k, function(error, value) {
          if (error) {
            loggerApp.error('[cache] ' + error);
          }
          callback(value);
        });
      },
      cacheSet: function(key, value, ex) {
        if (ex === undefined) {
          ex = 86400;
        }
        if (ex > 0) {
          cache.setex(key, ex, value, function(error) {
            if (error) {
              log.getLogger('server').error('[cache] ' + error);
            }
          });
        } else {
          cache.set(key, value, function(error) {
            if (error) {
              log.getLogger('server').error('[cache] ' + error);
            }
          });
        }
      },
      cacheIncr: function(key) {
        cache.incr(key);
      }
    };
    var scripts = [], business;
    config.httpScripts.forEach(function(script) {
      business =  require('./scripts/' + script[1]);
      business.logs = loggerScripts;
      business.get301Data = function(location) {
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
      };
      business.get200Data = function(content, contentType) {
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
      };
      business.util = util;
      scripts[script[0]] = business;
    });
    var evn = process.env;
    //注册个发包组件
    var sender = require('./node_modules/sender/build/Release/sender');
    dev = new Buffer(evn.sendPort);
    sender.sendInit({
      dev: dev,
      length : dev.length,
    });
    loggerApp.info('开启线程监听msgId为 ' + evn.msgId + ' msgType为 ' + evn.msgType + ' 队列' );
    var bypass = require('./node_modules/ipc/bypass')(evn.msgId, evn.cpuId);
    bypass.listen(pagesize, parseInt(evn.msgType, 10), function(data, buffer) {
      var script = scripts[data.host];
      if (script) {
       	console.log(data.host);
	 var httpData = script.getData(data);
        if (httpData) {
          sender.send(buffer, httpData);
        }
      }
    });
  }
}while(0);
