module.exports = {
  server: {
    // hostname: '127.0.0.1',
    port: 8080,
    worker_processes: 1,
//    daemonize: true,
    token: '12345678'
  },
  service: [
    'mysql',
    'cache',
    'config',
    'queue',
  ],
  mysql: {
    host: 'localhost',
    port: 3306,
    user: 'NoGFW',
    password: 'mysqlpwd',
    name: 'NoGFW',
    log_query: 1
  },
  cache: {
    host: 'localhost',
    port: 6379,
    lifetime: 1800,
  },
  queue: [
    'sysinfoUpdate',
  ],
};
