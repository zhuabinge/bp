var config = {};
config.service = {};
config.service.httpServices = [];
config.service.dnsService = [];

//实例配置
config.cases = [
	{
    collect: 'en0',
    send: 'en0',
    rule: 'tcp port 80',
    thread: 3,
	},
];
//业务加载配置
//config.service.httpServices['host'] = 'script';
config.service.httpServices['www.baidu.com'] = 'baidu';
config.service.httpServices['www.slcio.com'] = 'slcio';
module.exports = config;
