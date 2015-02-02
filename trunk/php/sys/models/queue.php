<?php
class QueueModel extends BpfModel
{

  /**
  * 生成接口配置文件
  * @return bool
  */
  public function getCPU_MemData()
  {
    $url = $this->serviceUrl . '/CPU_MemData';
    $result = $this->put($url);
    return $result;
  }

  public function getBaseInfoData()
  {
    $url = $this->serviceUrl . '/BaseInfoData';
    $result = $this->put($url);
    return $result;
  }
}
