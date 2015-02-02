<?php
class DeviceModel extends BpfModel
{
  public function getCPU_memData($type)
  {
    $day1 = date('d');
    $day2 = date('dHi');
    $seven = REQUEST_TIME - 60 * 60 * 24 * 7;
    $thirdty = REQUEST_TIME - 60 * 60 * 24 * 30;
    $mysqlModel = $this->getModel('mysql');
    $sql = '';
    if ($type == 1) {
      $sql = 'select cpu_mem_data,cpu_mem_created from `cpu_mem` where cpu_mem_id like "'.$day1.'%" and cpu_mem_id<'.$day2;
    } else if ($type == 2) {
      $sql = 'select cpu_mem_data,cpu_mem_created from `cpu_mem` where cpu_mem_created>='.$seven;
    } else if ($type == 3) {
      $sql = 'select cpu_mem_data,cpu_mem_created from `cpu_mem` where cpu_mem_created>='.$thirdty;
    }
    $set = $mysqlModel->query($sql)->all();
    $result = objectChange($set);
    return $result;
  }

  public function getFlowData($type)
  {
    $day1 = date('d');
    $day2 = date('dHi');
    $seven = REQUEST_TIME - 60 * 60 * 24 * 7;
    $thirdty = REQUEST_TIME - 60 * 60 * 24 * 30;
    $mysqlModel = $this->getModel('mysql');
    $sql = '';
    if ($type == 1) {
      $sql = 'select net_data,netport_created from `netport` where netport_id like "'.$day1.'%" and netport_id<'.$day2;
    } else if ($type == 2) {
      $sql = 'select net_data,netport_created from `netport` where netport_created>='.$seven;
    } else if ($type == 3) {
      $sql = 'select net_data,netport_created from `netport` where netport_created>='.$thirdty;
    }
    $set = $mysqlModel->query($sql)->all();
    $result = objectChange($set);
    return $result;
  }

  public function getPort()
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->getSqlBuilder()->select('name')->from('interface')->query()->all();
    $set = objectChange($result);
    return $set;
  }
}
