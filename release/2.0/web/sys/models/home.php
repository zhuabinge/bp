<?php
class HomeModel extends BpfModel
{
  public function getBaseInfo()
  {
    $mysqlModel = $this->getModel('mysql');
    $set1 = $mysqlModel->getSqlBuilder()->select('base_info_id,serialnum,hostname,hardware,version')->from('base_info')->query()->all();
    $result = objectChange($set1);
    return $result[0];
  }
}
