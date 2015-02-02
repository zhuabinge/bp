<?php
class LiscenceModel extends BpfModel
{
  public function getFileInfo()
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->getSqlBuilder()->select('base_info_id,init_liscence,legal_liscence')->from('base_info')->query()->row();
    return $result;
  }

  public function setFileInfo($info)
  {
    $mysqlModel = $this->getModel('mysql');
    $result1 = $mysqlModel->update('base_info', $info);
    return $result1->insertId();
  }
}
