<?php
class InterfaceModel extends BpfModel{
  public function getInterface( )
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->getSqlBuilder()->select('inter_id,name,type')->from('interface')->query()->all();
    $set = objectChange($result);
    for ($i = 0; $i < count($set); $i++) {
      if ($set[$i]['type'] == 1) {
        $set[$i]['type'] = '发包';
      } else if ($set[$i]['type'] == 2) {
        $set[$i]['type'] = '收包';
        $result1 = $mysqlModel->query('select type1,type2,type3,inter_id2 from `inpackage` where inter_id='.$set[$i]['inter_id'])->all();
        $set1 = objectChange($result1);
        $result2 = $mysqlModel->query('select name from `interface` where inter_id='.$set1[0]['inter_id2'])->all();
        $set2 = objectChange($result2);
        $set[$i]['outport'] = $set2[0]['name'];
        if ($set1[0]['type1'] == 12) {
          $set[$i]['type2'] = 'HTTP,DNS';
        } else if ($set1[0]['type1'] == 10) {
          $set[$i]['type2'] = 'HTTP';
        } else if ($set1[0]['type1'] == 02) {
          $set[$i]['type2'] = 'DNS';
        } else {
          $set[$i]['type2'] = '';
        }
        if ($set1[0]['type2'] == 1) {
          $set[$i]['style'] = 'pcap';
        } else if ($set1[0]['type2'] == 2) {
          if ($set1[0]['type3'] == 10) {
            $set[$i]['style'] = 'pf : rx';
          } else if ($set1[0]['type3'] == 02){
            $set[$i]['style'] = 'pf : tx';
          }
        } else {
          $set[$i]['style'] = '';
        }
      } else if ($set[$i]['type'] == 3) {
        $set[$i]['type'] = '管理';
        $result1 = $mysqlModel->query('select ip from `manage` where inter_id='.$set[$i]['inter_id'])->all();
        $set1 = objectChange($result1);
        $set[$i]['ip'] = $set1[0]['ip'];
      } else {
        $set[$i]['type'] = '';
      }
    }
    return $set;
  }

  public function setInterface( $set1, $set2, $set4, $set5)
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->update('interface',$set1, $set2);
    $result3 = $mysqlModel->update('interface',$set4, $set5);
    $sid = $result->affected();
    $set3 = array(
      'inter_id' => $set2['inter_id'],
      );
    if ($set1['type'] == 1) {
      $result1 = $mysqlModel->delete('inpackage',$set3);
      $result2 = $mysqlModel->delete('manage',$set3);
    } else if ($set1['type'] == 2) {
      $result1 = $mysqlModel->delete('outpackage',$set3);
      $result2 = $mysqlModel->delete('manage',$set3);
    } else if ($set1['type'] == 3) {
      $result1 = $mysqlModel->delete('outpackage',$set3);
      $result2 = $mysqlModel->delete('inpackage',$set3);
    }

    return $sid;
  }

  public function setOutpackage($set1, $set2)
  {
    $mysqlModel = $this->getModel('mysql');
    $result1 = $mysqlModel->insert('outpackage', $set1, false, true);
    $set3 = array(
      'out_left_id' => 1,
      );
    $result2 = $mysqlModel->update('out_left', $set2, $set3);
    $sid = $result2->affected();
    return $sid;
  }

  public function setInpackage( $set)
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->insert('inpackage', $set, false, true);
    $set1 = array(
      'state' => 1,
      );
    $set2 = array(
      'inter_id' => $set['inter_id2'],
      );
    $result1 = $mysqlModel->update('interface', $set1, $set2);
    $sid = $result->affected();
    return $sid;
  }

  public function setManage( $set)
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->insert('manage', $set, false, true);
    $sid = $result->affected();
    return $sid;
  }

  public function getManage( $id)
  {
    $result = array();
    $result1 = array();
    $mysqlModel = $this->getModel('mysql');
    $set = $mysqlModel->getSqlBuilder()->select('*')->from('manage')->where("inter_id",$id)->query()->all();
    $result = objectChange($set);
    if (count($result) > 0) {
      $result1 = $result[0];
    } else {
      $result1 = $result;
    }
    return $result1;
  }

  public function getOutpackage($id)
  {
    $mysqlModel = $this->getModel('mysql');
    $set1 = $mysqlModel->getSqlBuilder()->select('*')->from('outpackage')->where("inter_id",$id)->query()->all();
    $result2 = $mysqlModel->getSqlBuilder()->select('*')->from('out_left')->query()->all();
    $result = array();
    $num = 0;
    foreach ($set1 as $value) {
      $result[$num] = get_object_vars($value);
      $num++;
    }
    if ($num > 0) {
      $result[0]['out_left_sum'] = $result2[0]->out_left_num + $result[0]['out_num'];
    } else {
      $result[0]['out_left_sum'] = $result2[0]->out_left_num;
    }
    return $result[0];
  }

  public function getInpackage( $id)
  {
    $result = array();
    $result1 = array();
    $set1 = array();
    $mysqlModel = $this->getModel('mysql');
    $set = $mysqlModel->getSqlBuilder()->select('*')->from('inpackage')->where("inter_id", $id)->query()->all();
    $result = objectChange($set);
    $num = 0;
    if (isset($result[0]) && $result[0]['inter_id2']) {
      $set1 = $mysqlModel->query('select inter_id,name from `interface` where (type=1 and state=0) or inter_id='.$result[0]['inter_id2'])->all();
    } else {
      $set1 = $mysqlModel->query('select inter_id,name from `interface` where type=1 and state=0')->all();
    }
    $result1 = objectChange($set1);
    $result[0]['inter_id_set'] = $result1;
    return $result[0];
  }

  public function getData($name)
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->getSqlBuilder()->select('*')->from('interface')->where('name', $name)->query()->all();
    return $result;
  }

  public function getMainConfig()
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->query('select base_info_id,http_method,analysts_cache,dns1,dns2,created,updated from `base_info`')->all();
    return $result;
  }

  public function addMainConfig($set)
  {
    $mysqlModel = $this->getModel('mysql');
    $result = $mysqlModel->insert('base_info', $set, false, true);
    $sid = $result->affected();
    return $sid;
  }
}
