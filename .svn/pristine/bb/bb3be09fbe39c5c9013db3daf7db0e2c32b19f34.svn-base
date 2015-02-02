<?php
class DeviceController extends BpfController
{
  public function indexAction()
  {
    if (!isLogin()) {
      gotoUrl('');
    }
    if (isset($_GET['type'])) {
      $view = $this->getView();
      global $user;
        $view->assign('username', $user->user_name);
        if ($user->user_permission == 1) {
          $view->assign('permission', $user->user_permission);
        }
      if ($_GET['type'] == 1) {
        $view->display('device/cpu_mem_status.phtml');
      } else if ($_GET['type'] == 2) {
        $model = $this->getModel('device');
        $portset = $model->getPort();
        $view->assign('portset', $portset);
        $view->display('device/flow_status.phtml');
      }
    }
  }


  public function getFlow_infoAction()
  {
    if (!isLogin()) {
      gotoUrl('');
    }
    $view = $this->getView();
    $model = $this->getModel('device');
    $type = 1;
    if ($_POST['type'] == 2) {
      $type = 2;
    } else if ($_POST['type'] == 3) {
      $type = 3;
    }
    $result = $model->getFlowData($type);
    foreach ($result as $key => $row) {
      $time[$key] = $row['netport_created'];
    }
    array_multisort($time, SORT_ASC, $result);
    $view->assign('currentPort', $_POST['port']);
    $view->assign('result2', $result);
    $view->display('device/flow_detail.phtml');
  }

  public function getCPU_memAction()
  {
    if (!isLogin()) {
      gotoUrl('');
    }
    $view = $this->getView();
    $model = $this->getModel('device');
    $type = 1;
    if ($_POST['type'] == 2) {
      $type = 2;
    } else if ($_POST['type'] == 3) {
      $type = 3;
    }
    $result = $model->getCPU_memData($type);
    foreach ($result as $key => $row) {
      $time[$key] = $row['cpu_mem_created'];
    }
    array_multisort($time, SORT_ASC, $result);
    $view->assign('result2', $result);
    $view->display('device/cpu_mem_detail.phtml');
  }
}
