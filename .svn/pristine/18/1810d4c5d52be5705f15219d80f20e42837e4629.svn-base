<?php
class HomeController extends BpfController
{
  public function indexAction()
  {
    if (!isLogin()) {
      gotoUrl('');
    }
    $view = $this->getView();
    global $user;
    $view->assign('username', $user->user_name);
    if ($user->user_permission == 1) {
      $view->assign('permission', $user->user_permission);
    }
    $view->display('system.phtml');
  }

  public function getHomeViewAction()
  {
    if (!isLogin()) {
      gotoUrl('');
    }
    $view = $this->getView();
    $queuemodel  = $this->getModel('queue');
    $result2 = null;
    while ($result2 == null) {
      $set = $queuemodel->getCPU_MemData();
      $result2 = objectChange(get_object_vars($set)['data']);
    }
    foreach ($result2 as $key => $row) {
      $time[$key] = $row['time'];
    }
    array_multisort($time, SORT_DESC, $result2);
    $result1 = array();
    $temp = count($result2) > 8 ? 8 : count($result2);
    for ($i = $temp; $i >= 0; $i--) {
      $result1[$i] = $result2[$i];
    }
    $model = $this->getModel('home');
    $result = $model->getBaseInfo();
    $result['systime'] = REQUEST_TIME;
    $view->assign('result2', $result1);
    $view->assign('result', $result);
    $view->display('home/cpu_mem_chart.phtml');
  }
}
