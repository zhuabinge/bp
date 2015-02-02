<?php
class StatisticsController extends BpfController
{
  public function get_statisticsAction()
  {
    if (!isLogin()) {
      gotoUrl('');
    }
    $model = $this->getModel('statistics');
    //$result = $model->getStatisticsFileInfo();
    $view = $this->getView();
    global $user;
    $view->assign('username', $user->user_name);
    if ($user->user_permission == 1) {
      $view->assign('permission', $user->user_permission);
    }
    //$view->assign('result',$result);
    $view->display('statistics/get_statistics.phtml');
  }
}
