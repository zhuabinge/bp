<?php
class ValueaddController extends BpfController
{
  public function get_valueAddAction($page = 1)
  {
    if (!isLogin()) {
      gotoUrl('');
    }
    $rows = 10; //每页数量
    $model = $this->getModel('valueadd');
    $result = $model->getValueAdd($page, $rows);
    $valueAddCount = $model->getValueAddCount();
    $totalPage = ($valueAddCount / $rows);
    if ($valueAddCount % $rows > 0 ) {
      $totalPage++;
    }
    if ($page != 1 && $page > $totalPage) { //溢出处理
      gotoUrl('valueadd/get_valueAdd/1');
    }
    $view = $this->getView();
    global $user;
    $view->assign('username', $user->user_name);
    if ($user->user_permission == 1) {
      $view->assign('permission', $user->user_permission);
    }
    $view->assign('page', is_numeric($page) ? $page : 1);
    $view->assign('rows', $rows);
    $view->assign('count', $valueAddCount);
    $view->assign("result", $result);
    $view->display("value_added/set_valueAdd.phtml");
  }

  public function set_valueAddAction()
  {
    if (!isLogin()) {
      gotoUrl('');
    }
    if(isset($_GET['do_id']) && isset($_GET['state'])){
      $set = array(
        'do_id' => $_GET['do_id'],
        'state' => $_GET['state'],
        'updated' => REQUEST_TIME,
        );
      $model = $this->getModel('valueadd');
      $result = $model->setValueAdd($set);
      gotoUrl("valueadd/get_valueAdd");
    }
  }
}
