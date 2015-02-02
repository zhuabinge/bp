<?php
class LiscenceController extends BpfController
{
  public function indexAction()
  {
    if (!isLogin()) {
      gotoUrl('');
    }
    $model = $this->getModel('liscence');
    $result = $model->getFileInfo();
    $view = $this->getView();
    global $user;
    $view->assign('username', $user->user_name);
    if ($user->user_permission == 1) {
      $view->assign('permission', $user->user_permission);
    }
    $view->assign('result',$result);
    $view->display('liscence/add_liscence.phtml');
  }

  public function addLiscenceAction()
  {
    if (!isLogin()) {
      gotoUrl('');
    }
    if(isset($_POST['liscence'])){
      $model = $this->getModel('liscence');
      $set = array(
        'base_info_id' => $_POST['base_info_id'],
        'legal_liscence' => $_POST['liscence'],
        );
      $result = $model->setFileInfo($set);
      gotoUrl('liscence');
    }
  }
}
