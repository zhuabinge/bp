<?php
class LoginController extends BpfController
{
    // 退出登录
  public function logoutAction()
  {
    global $user;
    session_destroy();
    gotoUrl('');
  }

  public function indexAction()
  {
    if (isLogin()) {
      gotoUrl('');
    }
    if (isset($_POST['username']) && isset($_POST['password'])){
      $set = array(
        'user_name' => $_POST['username'],
        'user_pw' => $_POST['password'],
        );
      $model = $this->getModel('login');
      $result = $model->checkUserInfo($set);
      if ($result) {
        global $user;
        $user = $result;
        $set = get_object_vars($result);
        $view = $this->getView();
        $view->assign('username', $set['user_name']);
        if ($set['user_permission'] == 1) {
          $user->admin  = $set['user_permission'];
          $view->assign('permission', $set['user_permission']);
        }
        $view->display('system.phtml');
      } else {
        $view = $this->getView();
        $view->assign('username', $_POST['username']);
        $view->assign('loginMsg', '用户名或密码输入错误');
        $view->display('index.phtml');
      }
    }
  }
}
