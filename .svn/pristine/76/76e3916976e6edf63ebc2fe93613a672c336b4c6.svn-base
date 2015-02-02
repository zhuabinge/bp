<?php
class DefaultController extends BpfController
{
  public function indexAction()
  {
    if (isLogin()) {
      gotoUrl('home');
    }
    $view = $this->getView();
    $view->assign('page', 1);
    $view->display('index.phtml');
  }
}
