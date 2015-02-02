<?php
class LoginModel extends BpfModel
{
  public function checkUserInfo($set)
  {
    $mysqlModel = $this->getModel('mysql');
    $sql = 'select * from `sys_user` where user_name="'.$set['user_name'].'" and user_pw="'.$set['user_pw'].'"';
    $uid = $mysqlModel->getSqlBuilder()->select('uid')->from('sys_user')->where('user_name', $set['user_name'])->where('user_pw', $set['user_pw'])->query()->field();
    if ($uid) {
      $user = $mysqlModel->getSqlBuilder()->from('sys_user')->where('uid', $uid)->query()->row();
      if ($user) {
        unset($user->password);
      }
      return $user;
    } else {
      return false;
    }
  }
}
