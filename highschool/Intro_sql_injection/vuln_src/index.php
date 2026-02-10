<?php
include('./src/model.php');
session_start();

if (!isset($_SESSION['username']) && !isset($_SESSION['email'])) { //If not authenticate
  $action = isset($_GET['action']) && !empty($_GET['action']) ? $_GET['action'] : null; // Get the action : login

  //Login method
  if ($action=='login' && isset($_POST['username'], $_POST['password'])) {
    $loginCond = loginProcess($_POST);
    if (!is_int($loginCond)){ $errorMessage = $loginCond; }
  }


  if($action == 'login') {require('templates/login.php');}
  else{ header('Location: http://127.0.0.1/vulnerable/?action=login'); exit();}
}

else{

  if (isset($_GET['action']) && !empty($_GET['action'])) {
    if ($_GET['action'] === 'user') {
        if (!isset($_GET['id']) || empty($_GET['id'])){  $users = get_user(null);}
        else {
          $cond = verif_user($_GET['id'], $_SESSION['username']);
          $users = get_user($_GET['id']);
          if(!$cond) {  $message = 'Your a not allowed !';}
         }
          require('templates/members.php');
    } else {
      if (!isset($_GET['id']) || empty($_GET['id'])){ $posts = get_post(null);}
      else {$posts = get_post($_GET['id']);}
      require('templates/home.php');
    }
}
}
