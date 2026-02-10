<?php

function get_db() {
  try {
    $db  = new PDO ('mysql:host=localhost;dbname=vulndb', 'forum', 'password');
  } catch(PDOexception $e) {
    die;
    return 'error';
  }
  return $db;
}


function loginProcess($post) {
  if(empty($post['username']) || empty($post['password'])){return 'Please fill in all fields !';}
  $username = $post['username'];
  $password = $post['password'];

  $db = get_db();
  $sqlQuery = "SELECT username,password,email FROM user WHERE username='$username' AND password='$password'";
  $sth = $db->prepare($sqlQuery);
  $sth->execute();
  $creds = $sth->fetchAll();

  if(isset($creds[0])){
    $_SESSION['username'] = $username;
    $_SESSION['email'] = $creds[0]['email'];
    header('Location: http://127.0.0.1/vulnerable/?action=posts');
    exit();
  }
  else{return 'No login found !';}
}


function get_post($id) {
    $db = get_db();
    if (isset($id) && !empty($id)) {
        $sqlQuery = "SELECT * FROM post WHERE id = $id ";
    } else {
        $sqlQuery = "SELECT * FROM post ORDER BY id DESC";
    }
    $sth = $db->prepare($sqlQuery);
    $sth->execute();

    $post = $sth->fetchAll();
    return $post;
}


function get_user($id) {
  $db = get_db();
  if (isset($id) && !empty($id)) {
      $sqlQuery = "SELECT * FROM user WHERE id = $id ";
  } else {
      $sqlQuery = "SELECT * FROM user ORDER BY id ASC";
  }
  $sth = $db->prepare($sqlQuery);
  $sth->execute();

  $post = $sth->fetchAll();
  return $post;
}


function verif_user($id, $name){
  $db = get_db();
  $id2 = intval($id);
  $sqlQuery = "SELECT * FROM user WHERE id = $id2 AND username = '$name'";

  $sth = $db->prepare($sqlQuery);
  $sth->execute();

  $user = $sth->fetchAll();
  if(isset($user[0])) { return true;}
  else{return false;  }
}
