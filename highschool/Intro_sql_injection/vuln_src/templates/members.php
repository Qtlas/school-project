<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Posts</title>
  <link rel="stylesheet" href="/vulnerable/static/home.css">
</head>
<body>
  <div class="navbar">
    <ul>
      <li><a href="?action=user">List members</a></li>
      <li><a href="?action=posts">Posts </a></li>
      <li><a href="#">My account</a></li>
    </ul>
  </div>
  <div class="post-page">
  <h2> Members </h2>
    <div class="form">
      <?php if(!isset($message)): ?>
        <?php foreach ($users as $user): ?>
          <?php if($user['username'] !== $_SESSION['username']): ?>
          <div class="post">
                <h3><a href="/vulnerable/?action=user&id=<?php echo $user['id'] ?>"><?php echo $user['username']; ?></a></h3>
                <p><i>Contact : <?php echo $user['email'];?> </i></p>
            </div>
          <?php endif;?>
        <?php endforeach; ?>
      <?php else: ?>
        <p> <?php echo $message; ?> </p>
      <?php endif; ?>
    </div>
  </div>
</body>
</html>
