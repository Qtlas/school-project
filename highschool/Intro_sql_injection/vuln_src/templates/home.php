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
  <h2> Post </h2>
    <div class="form">
      <?php foreach ($posts as $post): ?>
          <div class="post">
              <h3><a href="/vulnerable/?action=posts&id=<?php echo $post['id'] ?>"><?php echo $post['title']; ?></a></h3>
              <p><?php echo $post['content']; ?></p>
              <p><i>Post by : <?php echo $post['author_name'];?> </i></p>
          </div>
      <?php endforeach; ?>
    </div>
  </div>
</body>
</html>
