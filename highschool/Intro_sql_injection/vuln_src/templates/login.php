<!DOCTYPE html>
 <html lang="en">
 <head>
     <meta charset="UTF-8">
     <meta http-equiv="X-UA-Compatible" content="IE=edge">
     <meta name="viewport" content="width=device-width, initial-scale=1.0">
     <title>Login</title>
     <link rel="stylesheet" href="/vulnerable/static/style.css">
 </head>
 <body style="display:flex; align-items:center; justify-content:center;">
 <div class="login-page">
   <div class="form">
     <form class="login-form" method="post">
       <h2><i> Login</h2>
       <input type="text" placeholder="Username" name="username" required />
       <input type="password" placeholder="Password" name="password" required/>
       <button type="submit" class="button"> Sign in </button><br>
       <?php if(isset($errorMessage)) { echo "<p class='message-error'>" . $errorMessage . "</p>";} ?>
       <p class="message">Not registered? <a href="?action=sign-up">Create an account</a></p>
     </form>
   </div>
 </div>
 </body>
 </html>
