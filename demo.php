<?php
require('./AuthMasterVK.php'); // подключаем класс
$secret = ''; // секретный ключ из настроек игры
$m = new AuthMasterVK($secret);

$userid = $m->auth(); // если нужна авторизация через iframe (не через POST запрос из js)
// если через js, то в auth передайте строку с GET параметрами, в js её можно получить через window.location.search, и передать через POST
$userid = $m->auth($_POST['s']); 

if($userid){
// авторизация успешна
echo 'Мой id '.$userid;
}else{
// ошибка авторизации
echo 'Ошибка авторизации';	
}
?>