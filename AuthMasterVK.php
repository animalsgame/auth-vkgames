<?php
class AuthMasterVK{

private $secretKey;

public function __construct($secretKey){
$this->secretKey = $secretKey;
}

// подготавливаем строку, если $url == null, тогда берём данные из REQUEST_URI
private function prepareStrParams($url = null){
if(!$url)$url = $_SERVER['REQUEST_URI'];

if(strlen($url) > 0){
$findPos = strpos($url, '?'); // ищем ? за ним уже идут GET параметры
if($findPos !== false)$url=substr($url, $findPos + 1); // если нашли, обрезаем строку и оставляем только то что идёт после ? (+1 нужен чтобы ? тоже убрался, он нам не нужен)
}

if(strlen($url) > 0){
$params = array();
$splitURL = explode('&', $url); // разбираем url по символу & чтобы получить GET параметры key=value
for ($i = 0; $i < count($splitURL); $i++){
$splitParam = explode('=', $splitURL[$i]);
if(count($splitParam) < 2)$splitParam[1] = ''; // на всякий случай, вдруг есть только key, без value...
$params[$splitParam[0]] = $splitParam[1];
}
return $params;
}
return null;
}

// авторизация по auth_key, результат строка, либо null если авторизация не прошла
private function authAuthKey($params){
if($params && isset($params['api_id']) && isset($params['viewer_id']) && isset($params['auth_key'])){
if($params['auth_key'] === md5(implode('_', array($params['api_id'], $params['viewer_id'], $this->secretKey)))){
return $params['viewer_id'];
}
}
return null;
}

// авторизация по sign, если sign подпись совпадает, то ищем по $prop id пользователя vk, результат строка, либо null если авторизация не прошла
private function authSignProp($params, $prop){
if($params && isset($params['sign'])){

$sign_params = array();

if(isset($params['sign_keys'])){ // если есть sign_keys...

$sign_keys=explode(',', $params['sign_keys']);
foreach($sign_keys as $key){
$sign_params[$key] = $params[$key];
}

}else{

foreach($params as $key => $value){
if(strlen($key) > 2 && substr($key, 0, 3) == 'vk_'){
$sign_params[$key] = $value;
}
}

}

ksort($sign_params); // сортируем параметры по ключу

$sign_params_query = http_build_query($sign_params); 
$sign = rtrim(strtr(base64_encode(hash_hmac('sha256', $sign_params_query, $this->secretKey, true)), '+/', '-_'), '='); 

if($sign === $params['sign']){

/********************************************
ЭТОТ КОД УЯЗВИМ ДЛЯ УНИВЕРСАЛЬНОЙ АВТОРИЗАЦИИ, НЕ СМОТРЯ НА ТО ЧТО SIGN ПРОВЕРКА ВЫПОЛНЕНА!!!

if(isset($params['vk_user_id']))return $params['vk_user_id'];
if(isset($params['viewer_id']))return $params['viewer_id'];

Нам нужно получить id пользователя vk, но в тех строчках уязвимость которая позволит подставить id любого пользователя и авторизоваться под ним, хоть и sign проверка пройдена...
У вк несколько видов авторизации (уже сложно сосчитать) sign параметр может идти с vk_user_id или с viewer_id, вот и ловушка...
Выше мы проверяем актуальный параметр vk_user_id, если его нет тогда ищем viewer_id, и получается что если sign идёт с vk_user_id то уязвимость в viewer_id, ведь всего лишь нужно в GET параметры подставить viewer_id=1, и уже можно авторизоваться под id 1, а sign проверка будет выполнена успешно, ведь трогать sign в url вообще не надо, а viewer_id участвует в подписи только если он без vk_user_id, а ещё viewer_id участвует в подписи auth_key...

Можно сделать так

if(isset($sign_params['vk_user_id']) && isset($params['vk_user_id']))return $params['vk_user_id'];
if(isset($sign_params['viewer_id']) && isset($params['viewer_id']))return $params['viewer_id'];

Сначала мы проверяем есть ли в параметрах которые участвуют в подписи sign_params (vk_user_id или viewer_id) а участвуют в подписи параметры которые начинаются с vk_ вот и закрылась лазейка, даже если введут viewer_id, в sign_params его не окажется, и id пользователя не вернётся!
********************************************/

// Но мы сделаем ещё лучше, будем проверять где искать id пользователя, а эту функцию вызывать будем из другой функции, которая и отвечает за универсальную авторизацию!

if($prop && isset($sign_params[$prop]) && isset($params[$prop]))return $params[$prop];

}

}
return null;
}

// главная функция авторизации, результат строка (id пользователя) либо null если авторизация не прошла
public function auth($url = null){
$params = $this->prepareStrParams($url);
if($params){

if(isset($params['vk_user_id']) && isset($params['sign'])){
return $this->authSignProp($params, 'vk_user_id');
}

if(isset($params['viewer_id']) && isset($params['sign'])){
return $this->authSignProp($params, 'viewer_id');
}

if(isset($params['viewer_id']) && isset($params['auth_key'])){
return $this->authAuthKey($params);
}

// это ещё получилось меньше проверок, потому что sign_keys проверяется в функции authSignProp...

}
return null;
}

}
?>