快速入门
========

简介
^^^^

　　MetaScan漏洞验证平台基于metasploit-framework框架而推，基于这个框架，你可以编写出属于你自己的漏洞验证模块，编写模块的相关说明，此文档将做详细的描述，同时我们也会奉上例子供您参考。期待您的加入，让我们一同成为安全牛。

环境配置
^^^^^^^^

下载程序
磨刀不误砍柴工，在写模块之前需要搭建好相关环境。如果你是个勤劳的白帽子，我们建议您在*nix系统中完整的安装一次Metasploit，有助于对该框架的多一些了解，不过，熟悉kali的人大都知道系统自身带有现成的环境。Metasploit和Kali Linux的相关下载地址参考如下：
Metasploit境内官方下载地址：http://www.metasploit.cn/thread-3-1-1.html
Metaspoit境外官方下载地址：
--Metasploit for Linux 64-bit:
Kali Linux境内官方下载地址：
Kali Linux境外官方下载地址：https://www.kali.org/downloads/

安装程序
Metasploit因存在windows和linux两个版本，windows下的安装方式较为常规，此处只介绍在linux系统下的安装方法。
a、添加执行权限
64位：chmod +x /path/to/metasploit-latest-linux-x64-installer.run
32位：chmod +x /path/to/metasploit-latest-linux-installer.run

b、以root权限运行安装程序
64位：sudo /path/to/metasploit-latest-linux-x64-installer.run
32位：sudo /path/to/metasploit-latest-linux-installer.run

c、在出现Metasploit的安装窗口之后，均按默认选项执行并单击‘Forward’即可完成安装。
 
注：编写Metaplosit模块所使用的语言是ruby， Metasploit和Kali Linux在安装完成后均包含了需要的ruby环境，用户可以直接进行相关操作，至于IDE以及Metasploit的两个不同平台的版本选择，此处不做推荐，可以根据自身熟悉情况而定。

相关目录
进入Metasploit的目录
cd /opt/metasploit/apps/pro/msf3/modules/exploits

注：该目录存放的主要是漏洞验证相关的模块，用户所写的相关漏洞验证模块均存放在此目录下，感兴趣的白帽子也可以写一些工具性的模块，工具性的模块主要存放在/opt/metasploit/apps/pro/msf3/modules/auxiliary目录中，但类似这些模块均不在此文档中做说明，用户可自行研究。

编写模块
^^^^^^^^

编写规范

参考如下：https://ruby-china.org/wiki/coding-style

常见问题
^^^^^^^^