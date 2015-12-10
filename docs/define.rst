相关定义
========

**常用的辅助方法**

辅助方法相关代码在 ``msf3/lib/msf/`` 目录下，以 ``Msf::Exploit::Remote::HttpClient`` 为例子，该辅助方法所在目录为：``msf3/lib/msf/core/exploit/http/client.rb``

``client.rb`` 里代码封装了 ``send_request_raw`` 方法， ``include`` 之后，我们可以在自己的模块中使用该方法，源码如下::

    #
    # Connects to the server, creates a request, sends the request, reads the response
    #
    # Passes +opts+ through directly to Rex::Proto::Http::Client#request_raw.
    #
    def send_request_raw(opts={}, timeout = 20)
      if datastore['HttpClientTimeout'] && datastore['HttpClientTimeout'] > 0
        actual_timeout = datastore['HttpClientTimeout']
      else
        actual_timeout =  opts[:timeout] || timeout
      end
      begin
        c = connect(opts)
        r = c.request_raw(opts)
        c.send_recv(r, actual_timeout)
      rescue ::Errno::EPIPE, ::Timeout::Error
        nil
      end
    end

该方法的作用为，创建一个请求，并发送请求到目标服务器，获取读取响应。在前面我们的编写模块例子中有使用，发起了一个method为get的请求，请求到Url地址::

    datastore['TARGETURI']) +"/getPass.php?update=s&email=#{datastore['EMAIL']}"
	
并且超时时间为20秒，代码如下::

    res = send_request_cgi( {
    	        'method' => "GET",
    	        'uri'    => normalize_uri(datastore['TARGETURI']) + "/getPass.php?update=s&email=#{datastore['EMAIL']}"
    	      }, 20)

常用辅助方法还包含了很多辅助我们模块使用的方法，大家可以去源码中发现并使用它们。

常用的辅助方法如下:

* *include Msf::Exploit::Remote::HttpClient* ----http请求辅助方法
* *include Msf::Exploit::Remote::Tcp* ----tcp请求辅助方法
* *include Msf::Exploit::EXE*
* *include Msf::Exploit::Remote::SMTPDeliver*
* *include Msf::Exploit::FileDropper*
* *include Msf::HTTP::Wordpress*
* *include Msf::Exploit::PhpEXE*
* *include Msf::Exploit::Remote::HttpServer::PHPInclude*
* *include Msf::Auxiliary::Scanner*
* *include Msf::Auxiliary::Report*
* *include Msf::Auxiliary::AuthBrute*
* *include Msf::Auxiliary::WmapScanServer*
* *include Msf::HTTP::Typo3*
* *include Msf::Auxiliary::Cisco*

**Initialize----初始化**
::

      def initialize(info = {})
        super(update_info(info,
          'Name'           => 'Generic PHP Code Evaluation',
          'Description'    => %q{
            Exploits things like <?php eval($_REQUEST['evalme']); ?>
            It is likely that HTTP evasion options will break this exploit.
          },
          'Author'         => [ 'egypt' ],
          'License'        => BSD_LICENSE,
          'References'     => [ ],
          'Privileged'     => false,
          'Platform'       => ['php'],
          'Arch'           => ARCH_PHP,
          'Payload'        =>
            {
    
              # max header length for Apache,
              # http://httpd.apache.org/docs/2.2/mod/core.html#limitrequestfieldsize
              'Space'       => 8190,
    
              # max url length for some old versions of apache according to
              # http://www.boutell.com/newfaq/misc/urllength.html
              #'Space'       => 4000,
              'DisableNops' => true,
              'BadChars'    => %q|'"`|,  # quotes are escaped by PHP's magic_quotes_gpc in a default install
              'Compat'      =>
                                       {
                  'ConnectionType' => 'find',
                },
              'Keys'        => ['php'],
            },
          'DisclosureDate' => 'Oct 13 2008',
          'Targets'        => [ ['Automatic', { }], ],
          'DefaultTarget' => 0
          ))
        register_options(
          [
            OptString.new('URIPATH',   [ true,  "The URI to request, with the eval()'d parameter changed to !CODE!", '/test.php?evalme=!CODE!']),
          ], self.class)
      end

``Name``：模块名称

``Description``：模块描述

``License``：开源协议，参数如下：

* *MSF_LICENSE      = "Metasploit Framework License (BSD)"*
* *GPL_LICENSE      = "GNU Public License v2.0"*
* *BSD_LICENSE      = "BSD License"*
* *ARTISTIC_LICENSE = "Perl Artistic License"*
* *UNKNOWN_LICENSE  = "Unknown License"*

``Author``：作者，可以为多人，数据格式，如：[‘Rain’,‘Bolide’]

``Platform``：目标平台，数组格式或字符串格式，如：[‘php’,’unix’]，或者’linux’

``Arch``：目标架构，架构数据如下:

* *ARCH_ANY     = '_any_'*
* *ARCH_X86     = 'x86'*
* *ARCH_X86_64  = 'x86_64'*
* *ARCH_X64     = 'x64' # To be used for compatability with ARCH_X86_64*
* *ARCH_MIPS    = 'mips'*
* *ARCH_MIPSLE  = 'mipsle'*
* *ARCH_MIPSBE  = 'mipsbe'*
* *ARCH_PPC     = 'ppc'*
* *ARCH_PPC64   = 'ppc64'*
* *ARCH_CBEA    = 'cbea'*
* *ARCH_CBEA64  = 'cbea64'*
* *ARCH_SPARC   = 'sparc'*
* *ARCH_CMD     = 'cmd'*
* *ARCH_PHP     = 'php'*
* *ARCH_TTY     = 'tty'*
* *ARCH_ARMLE   = 'armle'*
* *ARCH_ARMBE   = 'armbe'*
* *ARCH_JAVA    = 'java'*
* *ARCH_RUBY    = 'ruby'*
* *ARCH_DALVIK  = 'dalvik'*
* *ARCH_PYTHON  = 'python'*
* *ARCH_NODEJS  = 'nodejs'*
* *ARCH_FIREFOX = 'firefox'*
* *ARCH_ZARCH   = 'zarch'*

``Targets``：目标信息，数组格式，如::

    [
        [ 'MIPS Little Endian', {'Platform' => 'linux','Arch'     => ARCH_MIPSLE}],
        [ 'MIPS Big Endian',{'Platform' => 'linux','Arch'     => ARCH_MIPSBE}]
    ]

``DefaultTarget``：默认目标，指向Targets

``Privileged``：这个模块是否需要访问权限，数据为true或false，默认为false

``DisclosureDate``：POC公布时间

``Payload``：载荷，用于漏洞利用

``register_options``：该方法用于定义模块的参数，参数格式如下:

#第一个参数为数组，第二个参数为 ``self.classregister_options([], self.class)``，如下::

    register_options(
          [OptString.new('参数名', [true, '参数描述',默认值]),
            OptEnum.new('参数名', [true, '描述', '默认值', ['选项1', '选项2']]),
            Opt::RPORT(8080),
            ...
          ], self.class)

#数组参数，有如下类型:

* *OptString：字符串类型，如OptString.new('LOGIN_URL', [true, 'The URL that handles the login process', '/'])*
* *OptEnum：枚举类型，如OptEnum.new('HTTP_METHOD', [true, 'The HTTP method to use for the login', 'POST', ['GET', 'POST']])*
* *OptAddressRange：地址范围，如OptAddressRange.new("RHOSTS", [ false, "Target address range or CIDR identifier" ])*
* *OptAddress：目标地址，如OptAddress.new('SOURCEIP', [false, 'The local client address'])*
* *OptInt：数值类型，如OptInt.new('UID', [false, 'UID to emulate', 0])*
* *OptRegexp：正则匹配，如OptRegexp.new('PATTERN', [true, 'Match a keyword in any chat log\'s filename', '\(2012\-02\-.+\)\.xml$']),*
* *OptPath：文件路径类型，如OptPath.new('PLUGINS',   [ true, "Path to list of plugins to enumerate", File.join(Msf::Config.data_directory, "wordlists", "joomla.txt")])*
* *OptBool：boolean类型，如OptBool.new('PLESK', [true, "Exploit Plesk", false])*
* *OptPort：端口类型，如OptPort.new('RPORT', [true, 'The remote port', 13838])*
* *OptRaw：任何数据格式*

**Rank定义**

Rank是用来做模块排名的，在进行自动化扫描时，排名靠前的模块会优先被利用，分值如下:

* *#ManualRanking       = 0*
* *#LowRanking          = 100*
* *#AverageRanking      = 200*
* *#NormalRanking       = 300*
* *#GoodRanking         = 400*
* *#GreatRanking        = 500*
* *#ExcellentRanking    = 600*
