require 'spec_helper_acceptance'

test_name 'Client enroll via certmonger'

describe 'Client enroll via certmonger'
  ca_metadata = {
    'simp-puppet-pki' => {
      :http_port  => 5508,
      :https_port => 5509
    },
    'simp-site-pki' => {
      :http_port  => 8080,
      :https_port => 8443
    }
  }

  ca   = 'simp-site-pki'
  info = ca_metadata['simp-site-pki']

  hosts_with_role(hosts, 'ca').each do |ca_host|
    context "CA server #{ca_host}" do
      let(:ca_hostname) { fact_on(ca_host, 'fqdn') }

      context "on CA server #{ca_host} for CA #{ca}" do
        it "should set one time passwords for #{ca} SCEP requests from all clients" do
        create_scep_otps(hosts, ca_host, ca, :one_time_password.to_s)
      end

      hosts.each do |client|
        context "on client #{client}" do
          let(:client_fqdn) { fact_on(client, 'fqdn') }

          it 'should install, start, and enable certmonger' do
            client.install_package('certmonger')
            on(client, 'puppet resource service certmonger ensure=running')
            on(client, 'puppet resource service certmonger enable=true')
          end

          it 'should obtain CA root certificate' do
            # Real distribution mechanism TBD.  Can parse certs_info in commented
            # out code for root cert, but choosing lazy method in the test
            #
            #certs_info = on(host, "openssl s_client -host #{ca_hostname} -port #{info[:https_port]} -prexit -showcerts 2>/dev/null < /dev/null")
            cert = on(ca_host, "cat /root/.dogtag/crt_tmp_#{ca}/ca_certs/CA*.pem").stdout
            create_remote_file(client, '/etc/pki/simp-pki-root-ca.pem', cert)
            on(client, 'ls -Z /etc/pki/simp-pki-root-ca.pem')
          end

          it 'should obtain CA certificate ' do
            # Real distribution mechanism TBD
            on(client, "sscep getca -u http://#{ca_hostname}:#{info[:http_port]}/ca/cgi-bin/pkiclient.exe -c /etc/pki/#{ca}-ca.pem" )
            on(client, "ls -Z /etc/pki/#{ca}-ca.pem")
          end

          it 'should add the CA to certmonger' do
            cmd = [
              'getcert add-scep-ca',
              '-c SIMP_Site',
              "-u https://#{ca_hostname}:#{info[:https_port]}/ca/cgi-bin/pkiclient.exe",
              '-R /etc/pki/simp-pki-root-ca.pem',
              "-I /etc/pki/#{ca}-ca.pem"
            ]

            on(client, cmd.join(' '))
          end

          it 'should ensure the default NSS database exists' do
            results = on(client, 'ls /root/.netscape', :accept_all_exit_codes => true)
            if results.exit_code != 0
              on(client, 'mkdir /root/.netscape')
              # Creating a NSS DB without a password is not recommended for a real
              # system, but OK for this test
              on(client, 'certutil -N --empty-password')
            end
          end

          pending 'should request a certificate using certmonger' do
            cmd = [
              'getcert request',
              '-c SIMP_Site',
              "-k /etc/pki/#{client_fqdn}.pem",
              "-f /etc/pki/#{client_fqdn}.pub",
              "-I #{client_fqdn}",
              '-r -w -v',
              "-L #{:one_time_password.to_s}"
            ]

            on(client, cmd.join(' '))
            on(client, 'getcert list')

            on(client, "ls /etc/pki/#{client_fqdn}.pub")
            verify_cert(ca_host, ca, info[:https_port], client, "/etc/pki/#{client_fqdn}.pub", client_fqdn)
          end
        end
      end
    end
  end
end
