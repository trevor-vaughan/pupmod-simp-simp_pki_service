require 'spec_helper_acceptance'

test_name 'Obtain SCEP certificates using sscep'

describe 'Obtain SCEP certificates using sscep' do
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

  hosts_with_role(hosts, 'ca').each do |host|
    context "on the CA server #{host}" do
      let(:host_ip) { on(host,'hostname -i').stdout.strip }
      let(:one_time_password) { 'one_time_password' }

      ca_metadata.each do |ca, info|
        context "for CA #{ca}" do
          it 'should have a artifact collection directory' do
            host.mkdir_p(ca)
          end

          it "should set one time passwords for #{ca} SCEP requests from all clients" do
            create_scep_otps(hosts, host, ca, one_time_password)
          end

          it 'should have sscep installed' do
            host.install_package('sscep')
          end

          it 'should get the CA certificate' do
            on(host, "sscep getca -u http://$HOSTNAME:#{info[:http_port]}/ca/cgi-bin/pkiclient.exe -c #{ca}/ca.crt")
          end

          it 'should generate a certificate request' do
            on(host, "cd #{ca} && mkrequest -ip #{host_ip} #{one_time_password}")
          end

#client.host_hash[:platform] =~ /el-6/
          it 'should enroll the certificate' do
            on(host, "cd #{ca} && sscep enroll -u http://$HOSTNAME:#{info[:http_port]}/ca/cgi-bin/pkiclient.exe -c ca.crt -k local.key -r local.csr -l cert.crt")

            verify_cert(host, ca, info[:https_port], host, "#{ca}/cert.crt", host_ip)
          end

          it 'should not allow the one-time password to be reused' do
            # generate a new request
            on(host, "cd #{ca} && mkrequest -ip #{host_ip} #{one_time_password}")
            on(host, "cd #{ca} && sscep enroll -u http://$HOSTNAME:#{info[:http_port]}/ca/cgi-bin/pkiclient.exe -c ca.crt -k local.key -r local.csr -l cert2.crt", :accept_all_exit_codes => true)
            on(host, "ls #{ca}/cert2.crt", :acceptable_exit_codes => [2])
          end
        end
      end
    end
  end
end

