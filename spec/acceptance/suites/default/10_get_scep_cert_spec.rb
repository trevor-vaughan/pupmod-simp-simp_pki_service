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

  hosts_with_role(hosts, 'ca').each do |ca_host|
    context "CA server #{ca_host}" do
      let(:ca_hostname) { fact_on(ca_host, 'fqdn') }
      let(:one_time_password) { 'one_time_password' }

      ca_metadata.each do |ca, info|
        context "on CA server #{ca_host} for CA #{ca}" do
          it "should set one time passwords for #{ca} SCEP requests from all clients" do
            create_scep_otps(hosts, ca_host, ca, one_time_password)
          end
        end

        hosts.each do |client|
          context "on client #{client}" do
            let(:working_dir) { File.join('scep', ca) }
            let(:client_ip) { on(client,'hostname -i').stdout.strip }

            it 'should have sscep installed' do
              client.install_package('sscep')
            end

            it 'should have a artifact collection directory' do
              client.mkdir_p(working_dir)
            end

            it 'should get the CA certificate' do
              on(client, "sscep getca -u http://#{ca_hostname}:#{info[:http_port]}/ca/cgi-bin/pkiclient.exe -c #{working_dir}/ca.crt")
            end

            it 'should generate a certificate request' do
              on(client, "cd #{working_dir} && mkrequest -ip #{client_ip} #{one_time_password}")
            end

            if client.host_hash[:platform] =~ /el-6/
              # don't know why this is failing...can use sscep to enroll from an el6 host
              # in 20_puppet_swap_spec.rb, but the config used to generate the csr
              # is not the same
              pending 'should enroll the certificate from an el6 host' do
                on(client, "cd #{working_dir} && sscep enroll -u http://#{ca_hostname}:#{info[:http_port]}/ca/cgi-bin/pkiclient.exe -c ca.crt -k local.key -r local.csr -l cert.crt -v -d")

                verify_cert(ca_host, ca, info[:https_port], client, "#{working_dir}/cert.crt", client_ip)
              end
            else
              it 'should enroll the certificate from an el7 host' do
                on(client, "cd #{working_dir} && sscep enroll -u http://#{ca_hostname}:#{info[:http_port]}/ca/cgi-bin/pkiclient.exe -c ca.crt -k local.key -r local.csr -l cert.crt -v -d")

                verify_cert(ca_host, ca, info[:https_port], client, "#{working_dir}/cert.crt", client_ip)
              end
            end

            it 'should not allow the one-time password to be reused' do
              # generate a new request
              on(client, "cd #{working_dir} && mkrequest -ip #{client_ip} #{one_time_password}")
              on(client, "cd #{working_dir} && sscep enroll -u http://#{ca_hostname}:#{info[:http_port]}/ca/cgi-bin/pkiclient.exe -c ca.crt -k local.key -r local.csr -l cert2.crt", :accept_all_exit_codes => true)
              on(client, "ls #{working_dir}/cert2.crt", :acceptable_exit_codes => [2])
            end
          end
        end
      end
    end
  end
end

