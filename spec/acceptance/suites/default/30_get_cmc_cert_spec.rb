require 'spec_helper_acceptance'

test_name 'Client enroll via CMC on CA server'

describe 'Client enroll via CMC on CA server' do
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
    let(:domain) { fact_on(ca_host, 'domain') }

    context "on CA server #{host}" do
      it 'should ensure the default NSS database exists' do
        results = on(ca_host, 'ls /root/.netscape', :accept_all_exit_codes => true)
        if results.exit_code != 0
          on(ca_host, 'mkdir /root/.netscape')
          # Creating a NSS DB without a password is not recommended for a real
          # system, but OK for this test
          on(ca_host, 'certutil -N --empty-password')
        end
      end

      ca_metadata.each do |ca, info|
        context "for CA #{ca}" do
          let(:cmcdir) { File.join('cmc', ca) }

          it 'should have a artifact collection directory' do
            ca_host.mkdir_p(cmcdir)
          end

          hosts.each do |client|
            context "for client '#{client}'" do
              let(:client_fqdn) { fact_on(client, 'fqdn') }
              let(:client_cn) do
                cn = "#{client_fqdn},ou=Hosts"
                domain.split('.').each do |part|
                  cn += ",dc=#{part}"
                end
                cn
              end

              let(:client_cert_request_file)   { File.join(cmcdir, "#{client}_cert.req") }
              let(:client_cmc_submit_cfg_file) { File.join(cmcdir, "#{client}_cmc_submit.cfg") }
              let(:client_cmc_response_file)   { File.join(cmcdir, "#{client}_cmc_response.bin") }
              let(:client_cert_file)           { File.join(cmcdir, "#{client}_cert.pem") }

              it 'should create a certificate request' do
                # seed file needs to be at least 20 bytes in length, so
                # one 512-byte block will be more than enough
                seed_file = File.join(cmcdir, 'seed')
                on(ca_host, "dd if=/dev/urandom of=#{seed_file} count=1")
                cmd = [
                  'certutil -R',
                  "-s \"cn=#{client_cn}\"",
                  '-k rsa',
                  '-g 4096',
                  '-Z SHA384',
                  "-z #{seed_file}",
                  "-o #{client_cert_request_file}"
                ]
                on(ca_host, cmd.join(' '))
              end

              it 'should prepare CMC files for the request' do
                cfg = {
                  :ca => {
                    :host       => ca_host,
                    :name       => ca,
                    :https_port => info[:https_port],
                    :password   => on(ca_host, "cat  /root/.dogtag/#{ca}/ca/password.conf").stdout
                  },
                  :files => {
                    :cert_request    => client_cert_request_file,
                    :cmc_request_cfg => client_cmc_submit_cfg_file.gsub(/submit/,'request'),
                    :cmc_request     => client_cmc_response_file.gsub(/response/,'request'),
                    :cmc_submit_cfg  => client_cmc_submit_cfg_file,
                    :cmc_response    => client_cmc_response_file
                  }
                }
                generate_cmc_request_files(cfg)
              end

              it 'should submit the request using CMC' do
                on(ca_host, "HttpClient #{client_cmc_submit_cfg_file}")

                cmd = [
                 'CMCResponse',
                 "-d /root/.dogtag/#{ca}/ca/alias",
                 "-i #{client_cmc_response_file}",
                 "> #{client_cert_file}"
                 ]
                on(ca_host, cmd.join(' '))

                verify_cert(ca_host, ca, info[:https_port], ca_host, client_cert_file, cert_cn)
              end
            end
          end
        end
      end
    end
  end
end
