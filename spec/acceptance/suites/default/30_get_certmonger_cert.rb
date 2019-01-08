require 'spec_helper_acceptance'
require 'erb'

test_name 'Client enroll via certmonger'

describe 'simp_pki_service' do
  cas = {
    'simp-pki-root'   => 4509,
    'simp-puppet-pki' => 5509,
    'simp-site-pki'   => 8443
  }


  let(:ca) { fact_on(hosts_with_role(hosts, 'ca').first, 'fqdn') }
  let(:nss_import_script) { File.join(File.dirname(__FILE__), 'files', 'nss_import.sh') }


  hosts_with_role(hosts, 'ca').each do |host|
    context "on CA #{host}" do
      let(:import_script) { '/root/nss_import.sh' }

      it 'should install NSS import script' do
begin
        scp_to(host, nss_import_script, import_script)
        on(host, "chmod +x #{import_script}")
rescue => e
require 'pry-byebug'
binding.pry
end
      end

      cas.each do |ca, https_port|
        it "should import #{ca} CA chains into its NSS database" do
begin
          # Only variable used by erb is ca
          on(host, "#{import_script} #{ca}")

          cert_list_cmd = "pki -d $HOME/.dogtag/#{ca}/ca/alias -C $HOME/.dogtag/#{ca}/ca/password.conf"
          cert_list_cmd += " -n \"caadmin\" -P https -p #{https_port} cert-find"
          on(host, cert_list_cmd)
#FIXME
#verify imported certs
rescue => e
require 'pry-byebug'
binding.pry
end
        end
      end
    end
  end
=begin

  hosts_with_role(hosts, 'server').each do |host|
    context "on server #{host}" do
      it 'should have the puppetserver installed' do
        install_package(host, 'puppetserver')
      end

      it 'should disable the puppetserver CA' do
        create_remote_file(
          host,
          '/etc/puppetlabs/puppetserver/services.d/ca.cfg',
          'puppetlabs.services.ca.certificate-authority-disabled-service/certificate-authority-disabled-service'
        )
      end
    end
  end

  hosts.each do |host|
    context "on #{host}" do
      let(:fqdn) { fact_on(host, 'fqdn') }

      it 'should have the latest puppet agent' do
        on(host, 'puppet resource package puppet-agent ensure=latest')
      end

      it 'should have sscep installed' do
        host.install_package('sscep')
      end

      it 'should have a working dir' do
        host.mkdir_p(working_dir)
      end

      it 'should generate a host private key' do
        on(host, "cd #{working_dir} && openssl genrsa -out #{fqdn}.key 4096")
      end

      it 'should generate a host CSR' do
        if host[:roles].include?('server')
          # Set up the cert the same way that Puppet usually does
          subject_alt_name = "subjectAltName = critical,DNS:#{fqdn},DNS:puppet.int.localdomain,DNS:puppet"
        else
          subject_alt_name = "subjectAltName = critical,DNS:#{fqdn}"
        end

        create_remote_file(
          host,
          "#{working_dir}/request.cfg",
          <<-EOM
[ req ]
prompt = no
distinguished_name = req_distinguished_name
attributes = req_attributes
req_extensions = v3_req

[ req_attributes ]
challengePassword=#{fqdn}

[ req_distinguished_name ]
CN = #{fqdn}

[ v3_req ]
basicConstraints = CA:FALSE
nsCertType = server, client, email, objsign
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
#{subject_alt_name}
          EOM
        )

        on(host, "cd #{working_dir} && openssl req -new -sha384 -key #{fqdn}.key -out #{fqdn}.csr -config request.cfg")
      end

      it 'should get the CA certificate chain' do
        on(host, %{sscep getca -u http://#{ca}:#{ca_metadata['simp-puppet-pki']['http_port']}/ca/cgi-bin/pkiclient.exe -c #{working_dir}/dogtag-ca.crt})
      end

      it 'should get the CA certificate chain' do
        # This bunch of nonsense pulls out the entire CA chain into the base
        # format that Puppet expects
        on(host, %{openssl s_client -host #{ca} -port 5509 -prexit -showcerts 2>/dev/null < /dev/null | awk '{FS="\\n"; RS="-.*CERTIFICATE.*-";}!seen[$0] && $0 ~ /MII/ {print "-----BEGIN CERTIFICATE-----"$0"-----END CERTIFICATE-----"} {++seen[$0]}' > #{working_dir}/dogtag-ca-chain.pem})
      end

      it 'should get the CA CRL' do
        on(host, %{curl -sk "https://#{ca}:#{ca_metadata['simp-puppet-pki']['https_port']}/ca/ee/ca/getCRL?op=getCRL&crlIssuingPoint=MasterCRL" | openssl crl -inform DER -outform PEM > #{working_dir}/dogtag-ca-crl.pem})
      end

      it 'should obtain a certificate from the CA' do
        on(host, %{cd #{working_dir} && sscep enroll -u http://#{ca}:#{ca_metadata['simp-puppet-pki']['http_port']}/ca/cgi-bin/pkiclient.exe -c dogtag-ca.crt -k #{fqdn}.key -r #{fqdn}.csr -l #{fqdn}.pem})
      end

      if host[:roles].include?('server')
        it 'should ensure that the puppetserver is stopped' do
          on(host, 'puppet resource service puppetserver ensure=stopped')
        end
      end

      it 'should replace the puppet certificates' do
        install_cmd = 'install -D -m 600 -o `puppet config print user` -g `puppet config print group`'

        on(host, %{cd #{working_dir} && #{install_cmd} #{fqdn}.pem `puppet config print hostcert --section agent`})
        on(host, %{cd #{working_dir} && #{install_cmd} #{fqdn}.key `puppet config print hostprivkey --section agent`})
        on(host, %{cd #{working_dir} && #{install_cmd} dogtag-ca-chain.pem `puppet config print localcacert --section agent`})
        on(host, %{cd #{working_dir} && #{install_cmd}  dogtag-ca-crl.pem `puppet config print hostcrl --section agent`})
        on(host, %{cd #{working_dir} && #{install_cmd} dogtag-ca-crl.pem `puppet config print ssldir --section master`/ca/ca_crl.pem})
      end

      it 'should set the puppet certname' do
        on(host, "puppet config set certname #{fqdn}")
      end

      # This is needed due to a bug in puppet and is documented at
      # https://puppet.com/docs/puppet/5.3/config_ssl_external_ca.html
      it 'should set CRL checking to false' do
        on(host, 'puppet config set certificate_revocation false')
      end

      if host[:roles].include?('server')
        it 'should ensure that the puppetserver is stopped' do
          on(host, 'puppet resource service puppetserver ensure=stopped')
        end
      end
    end
  end

  context 'when enabling puppet with DogTag PKI certs' do
    hosts_with_role(hosts, 'server').each do |host|
      it 'should ensure that the puppetserver is running' do
        on(host, 'puppet resource service puppetserver ensure=running')
      end
    end

    hosts.each do |host|
      context "on #{host}" do
        it 'should connect to the puppet server' do
          on(host, %{puppet config set server #{ca}})
          on(host, %{puppet agent -t})
        end
      end
    end
  end
=end
end