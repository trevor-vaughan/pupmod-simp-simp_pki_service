require 'spec_helper_acceptance'
=begin

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


  hosts_with_role(hosts, 'ca').each do |ca_host|
    context "on CA #{host}" do
      it 'should set one time passwords for simp-site-pki SCEP requests from all clients' do
        create_scep_otps(hosts, ca_host, 'simp-site-pki', 'one_time_password')
      end
    end
  end

  describe 'CA client set up' do
    hosts.each do |host|
      it 'should install, start, and enable certmonger' do
        host.install_package('certmonger')
        on(host, 'puppet resource service certmonger ensure=running')
        on(host, 'puppet resource service certmonger enable=true')
      end

      it 'should obtain CA root certificate' do
      end

      it 'should obtain CA certificate chain' do
      end
    end
  end

  hosts.each do |host|
    context "on #{host}" do
      let(:fqdn) { fact_on(host, 'fqdn') }

      it 'should have a working dir' do
        host.mkdir_p(working_dir)
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

    end
  end

end
=end
