
use strict;
use warnings;
use English;
use Test::More;
# use Smart::Comments;

if( not exists $ENV{NCIPHER_LIBRARY} or
    not exists $ENV{CHIL_LIBRARY} or
    not exists $ENV{NCIPHER_KEY} or
    not -e $ENV{CHIL_LIBRARY} or
    not -e $ENV{NCIPHER_LIBRARY})
{
    plan skip_all => 'nCipher is not available (no environment variables NCIPHER_LIBRARY, CHIL_LIBRARY and NCIPHER_KEY)';
}
else
{
    plan tests => 24;
    print STDERR "OpenXPKI::Crypto::Command: Create CA and user certs and issue a CRL with nCipher\n";
}

use OpenXPKI qw( read_file write_file );
use OpenXPKI::Crypto::TokenManager;
use OpenXPKI::Crypto::Profile::Certificate;
use OpenXPKI::Crypto::Profile::CRL;
use OpenXPKI::Crypto::PKCS7;
use Time::HiRes;

our $cache;
our $basedir;
eval `cat t/25_crypto/common.pl`;
ok(1);

## parameter checks for TokenManager init

my $mgmt = OpenXPKI::Crypto::TokenManager->new ();
ok (1);

#------------------------CA-----------------------------------------------
my $ca_id = "INTERNAL_CA_NCIPH"; 
my $cn = $ca_id;
$cn =~ s{ INTERNAL_ }{}xms;

my $dir = lc($cn);
$dir =~ s{ _ }{}xms;

my $ca_token = $mgmt->get_token (TYPE => "CA", 
  		                 ID => $ca_id, 
		                 PKI_REALM => "Test nCipher Root CA"
	);
ok (1);

## try to create token key
eval
{
    my $hsm_key = $ca_token->command ({COMMAND    => "create_key",
                                       TYPE       => "RSA",
		    	               PASSWD     => "1234567890",
				       PARAMETERS => {
				               KEY_LENGTH => "1024",
				               ENC_ALG    => "aes256"}});
}; 

if ($EVAL_ERROR) {
    if (my $exc = OpenXPKI::Exception->caught())
    {
        print STDERR "OpenXPKI::Exception => ".$exc->as_string()."\n" if ($ENV{DEBUG});
        ok(1);                        
    }
    else                              
    {
        print STDERR "Unknown eval error: ${EVAL_ERROR}\n" if ($ENV{DEBUG});
        ok(0);
    }
}                                      
else
{
    print STDERR "Eval error does not occur when trying to create CA key in HSM\n" if ($ENV{DEBUG});
    ok(0);            
} 

## create CA CSR
my $ca_csr = $ca_token->command ({COMMAND => "create_pkcs10",
	                          SUBJECT => "cn=$cn,dc=OpenXPKI,dc=info"});
ok (1);
print STDERR "CA CSR: $ca_csr\n" if ($ENV{DEBUG});
    
## create profile
my $ca_profile = OpenXPKI::Crypto::Profile::Certificate->new (
	CONFIG    => $cache,
	PKI_REALM => "Test nCipher Root CA",
	CA        => $ca_id,
	TYPE      => "SELFSIGNEDCA");
$ca_profile->set_serial(1);
ok(1);
print STDERR "Profile is created\n" if ($ENV{DEBUG});

### profile: $profile
    
## create CA cert
my $ca_cert = $ca_token->command ({COMMAND => "create_cert",
	                           PROFILE => $ca_profile,
				   CSR     => $ca_csr});
ok (1);
print STDERR "CA cert: $ca_cert\n" if ($ENV{DEBUG});

# FIXME: create_cert should not write the text representation of the
# cert to the file specified in the configuration
OpenXPKI->write_file (
	FILENAME => "$basedir/$dir/cacert.pem", 
	CONTENT  => $ca_cert,
	FORCE    => 1,
);

## check that the CA is ready for further tests

if (not -e "$basedir/$dir/cacert.pem")
{
    ok(0);
    print STDERR "Missing CA cert\n";
} else {
    ok(1);
}

#----------------------USER-----------------------------------------------

## parameter checks for get_token
my $token = $mgmt->get_token (TYPE => "DEFAULT",
                              PKI_REALM => "Test nCipher Root CA");
ok (1);

## create PIN - just want to check if filter_stdout works correctly
my $passwd = $token->command ({COMMAND       => "create_random",
                               RANDOM_LENGTH => 16});
ok (1);
print STDERR "passwd: $passwd\n" if ($ENV{DEBUG});
OpenXPKI->write_file (FILENAME => "$basedir/$dir/passwd.txt", CONTENT => $passwd);

## create RSA key
my $key = $token->command ({COMMAND    => "create_key",
                            TYPE       => "RSA",
                            PASSWD     => $passwd,
                            PARAMETERS => {
			            KEY_LENGTH => 1024,
                                    ENC_ALG    => "aes256"}});
ok (1);
print STDERR "RSA: $key\n" if ($ENV{DEBUG});
OpenXPKI->write_file (FILENAME => "$basedir/$dir/key.pem", CONTENT => $key);

## create profile
my $profile = OpenXPKI::Crypto::Profile::Certificate->new (
                  CONFIG    => $cache,
                  PKI_REALM => "Test nCipher Root CA",
                  TYPE      => "ENDENTITY",
                  CA        => "INTERNAL_CA_NCIPH",
                  ID        => "User",
	      );

## create CSR
my $subject = "cn=John Doe,dc=OpenXPKI,dc=org";
my $csr = $token->command ({COMMAND => "create_pkcs10",
                            KEY     => $key,
                            PASSWD  => $passwd,
                            SUBJECT => $subject});
ok (1);
print STDERR "CSR: $csr\n" if ($ENV{DEBUG});
OpenXPKI->write_file (FILENAME => "$basedir/$dir/pkcs10.pem", CONTENT => $csr);

$profile->set_serial  (1);
$profile->set_subject ($subject);
ok(1);

## create cert
my $cert = $ca_token->command ({COMMAND => "issue_cert",
                                CSR     => $csr,
                                PROFILE => $profile});
ok (1);
print STDERR "cert: $cert\n" if ($ENV{DEBUG});
OpenXPKI->write_file (FILENAME => "$basedir/$dir/cert.pem", CONTENT => $cert);

## build the PKCS#12 file
 my $pkcs12 = $token->command ({COMMAND => "create_pkcs12",
                                PASSWD  => $passwd,
                                KEY     => $key,
                                CERT    => $cert,
                                CHAIN   => $token->get_certfile()});
ok (1);
print STDERR "PKCS#12 length: ".length ($pkcs12)."\n" if ($ENV{DEBUG});

### create CRL profile...
$profile = OpenXPKI::Crypto::Profile::CRL->new (
                  CONFIG    => $cache,
                  PKI_REALM => "Test nCipher Root CA",
                  CA        => "INTERNAL_CA_NCIPH");
### issue crl...
my $crl = $ca_token->command ({COMMAND => "issue_crl",
                               REVOKED => [$cert],
                               PROFILE => $profile});
print STDERR "CRL: $crl\n" if ($ENV{DEBUG});
OpenXPKI->write_file (FILENAME => "$basedir/$dir/crl.pem", CONTENT => $crl);
ok (1);

1;
#-----------PKCS7------------------------------
print STDERR "OpenXPKI::Crypto::PKCS7\n" if ($ENV{DEBUG});

my $content = "This is for example a passprase.";

## sign content

my $pkcs7 = OpenXPKI::Crypto::PKCS7->new (TOKEN => $ca_token, CONTENT => $content);
my $sig = $pkcs7->sign (CERT      => $ca_cert);
ok(1);
print STDERR "PKCS#7 signature: $sig\n" if ($ENV{DEBUG});

## encrypt content

$content = $pkcs7->encrypt (CERT      => $ca_cert );
ok(1);
print STDERR "PKCS#7 encryption: $content\n" if ($ENV{DEBUG});

## decrypt content

$content = $pkcs7->decrypt (CERT   => $ca_cert );
ok(1);
print STDERR "PKCS#7 content: $content\n" if ($ENV{DEBUG});
ok ($content eq "This is for example a passprase.");

## verify signature

$pkcs7 = OpenXPKI::Crypto::PKCS7->new (TOKEN => $ca_token, CONTENT => $content, PKCS7 => $sig);
my $result = $pkcs7->verify ();
ok(1);
print STDERR "PKCS#7 verify: $result\n" if ($ENV{DEBUG});

## extract available chain from signature

$result = $pkcs7->get_chain();
ok(1);
print STDERR "PKCS#7 get_chain: ".scalar @{$result}."\n" if ($ENV{DEBUG});

## performance

my $items = 5;
my $begin = [ Time::HiRes::gettimeofday() ];
for (my $i=0; $i<$items; $i++)
{
    $pkcs7 = OpenXPKI::Crypto::PKCS7->new (TOKEN => $ca_token, CONTENT => $content, PKCS7 => $sig);
    $pkcs7->verify();
    $pkcs7->get_chain();
}
ok (1);
$result = Time::HiRes::tv_interval( $begin, [Time::HiRes::gettimeofday()]);
$result = $items / $result;
$result *= 60.0; 
print STDERR " = $result signatures/minute (minimum: 5 per minute)\n";
#ok ($result > 17);
ok ($result);

1;
