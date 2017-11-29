package OpenXPKI::Test::Role::CryptoLayer;
use Moose::Role;

=head1 NAME

OpenXPKI::Test::Role::CryptoLayer - Moose role that extends L<OpenXPKI::Test>
to be able to test the crypto layer

=cut

# Core modules

# CPAN modules

# Project modules

requires "config_writer";
requires "testenv_root";
requires 'also_init';

before 'init_additional_config' => sub { # ... so we do not overwrite user supplied configs
    my $self = shift;

    # do not overwrite existing node (e.g. inserted by OpenXPKI::Test::QA::Role::SampleConfig)
    if (not $self->config_writer->get_config_node("system.crypto.token.default", 1)) {
        $self->config_writer->add_user_config(
            "system.crypto.token.default" => {
                backend   => "OpenXPKI::Crypto::Backend::OpenSSL",
                api       => "OpenXPKI::Crypto::Backend::API",
                engine    => "OpenSSL",
                key_store => "OPENXPKI",
                shell     => "/usr/bin/openssl",
                wrapper   => "",
                randfile  => $self->testenv_root."/rand",
            },
        );
    }
};

before 'init_server' => sub {
    my $self = shift;
    # prepend to existing array in case a user supplied "also_init" needs our modules
    unshift @{ $self->also_init }, 'crypto_layer';
};

1;
