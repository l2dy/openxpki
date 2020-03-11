## OpenXPKI::Server::Authentication::CAS.pm
##
## (C) Copyright 2020 by Zero King

package OpenXPKI::Server::Authentication::CAS;

use strict;
use warnings;

use OpenXPKI::Debug;
use OpenXPKI::Exception;
use OpenXPKI::Server::Context qw( CTX );

use LWP::UserAgent;

## constructor and destructor stuff

sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {};

    bless $self, $class;

    my $path = shift;
    my $config = CTX('config');

    ##! 2: "load name and description for handler"

    my @path = split /\./, $path;
    push @path, 'user';
    $self->{PREFIX} = \@path;
    $self->{DESC} = $config->get("$path.description");
    $self->{NAME} = $config->get("$path.label");
    $self->{ROLE} = $config->get("$path.role");

    return $self;
}

sub login_step {
    ##! 1: 'start'
    my $self    = shift;
    my $arg_ref = shift;

    my $name    = $arg_ref->{HANDLER};
    my $msg     = $arg_ref->{MESSAGE};

    if (! exists $msg->{PARAMS}->{TICKET} ||
        ! exists $msg->{PARAMS}->{CAS_URL}) {
        ##! 4: 'no login data received (yet)'
        return (undef, undef,
            {
        SERVICE_MSG => "GET_PASSWD_LOGIN",
        PARAMS      => {
                    NAME        => $self->{NAME},
                    DESCRIPTION => $self->{DESC},
            },
            },
        );
    }


    ##! 2: 'login data received'
    my $role;
    my $casTicket = $msg->{PARAMS}->{TICKET};
    my $casURL = $msg->{PARAMS}->{CAS_URL};
    $casURL =~ s{/login\?}{/serviceValidate?}s;

    my $ua = LWP::UserAgent->new();
    my $casGet;
    my $response;
    my $account;

    # check account - the handler config has a connector at .user
    # that returns password or password and role for a requested username

    $casGet = "$casURL&ticket=$casTicket";
    $response = $ua->get($casGet);

    ## do not let users with non-ASCII characters in their username
    ## log in, as this will cause a crash on the web interface. This
    ## is a known bug (#1909037), and this code is here as a workaround
    ## until it is fixed.
    if ($response->content =~ /<cas:user>([a-z0-9]+)<\/cas:user>/) {
        $account = $1;
    }

    CTX('log')->auth()->debug('CAS login - serviceValidate - ticket is ' . $casTicket );

    if (!$account) {
        ##! 4: "No such user: $account"
        OpenXPKI::Exception->throw (
            message => "I18N_OPENXPKI_SERVER_AUTHENTICATION_PASSWORD_LOGIN_FAILED",
            params  => {
              USER => $account,
            },
        );
    }

    my $userinfo;
    if (!$self->{ROLE}) {
        $userinfo = CTX('config')->get_hash( [ @{$self->{PREFIX}}, $account ] );
        $role = $userinfo->{role} || 'User';
        delete $userinfo->{role};
    } else {
        $role =  $self->{ROLE};
    }

    return ($account, $role,
        {
            SERVICE_MSG => 'SERVICE_READY',
        },
        $userinfo
    );
}


1;
__END__

=head1 Name

OpenXPKI::Server::Authentication::CAS - CAS authentication.

=head1 Description

This is the class which supports OpenXPKI with CAS authentication.
The parameters are passed as a hash reference.

=head1 Functions

=head2 new

is the constructor. It requires the config prefix as single argument.
This is the minimum parameter set for any authentication class.

When no I<role> is set in the configuration, the configuration must return
a hash for each user holding I<role>, any additonal fields of the hash are
returned as I<userinfo>.

If you add the I<role> parameter to the config, the configuration must return
a scalar value for each username representing the digest.

=head2 login_step

returns a pair of (user, role, response_message) for a given login
step. If user and role are undefined, the login is not yet finished.
