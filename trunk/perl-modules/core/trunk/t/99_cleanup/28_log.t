use strict;
use warnings;
use Test::More;

my @files = (             
             "t/28_log/openxpki.log",
            );

## 2 * number of files
plan tests => (scalar @files) * 2;

diag "OpenXPKI::Crypto Cleanup\n" if $ENV{VERBOSE};

foreach my $filename (@files)
{
    ok(! -e $filename || unlink ($filename), 'file does not exist or can be removed');
    ok(! -e $filename, 'file does not exist');
}

1;
