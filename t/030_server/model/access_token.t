use strict;
use warnings;

use Test::More tests => 3;

use lib 't/lib';

use TestAccessToken;

# auth_id token
# expires_in, created_on, secret secret_type

my $token1 = TestAccessToken->new(
    auth_id => q{foo},
    token   => q{bar},
    extra   => q{buz},
);

is($token1->auth_id, q{foo});
is($token1->token, q{bar});
is($token1->extra, q{buz});


