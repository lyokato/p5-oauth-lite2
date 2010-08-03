use strict;
use warnings;

use Test::More tests => 4; 

use lib 't/lib';

use TestAuthInfo;

# id user_id client_id
# scope refresh_token code redirect_uri
# extra

my $info1 = TestAuthInfo->new(
    id        => q{foo},
    user_id   => q{bar},
    client_id => q{buz},
    extra     => q{hoge},
);
is($info1->id,        q{foo});
is($info1->user_id,   q{bar});
is($info1->client_id, q{buz});
is($info1->extra,     q{hoge});

