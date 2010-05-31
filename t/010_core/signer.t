use strict;
use warnings;

use Test::More tests => 3;

use OAuth::Lite2::Signer;

# TODO check example variable
my $access_token_secret = "hoge";

my $signed_params = OAuth::Lite2::Signer->sign({
    secret          => $access_token_secret,
    algorithm       => q{hmac-sha256},
    method          => q{get},
    url             => q{http://example.com/resource},
    debug_nonce     => q{s8djwd},
    debug_timestamp => q{137131200},
});

#is($signed_params->{signature}, q{wOJIO9A2W5mFwDgiDvZbTSMK/PY=});
is($signed_params->{nonce},     q{s8djwd});
is($signed_params->{timestamp}, q{137131200});
is($signed_params->{algorithm}, q{hmac-sha256});

