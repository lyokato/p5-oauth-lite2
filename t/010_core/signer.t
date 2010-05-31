use strict;
use warnings;

use Test::More tests => 9;

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
is($signed_params->{signature}, q{TJvmJLtkrnh94j1IotnLX4hybtkgu+leKM7H7tetu98=});
is($signed_params->{nonce},     q{s8djwd});
is($signed_params->{timestamp}, q{137131200});
is($signed_params->{algorithm}, q{hmac-sha256});

# TODO verify test
ok(OAuth::Lite2::Signer->verify({
    secret          => $access_token_secret,
    algorithm       => q{hmac-sha256},
    method          => q{get},
    url             => q{http://example.com/resource},
    nonce           => q{s8djwd},
    timestamp       => q{137131200},
    signature       => q{TJvmJLtkrnh94j1IotnLX4hybtkgu+leKM7H7tetu98=},
}), "correct signature");

ok(!OAuth::Lite2::Signer->verify({
    secret          => $access_token_secret,
    algorithm       => q{hmac-sha256},
    method          => q{get},
    url             => q{http://example.com/resource},
    nonce           => q{s8djwd},
    timestamp       => q{137131200},
    signature       => q{wOJIO9A2W5mFwDgiDvZbTSMK/PY=},
}), "incorrect signature");


$signed_params = OAuth::Lite2::Signer->sign({
    secret          => $access_token_secret,
    algorithm       => q{hmac-sha256},
    method          => q{get},
    url             => q{http://example.com/resource},
});
like($signed_params->{nonce},     qr/^[a-zA-Z0-9]+$/);
like($signed_params->{timestamp}, qr/^\d+$/);
is($signed_params->{algorithm}, q{hmac-sha256});
