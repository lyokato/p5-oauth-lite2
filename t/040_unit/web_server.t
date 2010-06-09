use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 22;

use TestDataHandler;
use OAuth::Lite2::Server::Endpoint::Token;
use OAuth::Lite2::Agent::PSGIMock;
use OAuth::Lite2::Client::WebServer;

TestDataHandler->add_client(id => q{foo}, secret => q{bar});
TestDataHandler->add_user(username => q{buz}, password => q{hoge});
my $dh = TestDataHandler->new;

# set authorization-fixture-data instead of user interaction
my $auth_info = $dh->create_or_update_auth_info(
    client_id    => q{foo},
    user_id      => q{buz},
    scope        => q{email},
    redirect_uri => q{http://example.org/callback},
    code         => q{valid_code},
);

my $app = OAuth::Lite2::Server::Endpoint::Token->new(
    data_handler => "TestDataHandler",
);

$app->support_flows(qw(web_server));

my $agent = OAuth::Lite2::Agent::PSGIMock->new(app => $app);

my $client = OAuth::Lite2::Client::WebServer->new(
    id                => q{foo},
    secret            => q{bar},
    authorize_url     => q{http://localhost/authorize},
    access_token_url  => q{http://localhost/access_token},
    agent             => $agent,
);

# format "json"
my $res = $client->get_access_token(
    code         => q{invalid_code},
    redirect_uri => q{http://example.org/callback},
);

ok(!$res, q{response should be undef});
is($client->errstr, q{bad_verification_code}, q{verification code should be invalid});

# format "xml"
$res = $client->get_access_token(
    code         => q{invalid_code},
    redirect_uri => q{http://example.org/callback},
    format       => q{xml},
);

ok(!$res, q{response should be undef});
is($client->errstr, q{bad_verification_code}, q{verification code should be invalid});

# format "form"
$res = $client->get_access_token(
    code         => q{invalid_code},
    redirect_uri => q{http://example.org/callback},
    format       => q{form},
);

ok(!$res, q{response should be undef});
is($client->errstr, q{bad_verification_code}, q{verification code should be invalid});

$res = $client->get_access_token(
    code         => q{valid_code},
    redirect_uri => q{http://invalid.example.org/callback},
);
ok(!$res, q{response should be undef});
is($client->errstr, q{redirect_uri_mismatch}, q{redirect_uri should be invalid});


$res = $client->get_access_token(
    code         => q{valid_code},
    redirect_uri => q{http://example.org/callback},
);

ok($res, q{response should be not undef});
is($res->access_token, q{access_token_0});
is($res->refresh_token, q{refresh_token_0});
is($res->expires_in, q{3600});
ok(!$res->access_token_secret);
is($res->scope, q{email});

$res = $client->get_access_token(
    code         => q{valid_code},
    redirect_uri => q{http://example.org/callback},
    secret_type  => q{hmac-sha1},
);
ok(!$res, q{response should be undef});
is($client->errstr, q{unsupported_secret_type}, q{secret_type should be invalid});

$res = $client->get_access_token(
    code         => q{valid_code},
    redirect_uri => q{http://example.org/callback},
    secret_type  => q{hmac-sha256},
);
ok($res, q{response should be not undef});
is($res->access_token, q{access_token_2});
is($res->refresh_token, q{refresh_token_0});
is($res->expires_in, q{3600});
is($res->access_token_secret, q{access_token_secret_2});
is($res->scope, q{email});
