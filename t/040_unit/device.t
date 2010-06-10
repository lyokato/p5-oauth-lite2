use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 14;

use TestDataHandler;
use OAuth::Lite2::Server::Endpoint::Token;
use OAuth::Lite2::Agent::PSGIMock;
use OAuth::Lite2::Client::Device;

TestDataHandler->clear;
TestDataHandler->add_client(id => q{foo}, secret => q{bar});
TestDataHandler->add_user(username => q{buz}, password => q{hoge});
my $dh = TestDataHandler->new;

my $app = OAuth::Lite2::Server::Endpoint::Token->new(
    data_handler => "TestDataHandler",
);

$app->support_flows(qw(device));

my $agent = OAuth::Lite2::Agent::PSGIMock->new(app => $app);

my $invalid_client1 = OAuth::Lite2::Client::Device->new(
    id                => q{invalid},
    #secret            => q{bar},
    access_token_url  => q{http://localhost/access_token},
    agent             => $agent,
);

my $res;
$res = $invalid_client1->get_code();
ok(!$res, q{response should be undef});
is($invalid_client1->errstr, q{invalid_client}, q{client id should be invalid});

my $client = OAuth::Lite2::Client::Device->new(
    id                => q{foo},
    #secret            => q{bar},
    access_token_url  => q{http://localhost/access_token},
    agent             => $agent,
);

$res = $client->get_code();
ok($res, $client->errstr);
like($res->code, qr{^ver_.+$});
like($res->user_code, qr{^user_.+$});
is($res->verification_uri, q{http://example.org/verification});
is($res->expires_in, q{3600});
ok(!$res->interval);

my $code = $res->code;

# instead of authorization by user-interaction,
# create new auth_info data.
$dh->create_or_update_auth_info(
    client_id => q{foo},
    user_id   => q{buz},
    code      => $code,
);

my $token = $client->get_access_token(
    code => q{invalid},
);
ok(!$token, q{token response should be empty});
is($client->errstr, q{bad_verification_code}, q{code should be invalid});

$token = $client->get_access_token(
    code => $code,
);
ok($token, q{token response should not be empty});
is($token->access_token, q{access_token_0}, q{access_token is correct});
is($token->refresh_token, q{refresh_token_0}, q{refresh_token is correct});
is($token->expires_in, q{3600}, q{expires_in is correct});

