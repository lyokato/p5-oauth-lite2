use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 14;

use TestDataHandler;
use OAuth::Lite2::Server::Endpoint::Token;
use OAuth::Lite2::Agent::PSGIMock;
use OAuth::Lite2::Client::ClientCredentials;

TestDataHandler->clear;
TestDataHandler->add_client(id => q{foo}, secret => q{bar}, user_id => q{100});
TestDataHandler->add_user(username => q{buz}, password => q{hoge});
my $dh = TestDataHandler->new;

my $app = OAuth::Lite2::Server::Endpoint::Token->new(
    data_handler => "TestDataHandler",
);

$app->support_grant_types(qw(client_credentials refresh_token));

my $agent = OAuth::Lite2::Agent::PSGIMock->new(app => $app);

my $client = OAuth::Lite2::Client::ClientCredentials->new(
    id                => q{foo},
    secret            => q{bar},
    access_token_uri  => q{http://localhost/access_token},
    agent             => $agent,
);

my $res;
$res = $client->get_access_token();
ok($res, q{response should be not undef});
is($res->access_token, q{access_token_0});
is($res->refresh_token, q{refresh_token_0});
is($res->expires_in, q{3600});
ok(!$res->access_token_secret);
ok(!$res->scope);

$res = $client->refresh_access_token(
    refresh_token => q{invalid_refresh_token},
);
ok(!$res, q{response should be undef});
is($client->errstr, q{invalid_grant}, q{refresh-token should be invalid});

$res = $client->refresh_access_token(
    refresh_token => q{refresh_token_0},
);
ok($res, q{response should be not undef});
is($res->access_token, q{access_token_1});
is($res->refresh_token, q{refresh_token_0});
is($res->expires_in, q{3600});
ok(!$res->access_token_secret);
ok(!$res->scope);

