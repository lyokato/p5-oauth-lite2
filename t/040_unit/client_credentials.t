use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 24;

use TestDataHandler;
use OAuth::Lite2::Server::Endpoint::Token;
use OAuth::Lite2::Agent::PSGIMock;
use OAuth::Lite2::Client::ClientCredentials;

TestDataHandler->clear;
TestDataHandler->add_client(id => q{foo}, secret => q{bar});
TestDataHandler->add_user(username => q{buz}, password => q{hoge});
my $dh = TestDataHandler->new;

my $app = OAuth::Lite2::Server::Endpoint::Token->new(
    data_handler => "TestDataHandler",
);

$app->support_flows(qw(client_credentials));

my $agent = OAuth::Lite2::Agent::PSGIMock->new(app => $app);

my $invalid_client1 = OAuth::Lite2::Client::ClientCredentials->new(
    id                => q{invalid},
    secret            => q{bar},
    access_token_url  => q{http://localhost/access_token},
    agent             => $agent,
);

my $res;
$res = $invalid_client1->get_access_token();
ok(!$res, q{response should be undef});
is($invalid_client1->errstr, q{invalid_client}, q{client id should be invalid});

my $invalid_client2 = OAuth::Lite2::Client::ClientCredentials->new(
    id                => q{foo},
    secret            => q{invalid},
    access_token_url  => q{http://localhost/access_token},
    agent             => $agent,
);
$res = $invalid_client2->get_access_token();
ok(!$res, q{response should be undef});
is($invalid_client2->errstr, q{invalid_client}, q{client secret should be invalid});

$res = $invalid_client2->get_access_token();
my $client = OAuth::Lite2::Client::ClientCredentials->new(
    id                => q{foo},
    secret            => q{bar},
    access_token_url  => q{http://localhost/access_token},
    agent             => $agent,
);

$res = $client->get_access_token();
ok($res, q{response should be not undef});
is($res->access_token, q{access_token_0});
is($res->refresh_token, q{refresh_token_0});
is($res->expires_in, q{3600});
ok(!$res->access_token_secret);
ok(!$res->scope);

$res = $client->get_access_token(
    secret_type  => q{hmac-sha1},
);
ok(!$res, q{response should be undef});
is($client->errstr, q{unsupported_secret_type}, q{secret_type should be invalid});

$res = $client->get_access_token(
    secret_type  => q{hmac-sha256},
);
ok($res, q{response should be not undef});
is($res->access_token, q{access_token_2});
is($res->refresh_token, q{refresh_token_2});
is($res->expires_in, q{3600});
is($res->access_token_secret, q{access_token_secret_2});
ok(!$res->scope);

$res = $client->refresh_access_token(
    refresh_token => q{refresh_token_2},
);
ok($res, q{response should be not undef});
is($res->access_token, q{access_token_3});
is($res->refresh_token, q{refresh_token_2});
is($res->expires_in, q{3600});
ok(!$res->access_token_secret);
ok(!$res->scope);

