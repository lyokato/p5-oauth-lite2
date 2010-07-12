use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 18;

use TestDataHandler;
use OAuth::Lite2::Server::Endpoint::Token;
use OAuth::Lite2::Agent::PSGIMock;
use OAuth::Lite2::Client::UsernameAndPassword;

TestDataHandler->clear;
TestDataHandler->add_client(id => q{foo}, secret => q{bar});
TestDataHandler->add_user(username => q{buz}, password => q{hoge});
my $dh = TestDataHandler->new;

my $app = OAuth::Lite2::Server::Endpoint::Token->new(
    data_handler => "TestDataHandler",
);

$app->support_grant_types(qw(basic-credentials refresh-token));

my $agent = OAuth::Lite2::Agent::PSGIMock->new(app => $app);

my $client = OAuth::Lite2::Client::UsernameAndPassword->new(
    id                => q{foo},
    secret            => q{bar},
    access_token_uri  => q{http://localhost/access_token},
    agent             => $agent,
);

my $res;
$res = $client->get_access_token(
    username => q{invalid},
    password => q{hoge},
);
ok(!$res, q{response should be undef});
is($client->errstr, q{invalid-grant}, q{user should be invalid});

$res = $client->get_access_token(
    username => q{buz},
    password => q{invalid},
);
ok(!$res, q{response should be undef});
is($client->errstr, q{invalid-grant}, q{user should be invalid});

$res = $client->get_access_token(
    username => q{buz},
    password => q{hoge},
);
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
is($client->errstr, q{invalid-grant}, q{refresh-token should be invalid});

$res = $client->refresh_access_token(
    refresh_token => q{refresh_token_0},
);
ok($res, q{response should be not undef});
is($res->access_token, q{access_token_1});
is($res->refresh_token, q{refresh_token_0});
is($res->expires_in, q{3600});
ok(!$res->access_token_secret);
ok(!$res->scope);

