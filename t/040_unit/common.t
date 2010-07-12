use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 8;

use TestDataHandler;
use OAuth::Lite2::Server::Endpoint::Token;
use OAuth::Lite2::Agent::PSGIMock;
use OAuth::Lite2::Client::WebServer;
use OAuth::Lite2::Client::UsernameAndPassword;

TestDataHandler->clear();
TestDataHandler->add_client(id => q{foo}, secret => q{bar});
TestDataHandler->add_client(id => q{aaa}, secret => q{bbb});
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

$app->support_grant_types(qw(authorization_code));

my $agent = OAuth::Lite2::Agent::PSGIMock->new(app => $app);

my $invalid_client1 = OAuth::Lite2::Client::UsernameAndPassword->new(
    id                => q{foo},
    secret            => q{bar},
    access_token_uri  => q{http://localhost/access_token},
    agent             => $agent,
);

my $res;
$res = $invalid_client1->get_access_token(
    username => q{buz},
    password => q{hoge},
);
ok(!$res, q{response should be undef});
is($invalid_client1->errstr, q{unsupported_grant_type}, q{tried to use unsupported grant-type});

my $invalid_client2 = OAuth::Lite2::Client::WebServer->new(
    id                => q{invalid},
    secret            => q{bar},
    authorize_uri     => q{http://localhost/authorize},
    access_token_uri  => q{http://localhost/access_token},
    agent             => $agent,
);
$res = $invalid_client2->get_access_token(
    code         => q{buz},
    redirect_uri => q{http://example.org/callback},
);
ok(!$res, q{response should be undef});
is($invalid_client2->errstr, q{invalid_client}, q{invalid client_id});

my $invalid_client3 = OAuth::Lite2::Client::WebServer->new(
    id                => q{foo},
    secret            => q{invalid},
    authorize_uri     => q{http://localhost/authorize},
    access_token_uri  => q{http://localhost/access_token},
    agent             => $agent,
);
$res = $invalid_client3->get_access_token(
    code         => q{buz},
    redirect_uri => q{http://example.org/callback},
);
ok(!$res, q{response should be undef});
is($invalid_client3->errstr, q{invalid_client}, q{invalid client_secret});

my $invalid_client4 = OAuth::Lite2::Client::WebServer->new(
    id                => q{aaa},
    secret            => q{bbb},
    authorize_uri     => q{http://localhost/authorize},
    access_token_uri  => q{http://localhost/access_token},
    agent             => $agent,
);

$res = $invalid_client4->get_access_token(
    code         => q{buz},
    redirect_uri => q{http://example.org/callback},
);
ok(!$res, q{response should be undef});
is($invalid_client4->errstr, q{invalid_client}, q{This client isn't allowed to use this grant-type});


