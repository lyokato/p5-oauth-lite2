use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 1;

use TestDataHandler;
use OAuth::Lite2::Server::Endpoint::Token;
use OAuth::Lite2::Agent::PSGIMock;
use OAuth::Lite2::Client::WebServer;

TestDataHandler->add_client(id => q{foo}, secret => q{bar});
TestDataHandler->add_user(username => q{buz}, password => q{hoge});
my $dh = TestDataHandler->new;

# set authorization-fixture-data instead of user interaction
my $auth_info = $dh->create_or_update_auth_info(
    clinet_id    => q{foo},
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
    format            => q{json},
    authorize_url     => q{http://localhost/authorize},
    access_token_url  => q{http://localhost/access_token},
    agent             => $agent,
);

my $res = $client->get_access_token(
    code         => q{foba},
    redirect_uri => q{fuba},
    #secret_type  => q{},
    #format       => q{xml},
    #url          => q{},
);

# is($res->access_token, "");
# is($res->refresh_token, "");
# is($res->expires_in, "3600");
