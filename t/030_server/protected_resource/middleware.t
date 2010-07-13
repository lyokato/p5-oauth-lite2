use strict;
use warnings;

use Test::More tests => 14;

use TestPR;
use TestDataHandler;
use Try::Tiny;
use HTTP::Response;
use HTTP::Request;
use HTTP::Message::PSGI;

TestDataHandler->clear;
TestDataHandler->add_client(id => q{foo},       secret => q{secret_value});
TestDataHandler->add_client(id => q{bar},       secret => q{secret_value});
TestDataHandler->add_client(id => q{malformed}, secret => q{secret_value});

my $dh = TestDataHandler->new;

my $auth_info = $dh->create_or_update_auth_info(
    client_id    => q{foo},
    user_id      => q{1},
    scope        => q{email},
    code         => q{code_bar},
    redirect_uri => q{http://example.org/callback},
);

my $access_token = $dh->create_or_update_access_token(
    auth_info => $auth_info,
);

my $auth_info2 = $dh->create_or_update_auth_info(
    client_id    => q{bar},
    user_id      => q{1},
    scope        => q{email},
    code         => q{code_bar},
    redirect_uri => q{http://example.org/callback},
);

my $access_token2 = $dh->create_or_update_access_token(
    auth_info  => $auth_info2,
    expires_in => 1,
);

my $auth_info3 = $dh->create_or_update_auth_info(
    client_id    => q{malformed},
    user_id      => q{1},
    scope        => q{email},
    code         => q{code_bar},
    redirect_uri => q{http://example.org/callback},
);

my $access_token3 = $dh->create_or_update_access_token(
    auth_info => $auth_info3,
);

my $auth_info4 = $dh->create_or_update_auth_info(
    client_id    => q{foo},
    user_id      => q{666},
    scope        => q{email},
    code         => q{code_bar},
    redirect_uri => q{http://example.org/callback},
);

my $access_token4 = $dh->create_or_update_access_token(
    auth_info => $auth_info4,
);

my $app = TestPR->new;

sub request {
    my $req = shift;
    my $res = try {
        HTTP::Response->from_psgi($app->($req->to_psgi));
    } catch {
        HTTP::Response->from_psgi([500, ["Content-Type" => "text/plain"], [ $_ ]]);
    };
    return $res;
}


my ($req, $res);
$req = HTTP::Request->new("GET" => q{http://example.org/});
$req->header("Authorization" => sprintf(q{OAuth %s}, 'invalid_access_token'));
$res = &request($req);
ok(!$res->is_success, 'request should fail');
is($res->code, 401, 'invalid access token');
is($res->header("WWW-Authenticate"), q{OAuth realm='resource.example.org', error='invalid_token'}, 'invalid access token');

sleep 2;
$req = HTTP::Request->new("GET" => q{http://example.org/});
$req->header("Authorization" => sprintf(q{OAuth %s}, $access_token2->token));
$res = &request($req);
ok(!$res->is_success, 'request should fail');
is($res->code, 401, 'expired access token');
is($res->header("WWW-Authenticate"), q{OAuth realm='resource.example.org', error='expired_token'}, 'expired token');


$req = HTTP::Request->new("GET" => q{http://example.org/});
$req->header("Authorization" => sprintf(q{OAuth %s}, $access_token3->token));
$res = &request($req);
ok(!$res->is_success, 'request should fail');
is($res->code, 401, 'invalid client');
is($res->header("WWW-Authenticate"), q{OAuth realm='resource.example.org', error='invalid_token'}, 'invalid client');

$req = HTTP::Request->new("GET" => q{http://example.org/});
$req->header("Authorization" => sprintf(q{OAuth %s}, $access_token4->token));
$res = &request($req);
ok(!$res->is_success, 'request should fail');
is($res->code, 401, 'invalid client');
is($res->header("WWW-Authenticate"), q{OAuth realm='resource.example.org', error='invalid_token'}, 'invalid client');

$req = HTTP::Request->new("GET" => q{http://example.org/});
$req->header("Authorization" => sprintf(q{OAuth %s}, $access_token->token));
$res = &request($req);
ok($res->is_success, 'request should not fail');
is($res->content, q{{user: '1', scope: 'email'}}, 'successful response');
