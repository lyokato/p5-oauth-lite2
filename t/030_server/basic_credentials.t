use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 10;

use Plack::Request;
use Try::Tiny;
use TestDataHandler;
use OAuth::Lite2::Server::Context;
use OAuth::Lite2::Server::GrantHandler::BasicCredentials;
use OAuth::Lite2::Util qw(build_content);

TestDataHandler->clear;
TestDataHandler->add_client(id => q{foo}, secret => q{bar});
TestDataHandler->add_user(username => q{user_1}, password => q{pass_1});
my $dh = TestDataHandler->new;

my $auth_info = $dh->create_or_update_auth_info(
    client_id => q{foo},
    user_id   => q{1},
    scope     => q{email},
);

is($auth_info->refresh_token, "refresh_token_0");

my $action = OAuth::Lite2::Server::GrantHandler::BasicCredentials->new;

sub test_success {
    my $params = shift;
    my $expected = shift;
    my $request = Plack::Request->new({
        REQUEST_URI    => q{http://example.org/resource},
        REQUEST_METHOD => q{GET},
        QUERY_STRING   => build_content($params),
    });
    my $ctx = OAuth::Lite2::Server::Context->new({
        request      => $request,
        data_handler => $dh,
    });
    my $res; try {
        $res = $action->handle_request($ctx);
    } catch {
        my $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };

    if(exists $expected->{token}) {
        is($res->{access_token}, $expected->{token});
    } else {
        ok(!$res->{access_token});
    }

    if(exists $expected->{secret}) {
        is($res->{access_token_secret}, $expected->{secret});
    } else {
        ok(!$res->{access_token_secret});
    }

    if(exists $expected->{expires_in}) {
        is($res->{expires_in}, $expected->{expires_in});
    } else {
        ok(!$res->{expires_in});
    }

    if(exists $expected->{refresh_token}) {
        is($res->{refresh_token}, $expected->{refresh_token});
    } else {
        ok(!$res->{refresh_token});
    }

    if(exists $expected->{secret_type}) {
        is($res->{secret_type}, $expected->{secret_type});
    } else {
        ok(!$res->{secret_type});
    }

}

sub test_error {
    my $params = shift;
    my $message = shift;
    my $request = Plack::Request->new({
        REQUEST_URI    => q{http://example.org/resource},
        REQUEST_METHOD => q{GET},
        QUERY_STRING   => build_content($params),
    });
    my $ctx = OAuth::Lite2::Server::Context->new({
        request      => $request,
        data_handler => $dh,
    });
    my $error_message; try {
        my $res = $action->handle_request($ctx);
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };

    like($error_message, qr/$message/);
}

# no username
&test_error({
    client_id     => q{foo},
    client_secret => q{bar},
    password      => q{pass_1},
}, q{invalid-request});

# no password
&test_error({
    client_id     => q{foo},
    client_secret => q{bar},
    username      => q{user_1},
}, q{invalid-request});

# invalid client_id
#&test_error({
#    client_id     => q{unknown},
#    client_secret => q{bar},
#    username      => q{user_1},
#    password      => q{pass_1},
#}, q{invalid-client-id});

# invalid username
&test_error({
    client_id     => q{foo},
    client_secret => q{bar},
    username      => q{unknown},
    password      => q{pass_1},
}, q{invalid-grant});

# invalid password
&test_error({
    client_id     => q{foo},
    client_secret => q{bar},
    username      => q{user_1},
    password      => q{unknown},
}, q{invalid-grant});

&test_success({
    client_id     => q{foo},
    client_secret => q{bar},
    username      => q{user_1},
    password      => q{pass_1},
}, {
    token         => q{access_token_0},
    expires_in    => q{3600},
    refresh_token => q{refresh_token_1},
});

