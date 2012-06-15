use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 12;

use Plack::Request;
use Try::Tiny;
use TestDataHandler;
use OAuth::Lite2::Server::GrantHandler::AuthorizationCode;
use OAuth::Lite2::Util qw(build_content);

TestDataHandler->clear;
TestDataHandler->add_client(id => q{foo}, secret => q{secret_value});
my $dh = TestDataHandler->new;

my $auth_info = $dh->create_or_update_auth_info(
    client_id    => q{foo},
    user_id      => q{1},
    scope        => q{email},
    code         => q{code_bar},
    redirect_uri => q{http://example.org/callback},
);

is($auth_info->refresh_token, "refresh_token_0");

my $action = OAuth::Lite2::Server::GrantHandler::AuthorizationCode->new;

sub test_success {
    my $params = shift;
    my $expected = shift;
    my $request = Plack::Request->new({
        REQUEST_URI    => q{http://example.org/resource},
        REQUEST_METHOD => q{GET},
        QUERY_STRING   => build_content($params),
    });
    my $dh = TestDataHandler->new(request => $request);
    my $res; try {
        $res = $action->handle_request($dh);
    } catch {
        my $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };

    if(exists $expected->{token}) {
        is($res->{token_type}, $expected->{token_type});
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
    my $dh = TestDataHandler->new(request => $request);
    my $error_message; try {
        my $res = $action->handle_request($dh);
    } catch {
        $error_message = ($_->isa("OAuth::Lite2::Error"))
            ? $_->type : $_;
    };

    like($error_message, qr/$message/);
}

# no code
&test_error({
    client_id     => q{foo},
    redirect_uri  => q{http://example.org/callback},
    client_secret => q{secret_value},
}, q{invalid_request});

# no redirect_uri
&test_error({
    client_id     => q{foo},
    code          => q{bar},
    client_secret => q{secret_value},
}, q{invalid_request});

# invalid client_id
&test_error({
    client_id     => q{unknown},
    code          => q{code_bar},
    client_secret => q{secret_value},
    redirect_uri  => q{http://example.org/callback},
}, q{invalid_client});

# invalid code
&test_error({
    client_id     => q{foo},
    code          => q{code_invalid},
    client_secret => q{secret_value},
    redirect_uri  => q{http://example.org/callback},
}, q{invalid_grant});

# url mismatch
&test_error({
    client_id     => q{foo},
    code          => q{code_bar},
    client_secret => q{secret_value},
    redirect_uri  => q{http://example.org/unknown},
}, q{redirect_uri_mismatch});

# without secret type
&test_success({
    client_id     => q{foo},
    code          => q{code_bar},
    client_secret => q{secret_value},
    redirect_uri  => q{http://example.org/callback},
}, {
    token_type    => q{bearer},
    token         => q{access_token_0},
    expires_in    => q{3600},
    refresh_token => q{refresh_token_0},
});

