use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 20;

use Plack::Request;
use Try::Tiny;
use TestDataHandler;
use OAuth::Lite2::Server::Context;
use OAuth::Lite2::Server::Action::Token::WebServer;
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

my $action = OAuth::Lite2::Server::Action::Token::WebServer->new;

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
            ? $_->message : $_;
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
            ? $_->message : $_;
    };

    like($error_message, qr/$message/);
}

# no client id
&test_error({
    code          => q{bar},
    redirect_uri  => q{http://example.org/callback},
    client_secret => q{secret_value},
}, q{'client_id' not found});

# no code
&test_error({
    client_id     => q{foo},
    redirect_uri  => q{http://example.org/callback},
    client_secret => q{secret_value},
}, q{'code' not found});

# no client secret
&test_error({
    client_id     => q{foo},
    code          => q{bar},
    redirect_uri  => q{http://example.org/callback},
}, q{'client_secret' not found});

# no redirect_uri
&test_error({
    client_id     => q{foo},
    code          => q{bar},
    client_secret => q{secret_value},
}, q{'redirect_uri' not found});

# invalid client_id
&test_error({
    client_id     => q{unknown},
    code          => q{code_bar},
    client_secret => q{secret_value},
    redirect_uri  => q{http://example.org/callback},
}, q{invalid_client});

# invalid client_secret
&test_error({
    client_id     => q{foo},
    code          => q{code_bar},
    client_secret => q{secret_unknown},
    redirect_uri  => q{http://example.org/callback},
}, q{invalid_client});

# invalid code
&test_error({
    client_id     => q{foo},
    code          => q{code_invalid},
    client_secret => q{secret_value},
    redirect_uri  => q{http://example.org/callback},
}, q{bad_verification_code});

# url mismatch
&test_error({
    client_id     => q{foo},
    code          => q{code_bar},
    client_secret => q{secret_value},
    redirect_uri  => q{http://example.org/unknown},
}, q{redirect_uri_mismatch});

# invalid secret type
&test_error({
    client_id     => q{foo},
    code          => q{code_bar},
    client_secret => q{secret_value},
    redirect_uri  => q{http://example.org/callback},
    secret_type   => q{hmac-sha1},
}, q{unsupported_secret_type});

# without secret type
&test_success({
    client_id     => q{foo},
    code          => q{code_bar},
    client_secret => q{secret_value},
    redirect_uri  => q{http://example.org/callback},
}, {
    token         => q{access_token_1},
    expires_in    => q{3600},
    refresh_token => q{refresh_token_0},
});

# secret type
&test_success({
    client_id     => q{foo},
    code          => q{code_bar},
    client_secret => q{secret_value},
    redirect_uri  => q{http://example.org/callback},
    secret_type   => q{hmac-sha256},
}, {
    token         => q{access_token_2},
    secret        => q{access_token_secret_2},
    secret_type   => q{hmac-sha256},
    expires_in    => q{3600},
    refresh_token => q{refresh_token_0},
});

