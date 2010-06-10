use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 6;

use Plack::Request;
use Try::Tiny;
use TestDataHandler;
use OAuth::Lite2::Server::Context;
use OAuth::Lite2::Server::Action::Token::DeviceCode;
use OAuth::Lite2::Util qw(build_content);

TestDataHandler->clear;
TestDataHandler->add_client(id => q{foo}, secret => q{bar});
my $dh = TestDataHandler->new;

my $auth_info = $dh->create_or_update_auth_info(
    client_id => q{foo},
    user_id   => q{1},
    scope     => q{email},
);

is($auth_info->refresh_token, "refresh_token_0");

my $action = OAuth::Lite2::Server::Action::Token::DeviceCode->new;

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

    if(exists $expected->{code}) {
        like($res->{code}, $expected->{code});
    } else {
        ok(!$res->{code});
    }

    if(exists $expected->{user_code}) {
        like($res->{user_code}, $expected->{user_code});
    } else {
        ok(!$res->{user_code});
    }

    if(exists $expected->{expires_in}) {
        is($res->{expires_in}, $expected->{expires_in});
    } else {
        ok(!$res->{expires_in});
    }

    if(exists $expected->{verification_uri}) {
        is($res->{verification_uri}, $expected->{verification_uri});
    } else {
        ok(!$res->{verification_uri});
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
    scope => 'hoge',
}, q{'client_id' not found});

# TODO
# invalid client_id
#&test_error({
#    client_id => q{unknown},
#}, q{invalid_client});

# without secret type
&test_success({
    client_id     => q{foo},
}, {
    code             => qr{^ver_},
    user_code        => qr{^user_},
    verification_uri => q{http://example.org/verification},
    expires_in       => q{3600},
});

