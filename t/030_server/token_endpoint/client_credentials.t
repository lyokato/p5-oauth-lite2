use strict;
use warnings;

use lib 't/lib';
use Test::More tests => 13;

use Plack::Request;
use Try::Tiny;
use TestDataHandler;
use OAuth::Lite2::Server::GrantHandler::ClientCredentials;
use OAuth::Lite2::Util qw(build_content);

TestDataHandler->clear;
TestDataHandler->add_client(id => q{foo}, secret => q{bar},  user_id => 1);
TestDataHandler->add_client(id => q{buz}, secret => q{hoge}, user_id => 0);

my $dh = TestDataHandler->new;
my $auth_info = $dh->create_or_update_auth_info(
    client_id => q{foo},
    user_id   => q{1},
    scope     => q{email},
);
my $auth_info2 = $dh->create_or_update_auth_info(
    client_id => q{buz},
    user_id   => q{0},
    scope     => q{email},
);

is($auth_info->refresh_token, "refresh_token_0");
is($auth_info2->refresh_token, "refresh_token_1");

my $action = OAuth::Lite2::Server::GrantHandler::ClientCredentials->new;

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

&test_success({
    client_id     => q{foo},
    client_secret => q{bar},
}, {
    token_type    => q{bearer},
    token         => q{access_token_0},
    expires_in    => q{3600},
    refresh_token => q{refresh_token_2},
});

# work as expected when user_id is 1
&test_success({
    client_id     => q{buz},
    client_secret => q{hoge},
}, {
    token_type    => q{bearer},
    token         => q{access_token_1},
    expires_in    => q{3600},
    refresh_token => q{refresh_token_3},
});

&test_error({
    client_id     => q{unknown},    
    client_secret => q{bar},
}, q/invalid_client/);

