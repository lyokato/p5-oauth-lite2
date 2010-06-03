package TestDataHandler;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::DataHandler';

use OAuth::Lite2::Error;
use OAuth::Lite2::Model::AuthInfo;
use OAuth::Lite2::Model::AccessToken;

my %ID_POD = (
    auth_info    => 0,
    access_token => 0,
    client       => 0,
    user         => 0,
);

sub gen_next_auth_info_id {
    my $class = shift;
    $ID_POD{auth_info}++;
}

sub gen_next_client_id {
    my $class = shift;
    $ID_POD{client}++;
}

sub gen_next_user_id {
    my $class = shift;
    $ID_POD{user}++;
}

sub gen_next_access_token_id {
    my $class = shift;
    $ID_POD{access_token}++;
}

sub init {
    my $self = shift;
    $self->{auth_info}    = {};
    $self->{access_token} = {};
    $self->{clients}      = {};
    $self->{users}        = {};
}

# called in following flows:
#   - refresh
sub get_auth_info_by_refresh_token {
    my ($self, $refresh_token) = @_;

    for my $id (keys %{ $self->{auth_info} }) {
        my $auth_info = $self->{auth_info}{$id};
        return $auth_info if $auth_info->{refresh_token} eq $refresh_token;
    }
    return;
}

sub create_or_update_auth_info {
    my ($self, %params) = @_;

    my $client_id = $params{client_id};
    my $user_id   = $params{user_id};
    my $scope     = $params{scope};

    my $id = ref($self)->gen_next_auth_info_id();
    my $refresh_token = sprintf q{refresh_token_%d}, $id;

    my $auth_info = OAuth::Lite2::Model::AuthInfo->new({
        id            => $id,
        client_id     => $client_id,
        user_id       => $user_id,
        scope         => $scope,
        refresh_token => $refresh_token,
    });

    $self->{auth_info}{$id} = $auth_info;

    return $auth_info;
}

# called in following flows:
#   - refresh
sub create_or_update_access_token {
    my ($self, %params) = @_;

    my $auth_info = $params{auth_info};
    my $auth_id = $auth_info->id;

    my $id = ref($self)->gen_next_access_token_id();
    my $token = sprintf q{access_token_%d}, $id;

    my %attrs = (
        auth_id    => $auth_id,
        token      => $token,
        expires_in => 3600,
        created_on => time(),
    );

    my $secret_type = $params{secret_type};
    if ($secret_type) {
        # check if $secret_type is supported
        OAuth::Lite2::Error::UnsupportedSecretType->throw
            if ($secret_type ne 'hmac-sha256');
        $attrs{secret_type} = $secret_type;
    }
    $attrs{secret} = sprintf q{access_token_secret_%d}, $id if $secret_type;

    my $access_token = OAuth::Lite2::Model::AccessToken->new(\%attrs);
    $self->{access_token}{$auth_id} = $access_token;
    return $access_token;
}

1;

