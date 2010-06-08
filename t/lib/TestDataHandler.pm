package TestDataHandler;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::DataHandler';

use String::Random;

use OAuth::Lite2::Error;
use OAuth::Lite2::Model::AuthInfo;
use OAuth::Lite2::Model::DeviceCode;
use OAuth::Lite2::Model::AccessToken;

my %ID_POD = (
    auth_info    => 0,
    access_token => 0,
    user         => 0,
);

sub gen_next_auth_info_id {
    my $class = shift;
    $ID_POD{auth_info}++;
}

sub gen_next_user_id {
    my $class = shift;
    $ID_POD{user}++;
}

sub gen_next_access_token_id {
    my $class = shift;
    $ID_POD{access_token}++;
}

sub add_client {
    my ($self, %args) = @_;
    $self->{clients}{ $args{id} } = {
        secret => $args{secret},
    };
}

sub add_user {
    my ($self, %args) = @_;
    $self->{users}{ $args{username} } = {
        password => $args{password},
    };
}

sub init {
    my $self = shift;
    $self->{auth_info}    = {};
    $self->{access_token} = {};
    $self->{clients}      = {};
    $self->{users}        = {};
    $self->{device_code}  = {};
}

sub get_user_id {
    my ($self, $username, $password) = @_;
    return unless ($username && exists $self->{users}{$username});
    return unless ($password && $self->{users}{$username}{password} eq $password);
    return $username;
}

# called in folling flows:
# - web_server
# - username
# - client_credentials
# - refresh
sub get_client_user_id {
    my ($self, $client_id, $client_secret) = @_;
    return unless ($client_id && exists $self->{clients}{$client_id});
    return unless ($client_secret && $self->{clients}{$client_id}{secret} eq $client_secret);
    return $self->{clients}{$client_id};
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

# called in following flows:
#   - device_token
sub get_auth_info_by_code {
    my ($self, $device_code) = @_;
    for my $id (keys %{ $self->{auth_info} }) {
        my $auth_info = $self->{auth_info}{$id};
        return $auth_info if ($auth_info->code && $auth_info->code eq $device_code);
    }
    return;
}

# called in following flows:
#   - device_code
sub create_or_update_device_code {
    my ($self, %params) = @_;

    my $client_id = $params{client_id};
    my $scope     = $params{scope} || 'all';

    my $random = String::Random->new;
    my $s = $random->randregex( sprintf '[a-zA-Z0-9]{%d}', 10 );

    my $usercode = q{user_} . $s;
    my $vercode = q{ver_} . $s;

    my $device_code = OAuth::Lite2::Model::DeviceCode->new({
        client_id        => $client_id,
        user_code        => $usercode,
        code             => $vercode,
        scope            => $scope,
        verification_url => q{http://example.org/verification},
        expires_in       => 3600,
    });
    $self->{device_code}{$usercode} = $device_code;
    return $device_code;
}

sub create_or_update_auth_info {
    my ($self, %params) = @_;

    my $client_id    = $params{client_id};
    my $user_id      = $params{user_id};
    my $scope        = $params{scope};
    my $code         = $params{code};
    my $redirect_url = $params{redirect_url};

    my $id = ref($self)->gen_next_auth_info_id();
    my $refresh_token = sprintf q{refresh_token_%d}, $id;

    my $auth_info = OAuth::Lite2::Model::AuthInfo->new({
        id            => $id,
        client_id     => $client_id,
        user_id       => $user_id,
        scope         => $scope,
        refresh_token => $refresh_token,
    });
    $auth_info->code($code) if $code;
    $auth_info->redirect_url($redirect_url) if $redirect_url;

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

